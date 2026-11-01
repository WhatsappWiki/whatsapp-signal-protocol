"""Identity keys and local key-record serialization."""

import secrets
import time
from dataclasses import dataclass

from signal_protocol.ecc import Curve, ECKeyPair, ECPrivateKey, ECPublicKey
from signal_protocol.profiles import UPSTREAM, ProtocolProfile
from signal_protocol.protobuf import LocalStorageProtocol_pb2 as storage
from signal_protocol.protobuf_codec import parse_java_protobuf

__all__ = [
    "IdentityKey",
    "IdentityKeyPair",
    "PreKeyRecord",
    "SignedPreKeyRecord",
    "PreKeyBundle",
    "KyberPreKeyRecord",
    "KeyHelper",
]


def _decode_record(proto, serialized, profile):
    ProtocolProfile(profile)
    return parse_java_protobuf(proto, serialized)


@dataclass(frozen=True)
class IdentityKey:
    public_key: ECPublicKey

    def serialize(self):
        return self.public_key.serialize()

    @classmethod
    def from_bytes(cls, serialized, offset=0, *, strict=False):
        if strict:
            from signal_protocol.whatsapp import decode_identity_key

            return cls(decode_identity_key(serialized, offset=offset, strict=True))
        return cls(Curve.decode_point(serialized, offset))

    def fingerprint(self):
        return "".join(f"(byte)0x{byte:02x}, " for byte in self.serialize())


@dataclass(frozen=True)
class IdentityKeyPair:
    public_key: IdentityKey
    private_key: ECPrivateKey

    def serialize(self):
        return storage.IdentityKeyPairStructure(
            publicKey=self.public_key.serialize(), privateKey=self.private_key.serialize()
        ).SerializeToString()

    @classmethod
    def from_bytes(cls, serialized, *, profile=UPSTREAM):
        p = _decode_record(storage.IdentityKeyPairStructure, serialized, profile)
        return cls(IdentityKey.from_bytes(p.publicKey), ECPrivateKey(p.privateKey))


class PreKeyRecord:
    def __init__(self, id, key_pair):
        self.structure = storage.PreKeyRecordStructure(
            id=id & 0xFFFFFFFF,
            publicKey=key_pair.public_key.serialize(),
            privateKey=key_pair.private_key.serialize(),
        )

    @property
    def id(self):
        return self.structure.id

    @property
    def key_pair(self):
        return ECKeyPair(
            Curve.decode_point(self.structure.publicKey), ECPrivateKey(self.structure.privateKey)
        )

    def serialize(self):
        return self.structure.SerializeToString()

    @classmethod
    def from_bytes(cls, serialized, *, profile=UPSTREAM):
        obj = cls.__new__(cls)
        obj.structure = _decode_record(storage.PreKeyRecordStructure, serialized, profile)
        return obj


class SignedPreKeyRecord:
    def __init__(self, id, timestamp, key_pair, signature):
        self.structure = storage.SignedPreKeyRecordStructure(
            id=id & 0xFFFFFFFF,
            timestamp=timestamp & 0xFFFFFFFFFFFFFFFF,
            publicKey=key_pair.public_key.serialize(),
            privateKey=key_pair.private_key.serialize(),
            signature=signature,
        )

    @property
    def id(self):
        return self.structure.id

    @property
    def timestamp(self):
        return self.structure.timestamp

    @property
    def key_pair(self):
        return ECKeyPair(
            Curve.decode_point(self.structure.publicKey), ECPrivateKey(self.structure.privateKey)
        )

    @property
    def signature(self):
        return self.structure.signature

    def serialize(self):
        return self.structure.SerializeToString()

    @classmethod
    def from_bytes(cls, serialized, *, profile=UPSTREAM):
        obj = cls.__new__(cls)
        obj.structure = _decode_record(storage.SignedPreKeyRecordStructure, serialized, profile)
        return obj


@dataclass(frozen=True)
class PreKeyBundle:
    registration_id: int
    device_id: int
    pre_key_id: int
    pre_key: ECPublicKey
    signed_pre_key_id: int
    signed_pre_key: ECPublicKey
    signed_pre_key_signature: bytes
    identity_key: IdentityKey
    kyber_pre_key_id: int = None
    kyber_pre_key: object = None
    kyber_pre_key_signature: bytes = None


class KyberPreKeyRecord:
    """Signed KEM record; last-resort status is store metadata, not protobuf."""

    def __init__(self, id, timestamp, key_pair, signature, *, last_resort=False):
        self.structure = storage.SignedPreKeyRecordStructure(
            id=id & 0xFFFFFFFF,
            timestamp=timestamp & 0xFFFFFFFFFFFFFFFF,
            publicKey=key_pair.public_key.serialize(),
            privateKey=key_pair.secret_key.serialize(),
            signature=signature,
        )
        self.last_resort = bool(last_resort)

    @property
    def id(self):
        return self.structure.id

    @property
    def timestamp(self):
        return self.structure.timestamp

    @property
    def key_pair(self):
        from signal_protocol.kem import KemKeyPair, KemPublicKey, KemSecretKey

        return KemKeyPair(
            KemPublicKey.from_bytes(self.structure.publicKey),
            KemSecretKey.from_bytes(self.structure.privateKey),
        )

    @property
    def signature(self):
        return self.structure.signature

    def serialize(self):
        return self.structure.SerializeToString()

    @classmethod
    def from_bytes(cls, serialized, *, last_resort=False, profile=UPSTREAM):
        obj = cls.__new__(cls)
        obj.structure = _decode_record(storage.SignedPreKeyRecordStructure, serialized, profile)
        obj.last_resort = bool(last_resort)
        return obj


class KeyHelper:
    @staticmethod
    def get_random_sequence(max):
        return secrets.randbelow(max)

    @staticmethod
    def generate_identity_key_pair():
        pair = Curve.generate_key_pair()
        return IdentityKeyPair(IdentityKey(pair.public_key), pair.private_key)

    @staticmethod
    def generate_registration_id(extended_range=False):
        return secrets.randbelow(2147483646 if extended_range else 16380) + 1

    @staticmethod
    def generate_pre_keys(start, count):
        # Java's remainder keeps the dividend's sign (not Python's modulo).
        # In particular start=0 produces prekey 0, then 1, 2, ... upstream.
        def remainder(value):
            return value % 0xFFFFFE if value >= 0 else -((-value) % 0xFFFFFE)

        return [
            PreKeyRecord(remainder(start - 1 + i) + 1, Curve.generate_key_pair())
            for i in range(count)
        ]

    @staticmethod
    def generate_signed_pre_key(identity, id):
        pair = Curve.generate_key_pair()
        signature = Curve.calculate_signature(identity.private_key, pair.public_key.serialize())
        return SignedPreKeyRecord(id, int(time.time() * 1000), pair, signature)

    @staticmethod
    def generate_kyber_pre_key(identity, id, *, last_resort=False, seed=None, key_type=None):
        from signal_protocol.kem import KemKeyPair, KemKeyType

        pair = KemKeyPair.generate(
            key_type=KemKeyType.ML_KEM_1024 if key_type is None else key_type, seed=seed
        )
        signature = Curve.calculate_signature(identity.private_key, pair.public_key.serialize())
        return KyberPreKeyRecord(
            id, int(time.time() * 1000), pair, signature, last_resort=last_resort
        )

    @staticmethod
    def generate_sender_signing_key():
        return Curve.generate_key_pair()

    @staticmethod
    def generate_sender_key():
        return secrets.token_bytes(32)

    @staticmethod
    def generate_sender_key_id():
        return secrets.randbelow(2147483647)
