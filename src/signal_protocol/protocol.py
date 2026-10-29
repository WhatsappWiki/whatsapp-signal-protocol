"""Versioned Signal message envelopes. Parsers retain original signed bytes."""

import hmac

from google.protobuf.message import DecodeError

from .ecc import Curve
from .exceptions import (
    InvalidKeyException,
    InvalidMessageException,
    InvalidVersionException,
    LegacyMessageException,
)
from .kdf import mac
from .keys import IdentityKey
from .profiles import UPSTREAM, ProtocolProfile
from .protobuf import WhisperTextProtocol_pb2 as pb
from .protobuf_codec import parse_java_protobuf, uint32


class CiphertextMessage:
    CURRENT_VERSION = 3
    WHISPER_TYPE = 2
    PREKEY_TYPE = 3
    SENDERKEY_TYPE = 4
    SENDERKEY_DISTRIBUTION_TYPE = 5
    ENCRYPTED_MESSAGE_OVERHEAD = 53

    def serialize(self):
        return self.serialized

    def get_type(self):
        return self.type


def _parse(serialized, proto, required, trailer=0, prekey=False, profile=UPSTREAM, group=False):
    profile = ProtocolProfile(profile)
    serialized = bytes(serialized)
    if len(serialized) < 1 + trailer:
        raise InvalidMessageException("Truncated message")
    version = serialized[0] >> 4
    if version < (2 if profile.whatsapp and not prekey and not group else 3):
        exc = InvalidMessageException if prekey else LegacyMessageException
        raise exc(f"Legacy version: {version}")
    if version > (4 if profile.whatsapp and not group else 3):
        exc = InvalidVersionException if prekey else InvalidMessageException
        raise exc(f"Unknown version: {version}")
    try:
        payload = serialized[1 : len(serialized) - trailer]
        # R3l's ByteString route uses CodedInputStream (10-byte varint cap),
        # while Signal/SenderKey byte[] routes use unbounded ArrayDecoders.
        message = parse_java_protobuf(proto, payload, route="coded" if prekey else "array")
    except DecodeError as exc:
        raise InvalidMessageException("Malformed protobuf") from exc
    if not all(message.HasField(key) for key in required):
        raise InvalidMessageException("Incomplete message")
    return version, message


class SignalMessage(CiphertextMessage):
    type = CiphertextMessage.WHISPER_TYPE

    def __init__(
        self,
        version,
        mac_key,
        sender_ratchet_key,
        counter,
        previous_counter,
        ciphertext,
        sender_identity_key,
        receiver_identity_key,
        *,
        profile=UPSTREAM,
    ):
        self.message_version = version
        self.sender_ratchet_key = sender_ratchet_key
        self.counter = uint32(counter)
        self.previous_counter = uint32(previous_counter)
        self.body = bytes(ciphertext)
        data = (
            bytes([(version << 4) | (version if ProtocolProfile(profile).whatsapp else 3)])
            + pb.SignalMessage(
                ratchetKey=sender_ratchet_key.serialize(),
                counter=self.counter,
                previousCounter=self.previous_counter,
                ciphertext=ciphertext,
            ).SerializeToString()
        )
        self.serialized = data + self._mac(
            sender_identity_key, receiver_identity_key, mac_key, data, version
        )

    @classmethod
    def from_bytes(cls, serialized, *, profile=UPSTREAM):
        version, p = _parse(
            serialized,
            pb.SignalMessage,
            ("ratchetKey", "counter", "ciphertext"),
            8,
            profile=profile,
        )
        obj = cls.__new__(cls)
        try:
            obj.sender_ratchet_key = Curve.decode_point(p.ratchetKey)
        except InvalidKeyException as exc:
            raise InvalidMessageException(str(exc)) from exc
        obj.message_version, obj.counter = version, p.counter
        obj.previous_counter, obj.body = p.previousCounter, p.ciphertext
        obj.serialized = bytes(serialized)
        return obj

    @staticmethod
    def _mac(sender, receiver, key, data, version=3):
        identities = sender.serialize() + receiver.serialize() if version >= 3 else b""
        return mac(key, identities + data)[:8]

    def verify_mac(self, sender, receiver, key):
        expected = self._mac(sender, receiver, key, self.serialized[:-8], self.message_version)
        if not hmac.compare_digest(expected, self.serialized[-8:]):
            raise InvalidMessageException("Bad MAC")

    @staticmethod
    def is_legacy(message, *, profile=UPSTREAM):
        supported = (2, 3, 4) if ProtocolProfile(profile).whatsapp else (3,)
        return message is not None and len(message) >= 1 and message[0] >> 4 not in supported


class PreKeySignalMessage(CiphertextMessage):
    type = CiphertextMessage.PREKEY_TYPE

    def __init__(
        self,
        version,
        registration_id,
        pre_key_id,
        signed_pre_key_id,
        base_key,
        identity_key,
        message,
        *,
        kyber_pre_key_id=None,
        kyber_ciphertext=None,
        profile=UPSTREAM,
    ):
        self.message_version, self.registration_id = version, uint32(registration_id)
        self.pre_key_id = uint32(pre_key_id) if pre_key_id is not None else None
        self.signed_pre_key_id = uint32(signed_pre_key_id)
        self.base_key, self.identity_key, self.message = base_key, identity_key, message
        if (kyber_pre_key_id is None) != (kyber_ciphertext is None):
            raise InvalidMessageException("Incomplete KEM prekey pair")
        self.kyber_pre_key_id = uint32(kyber_pre_key_id) if kyber_pre_key_id is not None else None
        self.kyber_ciphertext = kyber_ciphertext
        p = pb.PreKeySignalMessage(
            registrationId=self.registration_id,
            signedPreKeyId=self.signed_pre_key_id,
            baseKey=base_key.serialize(),
            identityKey=identity_key.serialize(),
            message=message.serialize(),
        )
        if pre_key_id is not None:
            p.preKeyId = self.pre_key_id
        if kyber_pre_key_id is not None:
            p.kyberPreKeyId = self.kyber_pre_key_id
            p.kyberCiphertext = kyber_ciphertext
        self.serialized = (
            bytes([(version << 4) | (version if ProtocolProfile(profile).whatsapp else 3)])
            + p.SerializeToString()
        )

    @classmethod
    def from_bytes(cls, serialized, *, profile=UPSTREAM):
        version, p = _parse(
            serialized,
            pb.PreKeySignalMessage,
            ("signedPreKeyId", "baseKey", "identityKey", "message"),
            prekey=True,
            profile=profile,
        )
        obj = cls.__new__(cls)
        try:
            obj.base_key = Curve.decode_point(p.baseKey)
            obj.identity_key = IdentityKey.from_bytes(p.identityKey)
            obj.message = SignalMessage.from_bytes(p.message, profile=profile)
        except (InvalidKeyException, LegacyMessageException) as exc:
            raise InvalidMessageException(str(exc)) from exc
        obj.message_version, obj.registration_id = version, p.registrationId
        obj.pre_key_id = p.preKeyId if p.HasField("preKeyId") else None
        obj.signed_pre_key_id = p.signedPreKeyId
        if ProtocolProfile(profile).whatsapp and p.HasField("kyberPreKeyId") != p.HasField(
            "kyberCiphertext"
        ):
            raise InvalidMessageException("Incomplete KEM prekey pair")
        obj.kyber_pre_key_id = (
            p.kyberPreKeyId
            if ProtocolProfile(profile).whatsapp and p.HasField("kyberPreKeyId")
            else None
        )
        obj.kyber_ciphertext = (
            p.kyberCiphertext
            if ProtocolProfile(profile).whatsapp and p.HasField("kyberCiphertext")
            else None
        )
        obj.serialized = bytes(serialized)
        return obj


class SenderKeyDistributionMessage(CiphertextMessage):
    type = CiphertextMessage.SENDERKEY_DISTRIBUTION_TYPE

    def __init__(self, id, iteration, chain_key, signature_key):
        self.id, self.iteration = uint32(id), uint32(iteration)
        self.chain_key, self.signature_key = bytes(chain_key), signature_key
        self.serialized = (
            b"\x33"
            + pb.SenderKeyDistributionMessage(
                id=self.id,
                iteration=self.iteration,
                chainKey=chain_key,
                signingKey=signature_key.serialize(),
            ).SerializeToString()
        )

    @classmethod
    def from_bytes(cls, serialized, *, profile=UPSTREAM):
        _, p = _parse(
            serialized,
            pb.SenderKeyDistributionMessage,
            ("id", "iteration", "chainKey", "signingKey"),
            profile=profile,
            group=True,
        )
        obj = cls.__new__(cls)
        try:
            obj.signature_key = Curve.decode_point(p.signingKey)
        except InvalidKeyException as exc:
            raise InvalidMessageException(str(exc)) from exc
        obj.id, obj.iteration, obj.chain_key = p.id, p.iteration, p.chainKey
        obj.serialized = bytes(serialized)
        return obj


class SenderKeyMessage(CiphertextMessage):
    type = CiphertextMessage.SENDERKEY_TYPE

    def __init__(self, key_id, iteration, ciphertext, signature_key):
        self.key_id, self.iteration, self.ciphertext = (
            uint32(key_id),
            uint32(iteration),
            bytes(ciphertext),
        )
        self.message_version = 3
        data = (
            b"\x33"
            + pb.SenderKeyMessage(
                id=self.key_id, iteration=self.iteration, ciphertext=ciphertext
            ).SerializeToString()
        )
        self.serialized = data + Curve.calculate_signature(signature_key, data)

    @classmethod
    def from_bytes(cls, serialized, *, profile=UPSTREAM):
        version, p = _parse(
            serialized,
            pb.SenderKeyMessage,
            ("id", "iteration", "ciphertext"),
            64,
            profile=profile,
            group=True,
        )
        obj = cls.__new__(cls)
        obj.key_id, obj.iteration, obj.ciphertext = p.id, p.iteration, p.ciphertext
        obj.message_version, obj.serialized = version, bytes(serialized)
        return obj

    def verify_signature(self, key):
        try:
            if not Curve.verify_signature(key, self.serialized[:-64], self.serialized[-64:]):
                raise InvalidMessageException("Invalid signature")
        except InvalidKeyException as exc:
            raise InvalidMessageException(str(exc)) from exc
