"""Signal v3 session initialization and double-ratchet key derivation."""

from dataclasses import dataclass
from typing import Optional

from signal_protocol.ecc import Curve, ECKeyPair, ECPublicKey
from signal_protocol.integers import uint32
from signal_protocol.kdf import HKDF, mac
from signal_protocol.keys import IdentityKey, IdentityKeyPair
from signal_protocol.profiles import UPSTREAM, ProtocolProfile

__all__ = [
    "MessageKeys",
    "ChainKey",
    "RootKey",
    "AliceSignalProtocolParameters",
    "BobSignalProtocolParameters",
    "SymmetricSignalProtocolParameters",
    "RatchetingSession",
]


@dataclass(frozen=True)
class MessageKeys:
    cipher_key: bytes
    mac_key: bytes
    iv: bytes
    counter: int

    def __post_init__(self):
        object.__setattr__(self, "counter", uint32(self.counter))


@dataclass(frozen=True)
class ChainKey:
    kdf: HKDF
    key: bytes
    index: int

    def __post_init__(self):
        object.__setattr__(self, "index", uint32(self.index))

    def next_chain_key(self):
        return ChainKey(self.kdf, mac(self.key, b"\x02"), uint32(self.index + 1))

    def message_keys(self):
        data = self.kdf.derive_secrets(mac(self.key, b"\x01"), b"WhisperMessageKeys", 80)
        return MessageKeys(data[:32], data[32:64], data[64:], self.index)


@dataclass(frozen=True)
class RootKey:
    kdf: HKDF
    key: bytes

    def create_chain(self, their_ratchet_key, our_ratchet_key, *, profile=UPSTREAM):
        secret = Curve.calculate_agreement(
            their_ratchet_key, our_ratchet_key.private_key, profile=profile
        )
        data = self.kdf.derive_secrets(secret, b"WhisperRatchet", 64, self.key)
        return RootKey(self.kdf, data[:32]), ChainKey(self.kdf, data[32:], 0)


@dataclass(frozen=True)
class AliceSignalProtocolParameters:
    our_identity_key: IdentityKeyPair
    our_base_key: ECKeyPair
    their_identity_key: IdentityKey
    their_signed_pre_key: ECPublicKey
    their_ratchet_key: ECPublicKey
    their_one_time_pre_key: Optional[ECPublicKey] = None
    kem_shared_secret: Optional[bytes] = None


@dataclass(frozen=True)
class BobSignalProtocolParameters:
    our_identity_key: IdentityKeyPair
    our_signed_pre_key: ECKeyPair
    our_ratchet_key: ECKeyPair
    their_identity_key: IdentityKey
    their_base_key: ECPublicKey
    our_one_time_pre_key: Optional[ECKeyPair] = None
    kem_shared_secret: Optional[bytes] = None


@dataclass(frozen=True)
class SymmetricSignalProtocolParameters:
    our_identity_key: IdentityKeyPair
    our_base_key: ECKeyPair
    our_ratchet_key: ECKeyPair
    their_identity_key: IdentityKey
    their_base_key: ECPublicKey
    their_ratchet_key: ECPublicKey


class RatchetingSession:
    @staticmethod
    def initialize_session(state, parameters, *, profile=UPSTREAM):
        profile = ProtocolProfile(profile)
        p = parameters
        if isinstance(p, SymmetricSignalProtocolParameters):
            if p.our_base_key.public_key < p.their_base_key:
                p = AliceSignalProtocolParameters(
                    p.our_identity_key,
                    p.our_base_key,
                    p.their_identity_key,
                    p.their_base_key,
                    p.their_ratchet_key,
                )
            else:
                p = BobSignalProtocolParameters(
                    p.our_identity_key,
                    p.our_base_key,
                    p.our_ratchet_key,
                    p.their_identity_key,
                    p.their_base_key,
                )
        kem_secret = p.kem_shared_secret
        if kem_secret is not None and len(kem_secret) != 32:
            raise ValueError("KEM shared secret must be 32 bytes")
        state.session_version = 4 if kem_secret is not None else 3
        state.remote_identity_key = p.their_identity_key
        state.local_identity_key = p.our_identity_key.public_key

        def dh(public, private):
            return Curve.calculate_agreement(public, private, profile=profile)

        if isinstance(p, AliceSignalProtocolParameters):
            sending_ratchet = Curve.generate_key_pair()
            secret = b"\xff" * 32 + dh(p.their_signed_pre_key, p.our_identity_key.private_key)
            secret += dh(p.their_identity_key.public_key, p.our_base_key.private_key)
            secret += dh(p.their_signed_pre_key, p.our_base_key.private_key)
            if p.their_one_time_pre_key is not None:
                secret += dh(p.their_one_time_pre_key, p.our_base_key.private_key)
        elif isinstance(p, BobSignalProtocolParameters):
            secret = b"\xff" * 32 + dh(
                p.their_identity_key.public_key, p.our_signed_pre_key.private_key
            )
            secret += dh(p.their_base_key, p.our_identity_key.private_key)
            secret += dh(p.their_base_key, p.our_signed_pre_key.private_key)
            if p.our_one_time_pre_key is not None:
                secret += dh(p.their_base_key, p.our_one_time_pre_key.private_key)
        else:
            raise TypeError("Unknown session parameters")
        kdf = HKDF(3)
        info = b"WhisperText"
        if kem_secret is not None:
            secret += kem_secret
            info = b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"
        derived = kdf.derive_secrets(secret, info, 64)
        root, chain = RootKey(kdf, derived[:32]), ChainKey(kdf, derived[32:], 0)
        if isinstance(p, AliceSignalProtocolParameters):
            sending_root, sending_chain = root.create_chain(
                p.their_ratchet_key, sending_ratchet, profile=profile
            )
            state.add_receiver_chain(p.their_ratchet_key, chain)
            state.set_sender_chain(sending_ratchet, sending_chain)
            state.root_key = sending_root
        else:
            state.set_sender_chain(p.our_ratchet_key, chain)
            state.root_key = root
