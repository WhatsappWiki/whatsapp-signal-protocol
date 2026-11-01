"""Sender Key derivation and protobuf state, independent of storage and ciphers."""

from dataclasses import dataclass

from signal_protocol.address import SignalProtocolAddress
from signal_protocol.ecc import Curve, ECKeyPair, ECPrivateKey
from signal_protocol.exceptions import InvalidKeyIdException
from signal_protocol.integers import uint32
from signal_protocol.kdf import HKDF, mac
from signal_protocol.profiles import UPSTREAM, ProtocolProfile
from signal_protocol.protobuf import LocalStorageProtocol_pb2 as pb
from signal_protocol.protobuf_codec import parse_java_protobuf

__all__ = [
    "SenderKeyName",
    "SenderChainKey",
    "SenderMessageKey",
    "SenderKeyState",
    "SenderKeyRecord",
]


@dataclass(frozen=True)
class SenderKeyName:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.groups"

    group_id: str
    sender: SignalProtocolAddress

    def serialize(self):
        return f"{self.group_id}::{self.sender.name}::{self.sender.device_id}"


@dataclass(frozen=True)
class SenderChainKey:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.groups"

    iteration: int
    seed: bytes

    def __post_init__(self):
        object.__setattr__(self, "iteration", uint32(self.iteration))

    def next(self):
        return SenderChainKey(uint32(self.iteration + 1), mac(self.seed, b"\x02"))

    def sender_message_key(self):
        return SenderMessageKey(self.iteration, mac(self.seed, b"\x01"))


class SenderMessageKey:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.groups"

    def __init__(self, iteration, seed):
        self.iteration, self.seed = uint32(iteration), seed
        data = HKDF(3).derive_secrets(seed, b"WhisperGroup", 48)
        self.iv, self.cipher_key = data[:16], data[16:]


class SenderKeyState:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.groups"

    def __init__(
        self, id=None, iteration=None, chain_key=None, signature_key=None, *, structure=None
    ):
        self.structure = pb.SenderKeyStateStructure()
        if structure is not None:
            self.structure.CopyFrom(structure)
            return
        self.structure.senderKeyId = uint32(id)
        self.sender_chain_key = SenderChainKey(iteration, chain_key)
        public = signature_key.public_key if isinstance(signature_key, ECKeyPair) else signature_key
        setattr(self.structure.senderSigningKey, "public", public.serialize())
        if isinstance(signature_key, ECKeyPair):
            setattr(
                self.structure.senderSigningKey, "private", signature_key.private_key.serialize()
            )

    @property
    def key_id(self):
        return self.structure.senderKeyId

    @property
    def sender_chain_key(self):
        p = self.structure.senderChainKey
        return SenderChainKey(p.iteration, p.seed)

    @sender_chain_key.setter
    def sender_chain_key(self, key):
        self.structure.senderChainKey.CopyFrom(
            pb.SenderKeyStateStructure.SenderChainKey(
                iteration=uint32(key.iteration), seed=key.seed
            )
        )

    @property
    def signing_key_public(self):
        return Curve.decode_point(getattr(self.structure.senderSigningKey, "public"))

    @property
    def signing_key_private(self):
        return ECPrivateKey(getattr(self.structure.senderSigningKey, "private"))

    def has_sender_message_key(self, iteration):
        iteration = uint32(iteration)
        return any(k.iteration == iteration for k in self.structure.senderMessageKeys)

    def add_sender_message_key(self, key):
        self.structure.senderMessageKeys.add(iteration=uint32(key.iteration), seed=key.seed)
        if len(self.structure.senderMessageKeys) > 2000:
            del self.structure.senderMessageKeys[0]

    def remove_sender_message_key(self, iteration):
        iteration = uint32(iteration)
        for i, key in enumerate(self.structure.senderMessageKeys):
            if key.iteration == iteration:
                result = SenderMessageKey(key.iteration, key.seed)
                del self.structure.senderMessageKeys[i]
                return result
        return None


class SenderKeyRecord:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.groups"

    def __init__(self, serialized=None, *, profile=UPSTREAM):
        self.profile = ProtocolProfile(profile)
        self.states = []
        self._record = pb.SenderKeyRecordStructure()
        if serialized is not None:
            self._record.CopyFrom(parse_java_protobuf(pb.SenderKeyRecordStructure, serialized))
            self.states = [SenderKeyState(structure=p) for p in self._record.senderKeyStates]

    def is_empty(self):
        return not self.states

    def get_sender_key_state(self, key_id=None):
        key_id = uint32(key_id) if key_id is not None else None
        for state in self.states:
            if key_id is None or state.key_id == key_id:
                return state
        raise InvalidKeyIdException(f"No sender key state: {key_id}")

    def add_sender_key_state(self, id, iteration, chain_key, signature_key):
        self.states.insert(0, SenderKeyState(id, iteration, chain_key, signature_key))
        if len(self.states) > 5:
            self.states.pop()

    def set_sender_key_state(self, id, iteration, chain_key, signature_key):
        self.states = [SenderKeyState(id, iteration, chain_key, signature_key)]

    def serialize(self):
        p = pb.SenderKeyRecordStructure()
        del p.senderKeyStates[:]
        p.senderKeyStates.extend(s.structure for s in self.states)
        return p.SerializeToString()
