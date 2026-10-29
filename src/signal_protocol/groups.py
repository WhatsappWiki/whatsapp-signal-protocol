"""Sender Key group sessions, persisted in the upstream protobuf format."""

from dataclasses import dataclass
from threading import RLock
from typing import Protocol

from .ecc import Curve, ECKeyPair, ECPrivateKey
from .exceptions import (
    DuplicateMessageException,
    InvalidKeyException,
    InvalidKeyIdException,
    InvalidMessageException,
    NoSessionException,
)
from .integers import int32, uint32
from .kdf import HKDF, decrypt_cbc, encrypt_cbc, mac
from .keys import KeyHelper
from .profiles import UPSTREAM, ProtocolProfile
from .protobuf import LocalStorageProtocol_pb2 as pb
from .protobuf_codec import parse_java_protobuf
from .protocol import SenderKeyDistributionMessage, SenderKeyMessage
from .store import SignalProtocolAddress

GROUP_LOCK = RLock()


@dataclass(frozen=True)
class SenderKeyName:
    group_id: str
    sender: SignalProtocolAddress

    def serialize(self):
        return f"{self.group_id}::{self.sender.name}::{self.sender.device_id}"


@dataclass(frozen=True)
class SenderChainKey:
    iteration: int
    seed: bytes

    def __post_init__(self):
        object.__setattr__(self, "iteration", uint32(self.iteration))

    def next(self):
        return SenderChainKey(uint32(self.iteration + 1), mac(self.seed, b"\x02"))

    def sender_message_key(self):
        return SenderMessageKey(self.iteration, mac(self.seed, b"\x01"))


class SenderMessageKey:
    def __init__(self, iteration, seed):
        self.iteration, self.seed = uint32(iteration), seed
        data = HKDF(3).derive_secrets(seed, b"WhisperGroup", 48)
        self.iv, self.cipher_key = data[:16], data[16:]


class SenderKeyState:
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
        return any(k.iteration == iteration for k in self.structure.senderMessageKeys)

    def add_sender_message_key(self, key):
        self.structure.senderMessageKeys.add(iteration=uint32(key.iteration), seed=key.seed)
        if len(self.structure.senderMessageKeys) > 2000:
            del self.structure.senderMessageKeys[0]

    def remove_sender_message_key(self, iteration):
        for i, key in enumerate(self.structure.senderMessageKeys):
            if key.iteration == iteration:
                result = SenderMessageKey(key.iteration, key.seed)
                del self.structure.senderMessageKeys[i]
                return result
        return None


class SenderKeyRecord:
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


class SenderKeyStore(Protocol):
    def load_sender_key(self, name: SenderKeyName) -> SenderKeyRecord: ...
    def store_sender_key(self, name: SenderKeyName, record: SenderKeyRecord) -> None: ...


class InMemorySenderKeyStore:
    def __init__(self):
        self.keys = {}

    def load_sender_key(self, name):
        return SenderKeyRecord(self.keys.get(name))

    def store_sender_key(self, name, record):
        self.keys[name] = record.serialize()


class GroupSessionBuilder:
    def __init__(self, store, *, profile=UPSTREAM):
        self.store = store
        self.profile = ProtocolProfile(profile)

    def process(self, name, message):
        with GROUP_LOCK:
            record = self.store.load_sender_key(name)
            record.profile = self.profile
            record.add_sender_key_state(
                message.id, message.iteration, message.chain_key, message.signature_key
            )
            self.store.store_sender_key(name, record)

    def create(self, name):
        with GROUP_LOCK:
            record = self.store.load_sender_key(name)
            record.profile = self.profile
            if record.is_empty():
                record.set_sender_key_state(
                    KeyHelper.generate_sender_key_id(),
                    0,
                    KeyHelper.generate_sender_key(),
                    KeyHelper.generate_sender_signing_key(),
                )
                self.store.store_sender_key(name, record)
            state = record.get_sender_key_state()
            return SenderKeyDistributionMessage(
                state.key_id,
                state.sender_chain_key.iteration,
                state.sender_chain_key.seed,
                state.signing_key_public,
            )


class GroupCipher:
    def __init__(self, store, name, *, profile=UPSTREAM):
        self.store, self.name = store, name
        self.profile = ProtocolProfile(profile)

    def encrypt(self, plaintext):
        with GROUP_LOCK:
            record = self.store.load_sender_key(self.name)
            record.profile = self.profile
            try:
                state = record.get_sender_key_state()
            except InvalidKeyIdException as exc:
                raise NoSessionException(str(exc)) from exc
            key = state.sender_chain_key.sender_message_key()
            ciphertext = encrypt_cbc(key.cipher_key, key.iv, plaintext)
            message = SenderKeyMessage(
                state.key_id, key.iteration, ciphertext, state.signing_key_private
            )
            state.sender_chain_key = state.sender_chain_key.next()
            self.store.store_sender_key(self.name, record)
            return message.serialize()

    def decrypt(self, serialized, callback=None):
        with GROUP_LOCK:
            record = self.store.load_sender_key(self.name)
            record.profile = self.profile
            if record.is_empty():
                raise NoSessionException(str(self.name))
            message = SenderKeyMessage.from_bytes(serialized, profile=self.profile)
            try:
                state = record.get_sender_key_state(message.key_id)
                message.verify_signature(state.signing_key_public)
            except (InvalidKeyIdException, InvalidKeyException) as exc:
                raise InvalidMessageException(str(exc)) from exc
            key = self._get_sender_key(state, message.iteration)
            plaintext = decrypt_cbc(key.cipher_key, key.iv, message.ciphertext)
            if callback is not None:
                callback(plaintext)
            self.store.store_sender_key(self.name, record)
            return plaintext

    @staticmethod
    def _get_sender_key(state, iteration):
        chain = state.sender_chain_key
        iteration = uint32(iteration)
        current_index, message_index = int32(chain.iteration), int32(iteration)
        if current_index > message_index:
            key = state.remove_sender_message_key(iteration)
            if key is None:
                raise DuplicateMessageException(f"Old counter: {chain.iteration}, {iteration}")
            return key
        difference = message_index - current_index
        if int32(difference) > 2000 or difference > 2000:
            raise InvalidMessageException("Over 2000 messages into the future")
        while int32(chain.iteration) < message_index:
            state.add_sender_message_key(chain.sender_message_key())
            chain = chain.next()
        state.sender_chain_key = chain.next()
        return chain.sender_message_key()
