"""Store contracts and serialization-isolated in-memory implementations."""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Protocol

from .exceptions import InvalidKeyIdException
from .integers import uint32
from .keys import (
    IdentityKey,
    IdentityKeyPair,
    KeyHelper,
    KyberPreKeyRecord,
    PreKeyRecord,
    SignedPreKeyRecord,
)
from .state import SessionRecord


@dataclass(frozen=True)
class SignalProtocolAddress:
    name: str
    device_id: int

    def __str__(self):
        return f"{self.name}:{self.device_id}"


class Direction(Enum):
    SENDING = "sending"
    RECEIVING = "receiving"


class IdentityKeyStore(Protocol):
    def get_identity_key_pair(self) -> IdentityKeyPair: ...
    def get_local_registration_id(self) -> int: ...
    def save_identity(self, address: SignalProtocolAddress, identity: IdentityKey) -> bool: ...
    def is_trusted_identity(
        self, address: SignalProtocolAddress, identity: IdentityKey, direction: Direction
    ) -> bool: ...
    def get_identity(self, address: SignalProtocolAddress) -> Optional[IdentityKey]: ...


class PreKeyStore(Protocol):
    def load_pre_key(self, id: int) -> PreKeyRecord: ...
    def store_pre_key(self, id: int, record: PreKeyRecord) -> None: ...
    def contains_pre_key(self, id: int) -> bool: ...
    def remove_pre_key(self, id: int) -> None: ...


class SignedPreKeyStore(Protocol):
    def load_signed_pre_key(self, id: int) -> SignedPreKeyRecord: ...
    def load_signed_pre_keys(self) -> List[SignedPreKeyRecord]: ...
    def store_signed_pre_key(self, id: int, record: SignedPreKeyRecord) -> None: ...
    def contains_signed_pre_key(self, id: int) -> bool: ...
    def remove_signed_pre_key(self, id: int) -> None: ...


class KyberPreKeyStore(Protocol):
    def load_kyber_pre_key(self, id: int) -> KyberPreKeyRecord: ...
    def store_kyber_pre_key(self, id: int, record: KyberPreKeyRecord) -> None: ...
    def contains_kyber_pre_key(self, id: int) -> bool: ...
    def mark_kyber_pre_key_used(self, id: int) -> None: ...


class SessionStore(Protocol):
    def load_session(self, address: SignalProtocolAddress) -> SessionRecord: ...
    def store_session(self, address: SignalProtocolAddress, record: SessionRecord) -> None: ...
    def contains_session(self, address: SignalProtocolAddress) -> bool: ...
    def delete_session(self, address: SignalProtocolAddress) -> None: ...
    def delete_all_sessions(self, name: str) -> None: ...
    def get_sub_device_sessions(self, name: str) -> List[int]: ...


class SignalProtocolStore(IdentityKeyStore, PreKeyStore, SignedPreKeyStore, SessionStore, Protocol):
    pass


class InMemoryIdentityKeyStore:
    def __init__(self, identity_key_pair=None, registration_id=None):
        self.identity_key_pair = identity_key_pair or KeyHelper.generate_identity_key_pair()
        self.registration_id = (
            KeyHelper.generate_registration_id() if registration_id is None else registration_id
        )
        self.trusted_keys = {}

    def get_identity_key_pair(self):
        return self.identity_key_pair

    def get_local_registration_id(self):
        return self.registration_id

    def save_identity(self, address, identity):
        old = self.trusted_keys.get(address)
        self.trusted_keys[address] = identity
        return old != identity

    def is_trusted_identity(self, address, identity, direction):
        return address not in self.trusted_keys or self.trusted_keys[address] == identity

    def get_identity(self, address):
        return self.trusted_keys.get(address)


class InMemoryPreKeyStore:
    def __init__(self):
        self.pre_keys = {}

    def load_pre_key(self, id):
        id = uint32(id)
        if id not in self.pre_keys:
            raise InvalidKeyIdException(f"No such prekey: {id}")
        return PreKeyRecord.from_bytes(self.pre_keys[id])

    def store_pre_key(self, id, record):
        id = uint32(id)
        self.pre_keys[id] = record.serialize()

    def contains_pre_key(self, id):
        id = uint32(id)
        return id in self.pre_keys

    def remove_pre_key(self, id):
        id = uint32(id)
        self.pre_keys.pop(id, None)


class InMemorySignedPreKeyStore:
    def __init__(self):
        self.signed_pre_keys = {}

    def load_signed_pre_key(self, id):
        id = uint32(id)
        if id not in self.signed_pre_keys:
            raise InvalidKeyIdException(f"No such signed prekey: {id}")
        return SignedPreKeyRecord.from_bytes(self.signed_pre_keys[id])

    def load_signed_pre_keys(self):
        return [SignedPreKeyRecord.from_bytes(s) for s in self.signed_pre_keys.values()]

    def store_signed_pre_key(self, id, record):
        id = uint32(id)
        self.signed_pre_keys[id] = record.serialize()

    def contains_signed_pre_key(self, id):
        id = uint32(id)
        return id in self.signed_pre_keys

    def remove_signed_pre_key(self, id):
        id = uint32(id)
        self.signed_pre_keys.pop(id, None)


class InMemorySessionStore:
    def __init__(self):
        self.sessions = {}

    def load_session(self, address):
        return (
            SessionRecord(self.sessions[address]) if address in self.sessions else SessionRecord()
        )

    def store_session(self, address, record):
        self.sessions[address] = record.serialize()

    def contains_session(self, address):
        return address in self.sessions

    def delete_session(self, address):
        self.sessions.pop(address, None)

    def delete_all_sessions(self, name):
        for address in list(self.sessions):
            if address.name == name:
                del self.sessions[address]

    def get_sub_device_sessions(self, name):
        return [a.device_id for a in self.sessions if a.name == name and a.device_id != 1]


class InMemoryKyberPreKeyStore:
    def __init__(self):
        self.kyber_pre_keys = {}

    def load_kyber_pre_key(self, id):
        id = uint32(id)
        if id not in self.kyber_pre_keys:
            raise InvalidKeyIdException(f"No such KEM prekey: {id}")
        value, last_resort = self.kyber_pre_keys[id]
        return KyberPreKeyRecord.from_bytes(value, last_resort=last_resort)

    def store_kyber_pre_key(self, id, record):
        id = uint32(id)
        self.kyber_pre_keys[id] = (record.serialize(), record.last_resort)

    def contains_kyber_pre_key(self, id):
        id = uint32(id)
        return id in self.kyber_pre_keys

    def mark_kyber_pre_key_used(self, id):
        id = uint32(id)
        if id in self.kyber_pre_keys and not self.kyber_pre_keys[id][1]:
            del self.kyber_pre_keys[id]

    def remove_kyber_pre_key(self, id):
        id = uint32(id)
        self.kyber_pre_keys.pop(id, None)


class InMemorySignalProtocolStore(
    InMemoryIdentityKeyStore,
    InMemoryPreKeyStore,
    InMemorySignedPreKeyStore,
    InMemorySessionStore,
    InMemoryKyberPreKeyStore,
):
    def __init__(self, identity_key_pair=None, registration_id=None):
        InMemoryIdentityKeyStore.__init__(self, identity_key_pair, registration_id)
        InMemoryPreKeyStore.__init__(self)
        InMemorySignedPreKeyStore.__init__(self)
        InMemorySessionStore.__init__(self)
        InMemoryKyberPreKeyStore.__init__(self)
