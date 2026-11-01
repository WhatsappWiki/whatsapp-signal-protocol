"""Serialization-isolated memory stores for tests and local protocol sessions."""

from signal_protocol.exceptions import InvalidKeyIdException
from signal_protocol.integers import uint32
from signal_protocol.keys import KeyHelper, KyberPreKeyRecord, PreKeyRecord, SignedPreKeyRecord
from signal_protocol.sender_keys import SenderKeyRecord
from signal_protocol.state import SessionRecord

__all__ = [
    "InMemoryIdentityKeyStore",
    "InMemoryPreKeyStore",
    "InMemorySignedPreKeyStore",
    "InMemorySessionStore",
    "InMemoryKyberPreKeyStore",
    "InMemorySignalProtocolStore",
    "InMemorySenderKeyStore",
]


class InMemoryIdentityKeyStore:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

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
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

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
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

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
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

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
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

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
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

    def __init__(self, identity_key_pair=None, registration_id=None):
        InMemoryIdentityKeyStore.__init__(self, identity_key_pair, registration_id)
        InMemoryPreKeyStore.__init__(self)
        InMemorySignedPreKeyStore.__init__(self)
        InMemorySessionStore.__init__(self)
        InMemoryKyberPreKeyStore.__init__(self)


class InMemorySenderKeyStore:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.groups"

    def __init__(self):
        self.keys = {}

    def load_sender_key(self, name):
        return SenderKeyRecord(self.keys.get(name))

    def store_sender_key(self, name, record):
        self.keys[name] = record.serialize()
