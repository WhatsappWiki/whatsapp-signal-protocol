"""Structural storage interfaces; no concrete persistence implementation required."""

from typing import List, Optional, Protocol

from signal_protocol.address import Direction, SignalProtocolAddress
from signal_protocol.keys import (
    IdentityKey,
    IdentityKeyPair,
    KyberPreKeyRecord,
    PreKeyRecord,
    SignedPreKeyRecord,
)
from signal_protocol.sender_keys import SenderKeyName, SenderKeyRecord
from signal_protocol.state import SessionRecord

__all__ = [
    "IdentityKeyStore",
    "PreKeyStore",
    "SignedPreKeyStore",
    "KyberPreKeyStore",
    "SessionStore",
    "SignalProtocolStore",
    "SenderKeyStore",
]


class IdentityKeyStore(Protocol):
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

    def get_identity_key_pair(self) -> IdentityKeyPair: ...
    def get_local_registration_id(self) -> int: ...
    def save_identity(self, address: SignalProtocolAddress, identity: IdentityKey) -> bool: ...
    def is_trusted_identity(
        self, address: SignalProtocolAddress, identity: IdentityKey, direction: Direction
    ) -> bool: ...
    def get_identity(self, address: SignalProtocolAddress) -> Optional[IdentityKey]: ...


class PreKeyStore(Protocol):
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

    def load_pre_key(self, id: int) -> PreKeyRecord: ...
    def store_pre_key(self, id: int, record: PreKeyRecord) -> None: ...
    def contains_pre_key(self, id: int) -> bool: ...
    def remove_pre_key(self, id: int) -> None: ...


class SignedPreKeyStore(Protocol):
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

    def load_signed_pre_key(self, id: int) -> SignedPreKeyRecord: ...
    def load_signed_pre_keys(self) -> List[SignedPreKeyRecord]: ...
    def store_signed_pre_key(self, id: int, record: SignedPreKeyRecord) -> None: ...
    def contains_signed_pre_key(self, id: int) -> bool: ...
    def remove_signed_pre_key(self, id: int) -> None: ...


class KyberPreKeyStore(Protocol):
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

    def load_kyber_pre_key(self, id: int) -> KyberPreKeyRecord: ...
    def store_kyber_pre_key(self, id: int, record: KyberPreKeyRecord) -> None: ...
    def contains_kyber_pre_key(self, id: int) -> bool: ...
    def mark_kyber_pre_key_used(self, id: int) -> None: ...


class SessionStore(Protocol):
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

    def load_session(self, address: SignalProtocolAddress) -> SessionRecord: ...
    def store_session(self, address: SignalProtocolAddress, record: SessionRecord) -> None: ...
    def contains_session(self, address: SignalProtocolAddress) -> bool: ...
    def delete_session(self, address: SignalProtocolAddress) -> None: ...
    def delete_all_sessions(self, name: str) -> None: ...
    def get_sub_device_sessions(self, name: str) -> List[int]: ...


class SignalProtocolStore(IdentityKeyStore, PreKeyStore, SignedPreKeyStore, SessionStore, Protocol):
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

    pass


class SenderKeyStore(Protocol):
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.groups"

    def load_sender_key(self, name: SenderKeyName) -> SenderKeyRecord: ...
    def store_sender_key(self, name: SenderKeyName, record: SenderKeyRecord) -> None: ...
