"""Immutable peer addresses and identity trust directions."""

from dataclasses import dataclass
from enum import Enum

__all__ = ["SignalProtocolAddress", "Direction"]


@dataclass(frozen=True)
class SignalProtocolAddress:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

    name: str
    device_id: int

    def __str__(self):
        return f"{self.name}:{self.device_id}"


class Direction(Enum):
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.store"

    SENDING = "sending"
    RECEIVING = "receiving"
