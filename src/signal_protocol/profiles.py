"""Explicit protocol policies; storage records never silently select a policy."""

from enum import Enum

__all__ = ["ProtocolProfile", "UPSTREAM", "WHATSAPP"]


class ProtocolProfile(Enum):
    UPSTREAM = "upstream"
    WHATSAPP = "whatsapp"

    @property
    def whatsapp(self):
        return self is ProtocolProfile.WHATSAPP


UPSTREAM = ProtocolProfile.UPSTREAM
WHATSAPP = ProtocolProfile.WHATSAPP
