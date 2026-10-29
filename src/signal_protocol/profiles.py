"""Explicit protocol policies; storage records never silently select a policy."""

from enum import Enum


class ProtocolProfile(Enum):
    UPSTREAM = "upstream"
    WHATSAPP = "whatsapp"

    @property
    def whatsapp(self):
        return self is ProtocolProfile.WHATSAPP


UPSTREAM = ProtocolProfile.UPSTREAM
WHATSAPP = ProtocolProfile.WHATSAPP
