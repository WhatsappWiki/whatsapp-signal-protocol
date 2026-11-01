"""WhatsApp content-padding adapters over the explicitly selected Signal profile."""

from signal_protocol.group_session import GroupCipher
from signal_protocol.profiles import WHATSAPP
from signal_protocol.protocol import PreKeySignalMessage, SignalMessage
from signal_protocol.session_builder import SessionBuilder
from signal_protocol.session_cipher import SessionCipher
from signal_protocol.whatsapp import pad_message, unpad_message

__all__ = ["WhatsAppSessionBuilder", "WhatsAppSessionCipher", "WhatsAppGroupCipher"]


def _decrypt_content(decrypt, message, callback):
    """Unpad and deliver content inside the underlying cipher's commit boundary."""
    result = []

    def receive(padded):
        content = unpad_message(padded)
        if callback is not None:
            callback(content)
        result.append(content)

    decrypt(message, receive)
    return result[0]


class WhatsAppSessionBuilder(SessionBuilder):
    def __init__(self, store, remote_address, **kwargs):
        super().__init__(store, remote_address, profile=WHATSAPP, **kwargs)


class WhatsAppSessionCipher(SessionCipher):
    """Encrypt/decrypt business payload bytes, including business padding.

    Plaintext callbacks receive unpadded content before the session is saved or
    prekeys are consumed. Raw Signal users can use SessionCipher(profile=WHATSAPP).
    """

    def __init__(self, store, remote_address, **kwargs):
        super().__init__(store, remote_address, profile=WHATSAPP, **kwargs)

    def encrypt(self, message, *, padding_length=None):
        return super().encrypt(pad_message(message, padding_length=padding_length))

    def decrypt(self, message, callback=None, *, message_type=None):
        if isinstance(message, (bytes, bytearray, memoryview)):
            if message_type not in (2, 3):
                raise ValueError("Serialized messages require explicit message_type 2 or 3")
            cls = PreKeySignalMessage if message_type == 3 else SignalMessage
            message = cls.from_bytes(message, profile=WHATSAPP)
        return _decrypt_content(super().decrypt, message, callback)


class WhatsAppGroupCipher(GroupCipher):
    def __init__(self, store, name):
        super().__init__(store, name, profile=WHATSAPP)

    def encrypt(self, message, *, padding_length=None):
        return super().encrypt(pad_message(message, padding_length=padding_length))

    def decrypt(self, serialized, callback=None):
        return _decrypt_content(super().decrypt, serialized, callback)
