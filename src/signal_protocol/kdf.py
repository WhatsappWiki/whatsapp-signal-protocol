"""Signal HKDF v2/v3 and symmetric encryption primitives."""

import hashlib
import hmac

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from signal_protocol.exceptions import InvalidMessageException

__all__ = ["mac", "HKDF", "crypt_ctr", "HKDFv2", "HKDFv3", "encrypt_cbc", "decrypt_cbc"]


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


class HKDF:
    def __init__(self, version: int = 3):
        if version not in (2, 3, 4):
            raise ValueError(f"Unknown HKDF version: {version}")
        self.version = version

    def derive_secrets(self, ikm: bytes, info: bytes, length: int, salt: bytes = bytes(32)):
        if not 0 <= length <= 255 * 32:
            raise ValueError("Invalid HKDF output length")
        prk = mac(salt, ikm)
        result = previous = b""
        start = 0 if self.version == 2 else 1
        for i in range(start, start + (length + 31) // 32):
            previous = mac(prk, previous + (info or b"") + bytes([i]))
            result += previous
        return result[:length]


def crypt_ctr(key: bytes, counter: int, message: bytes) -> bytes:
    """Legacy WhatsApp v2 AES-CTR: counter BE32 followed by twelve zero bytes."""
    iv = (counter & 0xFFFFFFFF).to_bytes(4, "big") + bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return cipher.update(message) + cipher.finalize()


class HKDFv2(HKDF):
    def __init__(self):
        super().__init__(2)


class HKDFv3(HKDF):
    def __init__(self):
        super().__init__(3)


def encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return cipher.update(padded) + cipher.finalize()


def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = cipher.update(ciphertext) + cipher.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise InvalidMessageException("Invalid CBC ciphertext/padding") from exc
