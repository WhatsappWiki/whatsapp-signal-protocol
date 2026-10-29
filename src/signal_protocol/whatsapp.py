"""WhatsApp business padding and conditional identity-public-key validation.

These helpers do not alter the generic upstream Signal profile. Business
padding is separate from the AES-CBC PKCS7 padding applied by the cipher.
"""

import secrets
from typing import Callable, Optional

from .ecc import Curve, ECPublicKey, _public_edwards_multiply, montgomery_to_edwards
from .exceptions import InvalidKeyException, InvalidMessageException

_PRIME = 2**255 - 19
_NEUTRAL = b"\x01" + bytes(31)
_COFACTOR = (8).to_bytes(32, "little")


def _message_bytes(message: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("Message must be bytes-like")
    return bytes(message)


def pad_message(
    message: bytes,
    *,
    padding_length: Optional[int] = None,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> bytes:
    """Append n copies of n, where n is selected uniformly from 1 through 16.

    ``padding_length`` or ``randbelow`` can be supplied for reproducible protocol
    tests. The output format matches Q0E.A00; Python does not reproduce Java's
    global java.util.Random state or its pseudorandom byte sequence.
    """
    message = _message_bytes(message)
    count = randbelow(16) + 1 if padding_length is None else padding_length
    if type(count) is not int or not 1 <= count <= 16:
        raise ValueError("Business padding length must be between 1 and 16")
    return message + bytes([count]) * count


def unpad_message(message: bytes) -> bytes:
    """Remove the business padding using CYN.A02's last-byte rule.

    The Android receiver only requires 0 < last_byte < len(message). It does
    not require a count <= 16 or equal-valued preceding padding bytes. Preserve
    this acceptance policy rather than substituting a PKCS7 validator. Invalid
    padding raises InvalidMessageException in place of the Android helper's null
    result, allowing a caller to abort its plaintext callback transaction.
    """
    if message is None:
        raise InvalidMessageException("Empty business-padded message")
    message = _message_bytes(message)
    if not message:
        raise InvalidMessageException("Empty business-padded message")
    count = message[-1]
    if count == 0:
        raise InvalidMessageException("Invalid business padding")
    if count >= len(message):
        raise InvalidMessageException("Entire plaintext is business padding")
    return message[:-count]


def validate_public_key(public: ECPublicKey) -> None:
    """Apply WhatsApp's strict identity-public-key acceptance rule.

    The APK calls this check ``isTorsionFree``. Its Java provider actually checks
    membership in the main Montgomery curve and rejects points annihilated by
    the cofactor 8. It does not require prime-subgroup membership, so mixed-order
    points with a nonzero prime-order component remain accepted. All arithmetic
    here consumes public input only.
    """
    if not isinstance(public, ECPublicKey):
        raise TypeError("Public key must be an ECPublicKey")
    coordinate = int.from_bytes(public.key, "little")
    if coordinate >= _PRIME:
        raise InvalidKeyException("Public key scalar is out of range")
    rhs = (coordinate**3 + 486662 * coordinate**2 + coordinate) % _PRIME
    if pow(rhs, (_PRIME - 1) // 2, _PRIME) == _PRIME - 1:
        raise InvalidKeyException("Public key is not torsion-free")
    try:
        point = montgomery_to_edwards(public.key)
        if _public_edwards_multiply(_COFACTOR, point) == _NEUTRAL:
            raise InvalidKeyException("Public key is not torsion-free")
    except ValueError as exc:
        if isinstance(exc, InvalidKeyException):
            raise
        raise InvalidKeyException("Public key is not torsion-free") from exc


def decode_identity_key(serialized: bytes, *, strict: bool = True, offset: int = 0) -> ECPublicKey:
    """Decode type-05/raw32, conditionally applying strict identity validation.

    As in the existing Curve decoder and the APK, trailing bytes beyond the
    selected typed key are ignored. This routine returns an ECPublicKey; callers
    constructing an IdentityKey can wrap that result explicitly.
    """
    public = Curve.decode_point(serialized, offset)
    if strict:
        validate_public_key(public)
    return public
