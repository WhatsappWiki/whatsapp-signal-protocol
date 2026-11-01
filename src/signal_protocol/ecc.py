"""Curve25519 keys and Signal's randomized Curve25519 signature scheme.

The protocol is Python. Generated/clamped keys use libsodium through PyNaCl.
The upstream raw-scalar compatibility path uses a Python Montgomery ladder;
that fallback is not constant-time and is intended for legacy imported keys.
"""

import secrets
from dataclasses import dataclass
from hashlib import sha512
from hmac import compare_digest

from nacl import bindings as sodium
from nacl.exceptions import CryptoError

from signal_protocol.exceptions import InvalidKeyException
from signal_protocol.profiles import UPSTREAM, ProtocolProfile

__all__ = ["ECPublicKey", "ECPrivateKey", "ECKeyPair", "clamp", "montgomery_to_edwards", "Curve"]


@dataclass(frozen=True)
class ECPublicKey:
    key: bytes

    def __post_init__(self):
        try:
            object.__setattr__(self, "key", memoryview(self.key).tobytes())
        except (TypeError, ValueError) as exc:
            raise InvalidKeyException("Public key must be a bytes-like buffer") from exc
        if len(self.key) != 32:
            raise InvalidKeyException("Public key must be 32 bytes")

    def serialize(self) -> bytes:
        return b"\x05" + self.key

    def __lt__(self, other):
        # Java's BigInteger(byte[]) is signed and big-endian, even though
        # Curve25519 encodes the coordinate in little-endian order.
        return int.from_bytes(self.key, "big", signed=True) < int.from_bytes(
            other.key, "big", signed=True
        )


@dataclass(frozen=True)
class ECPrivateKey:
    key: bytes

    def __post_init__(self):
        try:
            object.__setattr__(self, "key", memoryview(self.key).tobytes())
        except (TypeError, ValueError) as exc:
            raise InvalidKeyException("Private key must be a bytes-like buffer") from exc
        if len(self.key) != 32:
            raise InvalidKeyException("Private key must be 32 bytes")

    def serialize(self) -> bytes:
        return self.key


@dataclass(frozen=True)
class ECKeyPair:
    public_key: ECPublicKey
    private_key: ECPrivateKey


def clamp(raw: bytes) -> bytes:
    if len(raw) != 32:
        raise InvalidKeyException("Private key must be 32 bytes")
    value = bytearray(raw)
    value[0] &= 248
    value[31] = (value[31] & 127) | 64
    return bytes(value)


def montgomery_to_edwards(public: bytes, sign: int = 0) -> bytes:
    prime = 2**255 - 19
    u = int.from_bytes(public, "little") & (2**255 - 1)
    y = ((u - 1) * pow(u + 1, prime - 2, prime)) % prime
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= sign & 128
    return bytes(encoded)


def _raw_agreement(public: bytes, private: bytes) -> bytes:
    """Match upstream scalarmult, which deliberately does NOT clamp decoded keys.

    The loop ignores bit 255 exactly like the Java implementation. Python big
    integers are not constant-time. Normally generated keys bypass this path.
    """
    prime = 2**255 - 19
    x1 = (int.from_bytes(public, "little") & (2**255 - 1)) % prime
    scalar = int.from_bytes(private, "little")
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for bit in range(254, -1, -1):
        k = (scalar >> bit) & 1
        swap ^= k
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = k
        a, b = (x2 + z2) % prime, (x2 - z2) % prime
        aa, bb = a * a % prime, b * b % prime
        e = (aa - bb) % prime
        da, cb = (x3 - z3) * a % prime, (x3 + z3) * b % prime
        x3 = (da + cb) ** 2 % prime
        z3 = x1 * (da - cb) ** 2 % prime
        x2, z2 = aa * bb % prime, e * (aa + 121665 * e) % prime
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, prime - 2, prime) % prime).to_bytes(32, "little")


def _public_edwards_multiply(scalar: bytes, encoded: bytes) -> bytes:
    """Public-data verification fallback for mixed/small-order Edwards points.

    libsodium's multiplication API intentionally rejects these points. The
    upstream verifier uses the full curve group; no secret may enter this helper.
    """
    p = 2**255 - 19
    d = -121665 * pow(121666, p - 2, p) % p
    value = int.from_bytes(encoded, "little")
    y = (value & (2**255 - 1)) % p
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p) % p
    x = pow(x2, (p + 3) // 8, p)
    if x * x % p != x2:
        x = x * pow(2, (p - 1) // 4, p) % p
    if x * x % p != x2:
        raise ValueError("Invalid Edwards point")
    if (x & 1) != (value >> 255):
        x = -x % p

    def add(a, b):
        x1, y1, z1, t1 = a
        x2, y2, z2, t2 = b
        aa, bb = (y1 - x1) * (y2 - x2) % p, (y1 + x1) * (y2 + x2) % p
        cc, dd = 2 * d * t1 * t2 % p, 2 * z1 * z2 % p
        e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
        return e * f % p, g * h % p, f * g % p, e * h % p

    result, point = (0, 1, 1, 0), (x, y, 1, x * y % p)
    n = int.from_bytes(scalar, "little")
    while n:
        if n & 1:
            result = add(result, point)
        point = add(point, point)
        n >>= 1
    x, y, z, _ = result
    inverse = pow(z, p - 2, p)
    return (y * inverse % p | ((x * inverse % p & 1) << 255)).to_bytes(32, "little")


class Curve:
    DJB_TYPE = 5

    @staticmethod
    def generate_key_pair() -> ECKeyPair:
        private = clamp(secrets.token_bytes(32))
        return ECKeyPair(ECPublicKey(sodium.crypto_scalarmult_base(private)), ECPrivateKey(private))

    @staticmethod
    def decode_point(serialized: bytes, offset: int = 0) -> ECPublicKey:
        if serialized is None or offset < 0 or len(serialized) - offset < 1:
            raise InvalidKeyException("No key type identifier")
        if serialized[offset] != 5 or len(serialized) - offset < 33:
            raise InvalidKeyException("Bad key type or length")
        return ECPublicKey(serialized[offset + 1 : offset + 33])

    @staticmethod
    def decode_private_point(serialized: bytes) -> ECPrivateKey:
        return ECPrivateKey(serialized)

    @staticmethod
    def calculate_agreement(
        public: ECPublicKey, private: ECPrivateKey, *, profile=UPSTREAM
    ) -> bytes:
        if public is None or private is None:
            raise InvalidKeyException("Keys must not be null")
        if ProtocolProfile(profile).whatsapp:
            try:
                shared = sodium.crypto_scalarmult(clamp(private.key), public.key)
            except CryptoError as exc:
                raise InvalidKeyException("Invalid public key: small-subgroup element") from exc
            if shared == bytes(32):
                raise InvalidKeyException("Invalid public key: small-subgroup element")
            return shared
        if private.key != clamp(private.key):
            return _raw_agreement(public.key, private.key)
        try:
            return sodium.crypto_scalarmult(private.key, public.key)
        except CryptoError:
            # libsodium rejects low-order inputs; upstream returns the all-zero
            # result. Preserve that API behavior (not a recommendation to use it).
            return _raw_agreement(public.key, private.key)

    @staticmethod
    def calculate_signature(
        private: ECPrivateKey, message: bytes, *, random: bytes = None
    ) -> bytes:
        if private is None or message is None:
            raise InvalidKeyException("Values must not be null")
        try:
            random = secrets.token_bytes(64) if random is None else memoryview(random).tobytes()
        except (TypeError, ValueError) as exc:
            raise InvalidKeyException("Signature randomness must be a bytes-like buffer") from exc
        if len(random) != 64:
            raise InvalidKeyException("Signature randomness must be 64 bytes")
        scalar = sodium.crypto_core_ed25519_scalar_reduce(private.key + bytes(32))
        # libsodium rejects identity-point products; the original signer
        # supports them for raw imported scalars and a zero reduced nonce.
        neutral = b"\x01" + bytes(31)
        public = (
            neutral
            if scalar == bytes(32)
            else sodium.crypto_scalarmult_ed25519_base_noclamp(scalar)
        )
        nonce = sodium.crypto_core_ed25519_scalar_reduce(
            sha512(b"\xfe" + b"\xff" * 31 + private.key + message + random).digest()
        )
        r_point = (
            neutral if nonce == bytes(32) else sodium.crypto_scalarmult_ed25519_base_noclamp(nonce)
        )
        challenge = sodium.crypto_core_ed25519_scalar_reduce(
            sha512(r_point + public + message).digest()
        )
        s = bytearray(
            sodium.crypto_core_ed25519_scalar_add(
                sodium.crypto_core_ed25519_scalar_mul(challenge, scalar), nonce
            )
        )
        s[31] |= public[31] & 128
        return r_point + bytes(s)

    @staticmethod
    def verify_signature(public: ECPublicKey, message: bytes, signature: bytes) -> bool:
        if public is None or message is None or signature is None:
            raise InvalidKeyException("Values must not be null")
        if len(signature) != 64:
            return False
        ed_public = montgomery_to_edwards(public.key, signature[63])
        unsigned = signature[:63] + bytes([signature[63] & 127])
        # The original ref10 verifier checks the top three S bits, not S < L.
        # Reducing S preserves its acceptance of equivalent S + L signatures.
        if unsigned[63] & 224:
            return False
        try:
            scalar = sodium.crypto_core_ed25519_scalar_reduce(unsigned[32:] + bytes(32))
            challenge = sodium.crypto_core_ed25519_scalar_reduce(
                sha512(unsigned[:32] + ed_public + message).digest()
            )
            neutral = b"\x01" + bytes(31)
            sb = (
                neutral
                if scalar == bytes(32)
                else sodium.crypto_scalarmult_ed25519_base_noclamp(scalar)
            )
            if sodium.crypto_core_ed25519_is_valid_point(ed_public):
                ha = (
                    neutral
                    if challenge == bytes(32)
                    else sodium.crypto_scalarmult_ed25519_noclamp(challenge, ed_public)
                )
            else:
                ha = _public_edwards_multiply(challenge, ed_public)
            return compare_digest(sodium.crypto_core_ed25519_sub(sb, ha), unsigned[:32])
        except (CryptoError, ValueError):
            return False

    @staticmethod
    def calculate_vrf_signature(private, message, *, random=None):
        from signal_protocol.vrf import sign

        return sign(private, message, random=random)

    @staticmethod
    def verify_vrf_signature(public, message, signature):
        from signal_protocol.vrf import verify

        return verify(public, message, signature)
