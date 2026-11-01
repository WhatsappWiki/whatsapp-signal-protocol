"""Generalized XVEdDSA / VEdDSA_25519_SHA512_Elligator2.

This is a Python port of curve25519-java's native VRF algorithm. Elligator
field arithmetic operates on public data; secret scalar multiplication uses
libsodium. This module does not load the upstream native implementation.
"""

import secrets
from hashlib import sha512
from hmac import compare_digest

from nacl import bindings as s
from nacl.exceptions import CryptoError

from signal_protocol.ecc import _public_edwards_multiply, montgomery_to_edwards
from signal_protocol.exceptions import InvalidKeyException, VrfSignatureVerificationFailedException

__all__ = ["P", "L", "B", "IDENTITY", "PROTOCOL", "sign", "verify"]

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
B = b"\x58" + b"\x66" * 31
IDENTITY = b"\x01" + bytes(31)
PROTOCOL = b"VEdDSA_25519_SHA512_Elligator2"


def _label(number):
    return bytes([3, len(PROTOCOL)]) + PROTOCOL + b"\x00\x01" + number


def _reduce(data):
    return s.crypto_core_ed25519_scalar_reduce(data)


def _hash_scalar(data):
    return _reduce(sha512(data).digest())


def _base(scalar):
    return IDENTITY if scalar == bytes(32) else s.crypto_scalarmult_ed25519_base_noclamp(scalar)


def _mul(scalar, point):
    return IDENTITY if scalar == bytes(32) else s.crypto_scalarmult_ed25519_noclamp(scalar, point)


def _cofactor(point):
    for _ in range(3):
        point = s.crypto_core_ed25519_add(point, point)
    return point


def _verify_multiply(scalar, point):
    if s.crypto_core_ed25519_is_valid_point(point):
        return _mul(scalar, point)
    return _public_edwards_multiply(scalar, point)


def _hash_to_point(data):
    digest = sha512(data).digest()
    r = int.from_bytes(digest[:32], "little") & (2**255 - 1)
    x = (-486662 * pow(1 + 2 * r * r, P - 2, P)) % P
    rhs = (x * x * x + 486662 * x * x + x) % P
    if pow(rhs, (P - 1) // 2, P) == P - 1:
        x = (-x - 486662) % P
    point = montgomery_to_edwards(x.to_bytes(32, "little"), digest[31])
    point = _cofactor(point)
    if point == IDENTITY:
        raise ValueError("Neutral VRF base point")
    return point


def _challenge(public, bv, kv, rv, r, message):
    label = _label(b"3")
    return _hash_scalar(B + label + r + label + public + bv + kv + rv + message)


def sign(private, message, *, random=None):
    if private is None or message is None:
        raise InvalidKeyException("Values must not be null")
    if len(message) > 1048576:
        raise ValueError("VRF message exceeds 1 MiB")
    try:
        random = secrets.token_bytes(32) if random is None else memoryview(random).tobytes()
    except (TypeError, ValueError) as exc:
        raise InvalidKeyException("VRF randomness must be a bytes-like buffer") from exc
    if len(random) != 32:
        raise ValueError("VRF randomness must be 32 bytes")
    scalar = _reduce(private.key + bytes(32))
    public = _base(scalar)
    # Keep the original scalar bytes in the nonce hash for sign-bit zero,
    # matching calculate_25519_keypair; the negative representation is reduced.
    k_bytes = private.key
    if public[31] & 128:
        scalar = s.crypto_core_ed25519_scalar_negate(scalar)
        k_bytes = scalar
    public = public[:31] + bytes([public[31] & 127])
    bv = _hash_to_point(B + _label(b"1") + public + message)
    kv = _mul(scalar, bv)
    label = _label(b"2")
    prefix = B + label + random
    prefix += bytes((-len(prefix)) % 128)
    prefix += k_bytes
    prefix += bytes((-len(prefix)) % 128)
    nonce = _hash_scalar(prefix + label + public + bv + kv + message)
    r, rv = _base(nonce), _mul(nonce, bv)
    h = _challenge(public, bv, kv, rv, r, message)
    proof = s.crypto_core_ed25519_scalar_add(nonce, s.crypto_core_ed25519_scalar_mul(h, scalar))
    return kv + h + proof


def verify(public, message, signature):
    if public is None or message is None or signature is None:
        raise InvalidKeyException("Values must not be null")
    try:
        if len(signature) != 96 or len(message) > 1048576:
            raise ValueError("Invalid VRF length")
        if int.from_bytes(public.key, "little") >= P:
            raise ValueError("Noncanonical Montgomery public key")
        key = montgomery_to_edwards(public.key)
        kv, h, proof = signature[:32], signature[32:64], signature[64:]
        if int.from_bytes(h, "little") >= L or int.from_bytes(proof, "little") >= L:
            raise ValueError("Noncanonical VRF scalar")
        if (int.from_bytes(kv, "little") & (2**255 - 1)) >= P:
            raise ValueError("Noncanonical VRF point")
        bv = _hash_to_point(B + _label(b"1") + key + message)
        r = s.crypto_core_ed25519_sub(_base(proof), _verify_multiply(h, key))
        rv = s.crypto_core_ed25519_sub(_mul(proof, bv), _verify_multiply(h, kv))
        if _cofactor(key) == IDENTITY or _cofactor(kv) == IDENTITY:
            raise ValueError("Neutral cofactored VRF point")
        if not compare_digest(h, _challenge(key, bv, kv, rv, r, message)):
            raise ValueError("Invalid VRF proof")
        return sha512(B + _label(b"4") + _cofactor(kv)).digest()[:32]
    except (ValueError, CryptoError) as exc:
        raise VrfSignatureVerificationFailedException(str(exc)) from exc
