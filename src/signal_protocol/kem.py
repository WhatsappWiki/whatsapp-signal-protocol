"""Raw ML-KEM keys for the observed WhatsApp v4 handshake.

The APK exposes FIPS 203 ML-KEM-512/768/1024 (type metadata 6/7/10),
although its handshake KDF retains a historical CRYSTALS-KYBER label.
Its JNI public key, expanded private key and ciphertext encodings are raw,
without the type-byte prefixes used by other libsignal implementations.
Legacy round-3 Kyber is deliberately not accepted as the same algorithm.

Normal operations use pqcrypto's matching native PQClean ML-KEM primitive.
Explicit deterministic seeds or ``backend="reference"`` select kyber-py's
Python reference implementation, which is not constant-time. Backend failures
never trigger a fallback. Reference operations use a fresh instance and private
entropy source, so test seeds cannot alter a shared RNG or singleton backend.
"""

import secrets
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional

from signal_protocol.exceptions import InvalidKeyException

__all__ = [
    "PUBLIC_KEY_LENGTH",
    "SECRET_KEY_LENGTH",
    "CIPHERTEXT_LENGTH",
    "SHARED_SECRET_LENGTH",
    "KemKeyType",
    "KemEncapsulated",
    "KemPublicKey",
    "KemSecretKey",
    "KemKeyPair",
]

# Unqualified lengths retain the original default-1024 API. Other parameter
# sets expose their lengths on KemKeyType, and raw imports infer the set.
PUBLIC_KEY_LENGTH = 1568
SECRET_KEY_LENGTH = 3168
CIPHERTEXT_LENGTH = 1568
SHARED_SECRET_LENGTH = 32


class KemKeyType(IntEnum):
    ML_KEM_512 = 0x06
    ML_KEM_768 = 0x07
    ML_KEM_1024 = 0x0A

    @property
    def public_key_length(self):
        return _PARAMETERS[self][0]

    @property
    def secret_key_length(self):
        return _PARAMETERS[self][1]

    @property
    def ciphertext_length(self):
        return _PARAMETERS[self][2]


_PARAMETERS = {
    KemKeyType.ML_KEM_512: (800, 1632, 768, "ML512"),
    KemKeyType.ML_KEM_768: (1184, 2400, 1088, "ML768"),
    KemKeyType.ML_KEM_1024: (1568, 3168, 1568, "ML1024"),
}


def _type(value):
    try:
        return KemKeyType(value)
    except (TypeError, ValueError) as exc:
        raise InvalidKeyException(f"Unsupported KEM key type: {value!r}") from exc


def _sized(value, length, label):
    try:
        value = memoryview(value).tobytes()
    except (TypeError, ValueError) as exc:
        raise InvalidKeyException(f"{label} must be bytes") from exc
    if len(value) != length:
        raise InvalidKeyException(f"{label} must be {length} bytes, received {len(value)}")
    return value


def _infer_type(serialized, key_type, length_index, label):
    if key_type is not None:
        return _type(key_type)
    try:
        length = memoryview(serialized).nbytes
    except (TypeError, ValueError) as exc:
        raise InvalidKeyException(f"{label} must be bytes") from exc
    for candidate, values in _PARAMETERS.items():
        if length == values[length_index]:
            return candidate
    raise InvalidKeyException(f"Unsupported raw {label} length: {length}")


def _reference_backend(key_type, random_bytes=None, seed=None, seed_length=None):
    """Instantiate explicitly selected algorithms; never downgrade on failure."""
    if seed is not None and random_bytes is not None:
        raise ValueError("Supply a deterministic seed or an entropy callable, not both")
    key_type = _type(key_type)
    from kyber_py.ml_kem.default_parameters import DEFAULT_PARAMETERS
    from kyber_py.ml_kem.ml_kem import ML_KEM

    backend = ML_KEM(dict(DEFAULT_PARAMETERS[_PARAMETERS[key_type][3]]))
    if seed is not None:
        seed = _sized(seed, seed_length, "KEM deterministic seed")
        offset = 0

        def entropy(length):
            nonlocal offset
            if offset + length > len(seed):
                raise ValueError("Deterministic entropy exhausted")
            result = seed[offset : offset + length]
            offset += length
            return result

    else:
        source = secrets.token_bytes if random_bytes is None else random_bytes

        def entropy(length):
            return _sized(source(length), length, "Entropy source result")

    backend.random_bytes = entropy
    return backend


def _native_backend(key_type=KemKeyType.ML_KEM_1024):
    from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024

    return {
        KemKeyType.ML_KEM_512: ml_kem_512,
        KemKeyType.ML_KEM_768: ml_kem_768,
        KemKeyType.ML_KEM_1024: ml_kem_1024,
    }[_type(key_type)]


def _select_backend(backend, seed=None, random_bytes=None):
    if backend is None:
        return "reference" if seed is not None or random_bytes is not None else "native"
    if backend not in ("native", "reference"):
        raise ValueError("KEM backend must be 'native' or 'reference'")
    if backend == "native" and (seed is not None or random_bytes is not None):
        raise ValueError(
            "Native KEM uses its own entropy; use the reference backend for test seeds"
        )
    return backend


@dataclass(frozen=True)
class KemEncapsulated:
    ciphertext: bytes
    shared_secret: bytes


@dataclass(frozen=True)
class KemPublicKey:
    key: bytes
    key_type: KemKeyType = KemKeyType.ML_KEM_1024

    def __post_init__(self):
        key_type = _type(self.key_type)
        object.__setattr__(
            self, "key", _sized(self.key, key_type.public_key_length, "KEM public key")
        )
        object.__setattr__(self, "key_type", key_type)

    def serialize(self):
        return self.key

    @classmethod
    def from_bytes(cls, serialized, *, key_type=None):
        return cls(serialized, _infer_type(serialized, key_type, 0, "KEM public key"))

    def encapsulate(
        self,
        *,
        seed: Optional[bytes] = None,
        random_bytes: Optional[Callable[[int], bytes]] = None,
        backend: Optional[str] = None,
    ):
        """Return a raw capsule and shared secret.

        An explicit ``seed`` supplies the FIPS 203 random message ``m`` for
        reproducible algorithm tests. It does not model the APK JNI method's
        internal handling of its separate 32-byte seed argument.
        """
        selected = _select_backend(backend, seed, random_bytes)
        try:
            if selected == "native":
                ciphertext, secret = _native_backend(self.key_type).encrypt(self.key)
            else:
                reference = _reference_backend(self.key_type, random_bytes, seed, 32)
                secret, ciphertext = reference.encaps(self.key)
        except ValueError as exc:
            raise InvalidKeyException(f"Invalid KEM encapsulation key: {exc}") from exc
        return KemEncapsulated(
            _sized(ciphertext, self.key_type.ciphertext_length, "KEM ciphertext"),
            _sized(secret, SHARED_SECRET_LENGTH, "KEM shared secret"),
        )


@dataclass(frozen=True)
class KemSecretKey:
    key: bytes
    key_type: KemKeyType = KemKeyType.ML_KEM_1024

    def __post_init__(self):
        key_type = _type(self.key_type)
        object.__setattr__(
            self, "key", _sized(self.key, key_type.secret_key_length, "KEM secret key")
        )
        object.__setattr__(self, "key_type", key_type)

    def serialize(self):
        return self.key

    @classmethod
    def from_bytes(cls, serialized, *, key_type=None):
        return cls(serialized, _infer_type(serialized, key_type, 1, "KEM secret key"))

    def decapsulate(self, ciphertext, *, backend="native"):
        raw = _sized(ciphertext, self.key_type.ciphertext_length, "KEM ciphertext")
        selected = _select_backend(backend)
        try:
            if selected == "native":
                secret = _native_backend(self.key_type).decrypt(self.key, raw)
            else:
                secret = _reference_backend(self.key_type).decaps(self.key, raw)
        except ValueError as exc:
            raise InvalidKeyException(f"Invalid KEM decapsulation input: {exc}") from exc
        # A full-sized corrupted capsule uses the KEM's implicit rejection and
        # returns a pseudorandom secret. Authentication is checked by Signal MAC.
        return _sized(secret, SHARED_SECRET_LENGTH, "KEM shared secret")


@dataclass(frozen=True)
class KemKeyPair:
    public_key: KemPublicKey
    secret_key: KemSecretKey

    def __post_init__(self):
        if self.public_key.key_type != self.secret_key.key_type:
            raise InvalidKeyException("KEM public and secret key types differ")

    @property
    def private_key(self):
        return self.secret_key

    @classmethod
    def generate(
        cls,
        key_type=KemKeyType.ML_KEM_1024,
        *,
        seed: Optional[bytes] = None,
        random_bytes: Optional[Callable[[int], bytes]] = None,
        backend: Optional[str] = None,
    ):
        """Generate keys, optionally using the FIPS 203 ``d || z`` seed64."""
        key_type = _type(key_type)
        if _select_backend(backend, seed, random_bytes) == "native":
            public, secret = _native_backend(key_type).generate_keypair()
        else:
            public, secret = _reference_backend(key_type, random_bytes, seed, 64).keygen()
        return cls(KemPublicKey(public, key_type), KemSecretKey(secret, key_type))

    @classmethod
    def from_bytes(cls, public, secret, *, key_type=None):
        return cls(
            KemPublicKey.from_bytes(public, key_type=key_type),
            KemSecretKey.from_bytes(secret, key_type=key_type),
        )
