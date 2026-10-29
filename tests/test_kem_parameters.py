"""Cross-implementation ML-KEM parameter and raw-format coverage."""

from itertools import permutations

import pytest

from signal_protocol.exceptions import InvalidKeyException
from signal_protocol.kem import (
    CIPHERTEXT_LENGTH,
    PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH,
    KemKeyPair,
    KemKeyType,
    KemPublicKey,
    KemSecretKey,
)

PARAMETERS = (
    (KemKeyType.ML_KEM_512, 6, 800, 1632, 768),
    (KemKeyType.ML_KEM_768, 7, 1184, 2400, 1088),
    (KemKeyType.ML_KEM_1024, 10, 1568, 3168, 1568),
)


@pytest.mark.parametrize("key_type,code,public_length,private_length,capsule_length", PARAMETERS)
@pytest.mark.parametrize("generator", ("native", "reference"))
@pytest.mark.parametrize("encapsulator", ("native", "reference"))
def test_parameter_backends_cross_decapsulate(
    key_type, code, public_length, private_length, capsule_length, generator, encapsulator
):
    pair = KemKeyPair.generate(key_type, backend=generator)
    assert int(pair.public_key.key_type) == int(pair.secret_key.key_type) == code
    assert len(pair.public_key.serialize()) == public_length
    assert len(pair.secret_key.serialize()) == private_length
    restored = KemKeyPair.from_bytes(pair.public_key.serialize(), pair.secret_key.serialize())
    assert restored == pair
    capsule = restored.public_key.encapsulate(backend=encapsulator)
    assert len(capsule.ciphertext) == capsule_length
    assert len(capsule.shared_secret) == 32
    for backend in ("native", "reference"):
        assert (
            restored.secret_key.decapsulate(capsule.ciphertext, backend=backend)
            == capsule.shared_secret
        )


@pytest.mark.parametrize("key_type,code,public_length,private_length,capsule_length", PARAMETERS)
def test_deterministic_parameter_generation_and_implicit_rejection(
    key_type, code, public_length, private_length, capsule_length
):
    # Native PQClean and the independent reference agree on both normal and
    # implicit-rejection outputs. Test entropy remains local to each operation.
    seed = bytes(range(64))
    pair = KemKeyPair.generate(key_type, seed=seed)
    assert pair == KemKeyPair.generate(key_type, seed=seed)
    capsule = pair.public_key.encapsulate(seed=bytes(range(32)))
    assert capsule == pair.public_key.encapsulate(seed=bytes(range(32)))
    altered = capsule.ciphertext[:-1] + bytes([capsule.ciphertext[-1] ^ 1])
    rejected = pair.secret_key.decapsulate(altered)
    assert rejected != capsule.shared_secret
    assert pair.secret_key.decapsulate(altered, backend="reference") == rejected


@pytest.mark.parametrize("source,target", list(permutations(KemKeyType, 2)))
def test_cross_parameter_import_and_decapsulation_rejected(source, target):
    pair = KemKeyPair.generate(source, seed=bytes(range(64)))
    other = KemKeyPair.generate(target, seed=bytes(range(64)))
    with pytest.raises(InvalidKeyException):
        KemPublicKey.from_bytes(pair.public_key.serialize(), key_type=target)
    with pytest.raises(InvalidKeyException):
        KemSecretKey.from_bytes(pair.secret_key.serialize(), key_type=target)
    with pytest.raises(InvalidKeyException, match="types differ"):
        KemKeyPair.from_bytes(pair.public_key.serialize(), other.secret_key.serialize())
    with pytest.raises(InvalidKeyException, match="types differ"):
        KemKeyPair(pair.public_key, other.secret_key)
    capsule = other.public_key.encapsulate(seed=bytes(range(32)))
    for backend in ("native", "reference"):
        with pytest.raises(InvalidKeyException):
            pair.secret_key.decapsulate(capsule.ciphertext, backend=backend)


@pytest.mark.parametrize("key_type,code,public_length,private_length,capsule_length", PARAMETERS)
def test_explicit_parameter_and_default_1024_constructor_rules(
    key_type, code, public_length, private_length, capsule_length
):
    pair = KemKeyPair.generate(key_type, seed=bytes(range(64)))
    assert KemPublicKey.from_bytes(pair.public_key.key).key_type == key_type
    assert KemSecretKey.from_bytes(pair.secret_key.key).key_type == key_type
    assert KemPublicKey.from_bytes(pair.public_key.key, key_type=code) == pair.public_key
    assert KemSecretKey.from_bytes(pair.secret_key.key, key_type=code) == pair.secret_key
    if key_type != KemKeyType.ML_KEM_1024:
        with pytest.raises(InvalidKeyException):
            KemPublicKey(pair.public_key.key)
        with pytest.raises(InvalidKeyException):
            KemSecretKey(pair.secret_key.key)
    else:
        assert KemPublicKey(pair.public_key.key) == pair.public_key
        assert KemSecretKey(pair.secret_key.key) == pair.secret_key
    for length in (0, 1, public_length - 1, public_length + 1):
        with pytest.raises(InvalidKeyException):
            KemPublicKey.from_bytes(bytes(length))
    for length in (0, 1, private_length - 1, private_length + 1):
        with pytest.raises(InvalidKeyException):
            KemSecretKey.from_bytes(bytes(length))


def test_1024_size_constants_remain_backward_compatible():
    assert (PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, CIPHERTEXT_LENGTH) == (1568, 3168, 1568)
