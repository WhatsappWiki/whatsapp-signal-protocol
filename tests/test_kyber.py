"""KEM vectors and format/type boundaries, independent of the handshake code."""

import json
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import signal_protocol.kem as kem
from signal_protocol.exceptions import InvalidKeyException
from signal_protocol.kem import (
    KemKeyPair,
    KemKeyType,
    KemPublicKey,
    KemSecretKey,
)

OPENSSL = json.loads((Path(__file__).parent / "vectors/mlkem1024-openssl.json").read_text())
WHATSAPP = json.loads((Path(__file__).parent / "vectors/mlkem1024-whatsapp.json").read_text())


def test_whatsapp_native_key_generation_raw_encoding():
    row = WHATSAPP["keygen"]
    assert row["response"]["ok"]
    pair = KemKeyPair.generate(seed=b64decode(row["request"]["seed"]))
    expected = row["response"]["value"]
    assert pair.public_key.serialize() == b64decode(expected["public"])
    assert pair.secret_key.serialize() == b64decode(expected["private"])


def test_whatsapp_native_capsule_decapsulation():
    row = WHATSAPP["encapsulation"]
    assert row["response"]["ok"]
    private = b64decode(WHATSAPP["keygen"]["response"]["value"]["private"])
    native = row["response"]["value"]
    ciphertext = b64decode(native["ciphertext"])
    assert len(ciphertext) == 1568
    assert KemSecretKey.from_bytes(private).decapsulate(ciphertext) == b64decode(native["secret"])
    # The APK's own independent JNI decapsulation agrees with the original.
    own = WHATSAPP["decapsulation"]
    assert own["response"]["ok"]
    assert b64decode(own["response"]["value"]) == b64decode(native["secret"])


@pytest.mark.parametrize("vector", OPENSSL["vectors"])
def test_mlkem1024_independent_openssl_vector(vector):
    value = {k: bytes.fromhex(v) for k, v in vector.items()}
    pair = KemKeyPair.generate(seed=value["seed"])
    assert pair.public_key.key == value["public"]
    assert pair.secret_key.decapsulate(value["ciphertext"]) == value["shared_secret"]
    assert (
        pair.secret_key.decapsulate(value["mutated_ciphertext"]) == value["mutated_shared_secret"]
    )
    assert value["shared_secret"] != value["mutated_shared_secret"]
    assert (
        pair.secret_key.decapsulate(value["ciphertext"], backend="reference")
        == value["shared_secret"]
    )
    assert (
        pair.secret_key.decapsulate(value["mutated_ciphertext"], backend="reference")
        == value["mutated_shared_secret"]
    )


@pytest.mark.parametrize("key_type", list(KemKeyType))
def test_kem_encapsulation_type_and_record_roundtrip(key_type):
    pair = KemKeyPair.generate(key_type, seed=bytes(range(64)))
    assert len(pair.public_key.serialize()) == key_type.public_key_length
    assert len(pair.secret_key.serialize()) == key_type.secret_key_length
    restored = KemKeyPair.from_bytes(pair.public_key.serialize(), pair.secret_key.serialize())
    assert restored == pair
    capsule = restored.public_key.encapsulate(seed=bytes(range(32)))
    assert len(capsule.ciphertext) == key_type.ciphertext_length
    assert restored.private_key.decapsulate(capsule.ciphertext) == capsule.shared_secret


def test_legacy_kyber_is_never_silently_substituted():
    with pytest.raises(InvalidKeyException, match="Unsupported KEM key type"):
        KemKeyPair.generate(8, seed=bytes(range(64)))
    with pytest.raises(InvalidKeyException, match="Unsupported KEM key type"):
        KemPublicKey(bytes(1568), 8)


def test_entropy_and_deterministic_calls_do_not_share_mutable_rng():
    seeds = [bytes([i]) * 64 for i in range(4)]
    expected = [KemKeyPair.generate(seed=seed) for seed in seeds]
    with ThreadPoolExecutor(max_workers=4) as pool:
        concurrent = list(pool.map(lambda seed: KemKeyPair.generate(seed=seed), seeds))
    assert concurrent == expected
    observed = []

    def source(length):
        observed.append(length)
        return bytes([7]) * length

    assert KemKeyPair.generate(random_bytes=source) == KemKeyPair.generate(seed=b"\x07" * 64)
    assert observed == [32, 32]
    first = expected[0].public_key.encapsulate(seed=b"\x04" * 32)
    second = expected[1].public_key.encapsulate(seed=b"\x05" * 32)
    assert first == expected[0].public_key.encapsulate(seed=b"\x04" * 32)
    assert second == expected[1].public_key.encapsulate(seed=b"\x05" * 32)


@pytest.mark.parametrize("cls,length", [(KemPublicKey, 1568), (KemSecretKey, 3168)])
@pytest.mark.parametrize("delta", [-1, 1])
def test_key_length_validation(cls, length, delta):
    with pytest.raises(InvalidKeyException):
        cls(bytes(length + delta))
    with pytest.raises(InvalidKeyException):
        cls.from_bytes(bytes(length + delta))


@pytest.mark.parametrize("cls,length", [(KemPublicKey, 1568), (KemSecretKey, 3168)])
def test_key_type_validation(cls, length):
    with pytest.raises(InvalidKeyException, match="Unsupported KEM key type"):
        cls.from_bytes(bytes(length), key_type=8)
    with pytest.raises(InvalidKeyException, match="Unsupported KEM key type"):
        cls(bytes(length), 9)


def test_seed_and_entropy_validation():
    for seed in (b"", bytes(32), bytes(63), bytes(65)):
        with pytest.raises(InvalidKeyException):
            KemKeyPair.generate(seed=seed)
    pair = KemKeyPair.generate(seed=bytes(64))
    for seed in (b"", bytes(31), bytes(33)):
        with pytest.raises(InvalidKeyException):
            pair.public_key.encapsulate(seed=seed)
    with pytest.raises(ValueError, match="not both"):
        KemKeyPair.generate(seed=bytes(64), random_bytes=lambda n: bytes(n))
    with pytest.raises(InvalidKeyException, match="Entropy source result"):
        KemKeyPair.generate(random_bytes=lambda n: bytes(n - 1))
    with pytest.raises(InvalidKeyException):
        pair.secret_key.decapsulate(bytes(1567))
    with pytest.raises(InvalidKeyException):
        pair.secret_key.decapsulate(bytes(1570))


@pytest.mark.parametrize("generator", ["native", "reference"])
@pytest.mark.parametrize("encapsulator", ["native", "reference"])
def test_native_and_reference_backend_interoperate(generator, encapsulator):
    pair = KemKeyPair.generate(backend=generator)
    capsule = pair.public_key.encapsulate(backend=encapsulator)
    assert pair.secret_key.decapsulate(capsule.ciphertext) == capsule.shared_secret
    assert (
        pair.secret_key.decapsulate(capsule.ciphertext, backend="reference")
        == capsule.shared_secret
    )


def test_normal_operations_use_native_without_reference_fallback(monkeypatch):
    native = kem._native_backend()
    calls = []
    for name in ("generate_keypair", "encrypt", "decrypt"):
        original = getattr(native, name)

        def spy(*args, _operation=name, _original=original):
            calls.append(_operation)
            return _original(*args)

        monkeypatch.setattr(native, name, spy)

    def forbidden(*args, **kwargs):
        raise AssertionError("Reference backend entered during a normal operation")

    monkeypatch.setattr(kem, "_reference_backend", forbidden)
    pair = KemKeyPair.generate()
    capsule = pair.public_key.encapsulate()
    assert pair.secret_key.decapsulate(capsule.ciphertext) == capsule.shared_secret
    assert calls == ["generate_keypair", "encrypt", "decrypt"]


@pytest.mark.parametrize("operation", ["generate", "encapsulate", "decapsulate"])
def test_native_errors_are_not_retried_with_reference(monkeypatch, operation):
    pair = KemKeyPair.generate(seed=bytes(64))
    capsule = pair.public_key.encapsulate(seed=bytes(32))
    native = kem._native_backend()
    name = {"generate": "generate_keypair", "encapsulate": "encrypt", "decapsulate": "decrypt"}[
        operation
    ]

    def fail(*args):
        raise RuntimeError("independent native failure sentinel")

    def forbidden(*args, **kwargs):
        raise AssertionError("Reference backend entered after native failure")

    monkeypatch.setattr(native, name, fail)
    monkeypatch.setattr(kem, "_reference_backend", forbidden)
    action = {
        "generate": lambda: KemKeyPair.generate(),
        "encapsulate": lambda: pair.public_key.encapsulate(),
        "decapsulate": lambda: pair.secret_key.decapsulate(capsule.ciphertext),
    }[operation]
    with pytest.raises(RuntimeError, match="independent native failure sentinel"):
        action()


def test_explicit_reference_seed_path_does_not_enter_native(monkeypatch):
    def forbidden():
        raise AssertionError("Native backend entered during explicit reference operation")

    monkeypatch.setattr(kem, "_native_backend", forbidden)
    pair = KemKeyPair.generate(seed=bytes(64))
    capsule = pair.public_key.encapsulate(seed=bytes(32))
    assert (
        pair.secret_key.decapsulate(capsule.ciphertext, backend="reference")
        == capsule.shared_secret
    )


def test_backend_selection_is_explicit():
    pair = KemKeyPair.generate(seed=bytes(64))
    with pytest.raises(ValueError, match="own entropy"):
        KemKeyPair.generate(backend="native", seed=bytes(64))
    with pytest.raises(ValueError, match="own entropy"):
        pair.public_key.encapsulate(backend="native", seed=bytes(32))
    with pytest.raises(ValueError, match="backend must"):
        KemKeyPair.generate(backend="fallback")
    with pytest.raises(ValueError, match="backend must"):
        pair.public_key.encapsulate(backend="fallback")
    with pytest.raises(ValueError, match="backend must"):
        pair.secret_key.decapsulate(bytes(1568), backend="fallback")
