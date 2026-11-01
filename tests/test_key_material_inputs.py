"""Key and entropy inputs must be buffers, never byte-count constructors."""

import pytest

from signal_protocol import Curve, ECPrivateKey, ECPublicKey
from signal_protocol.exceptions import InvalidKeyException
from signal_protocol.kem import KemKeyPair, KemPublicKey, KemSecretKey


@pytest.mark.parametrize(
    "cls,size", [(ECPrivateKey, 32), (ECPublicKey, 32), (KemPublicKey, 1568), (KemSecretKey, 3168)]
)
@pytest.mark.parametrize("make_invalid", [lambda size: size, lambda size: [0] * size])
def test_key_constructors_reject_non_buffer_inputs(cls, size, make_invalid):
    with pytest.raises(InvalidKeyException):
        cls(make_invalid(size))


@pytest.mark.parametrize("cls,size", [(KemPublicKey, 1568), (KemSecretKey, 3168)])
@pytest.mark.parametrize("explicit_type", [False, True])
def test_kem_import_rejects_integer_instead_of_raw_bytes(cls, size, explicit_type):
    kwargs = {"key_type": 10} if explicit_type else {}
    with pytest.raises(InvalidKeyException):
        cls.from_bytes(size, **kwargs)


@pytest.mark.parametrize("operation", ["generate", "encapsulate"])
@pytest.mark.parametrize("source", ["integer_seed", "integer_entropy", "list_entropy"])
def test_kem_rejects_non_buffer_seeds_and_entropy(operation, source):
    if operation == "generate":
        call, length = KemKeyPair.generate, 64
    else:
        pair = KemKeyPair.generate(seed=bytes(range(64)))
        call, length = pair.public_key.encapsulate, 32
    kwargs = {
        "integer_seed": {"seed": length},
        "integer_entropy": {"random_bytes": lambda size: size},
        "list_entropy": {"random_bytes": lambda size: [0] * size},
    }[source]
    with pytest.raises(InvalidKeyException):
        call(**kwargs)


@pytest.mark.parametrize(
    "method,size", [(Curve.calculate_signature, 64), (Curve.calculate_vrf_signature, 32)]
)
@pytest.mark.parametrize("make_invalid", [lambda size: size, lambda size: [0] * size])
def test_signatures_reject_non_buffer_randomness(method, size, make_invalid):
    private = Curve.generate_key_pair().private_key
    with pytest.raises(InvalidKeyException):
        method(private, b"message", random=make_invalid(size))


@pytest.mark.parametrize("wrapper", [bytes, bytearray, memoryview])
def test_supported_buffers_preserve_key_material_and_deterministic_outputs(wrapper):
    raw = bytes(range(32))
    assert ECPrivateKey(wrapper(raw)).serialize() == raw
    assert ECPublicKey(wrapper(raw)).serialize() == b"\x05" + raw
    expected = KemKeyPair.generate(seed=bytes(range(64)))
    assert KemKeyPair.generate(seed=wrapper(bytes(range(64)))) == expected
    restored = KemKeyPair.from_bytes(
        wrapper(expected.public_key.serialize()), wrapper(expected.secret_key.serialize())
    )
    capsule = restored.public_key.encapsulate(seed=wrapper(raw))
    assert capsule == expected.public_key.encapsulate(seed=raw)
    assert restored.secret_key.decapsulate(wrapper(capsule.ciphertext)) == capsule.shared_secret
    private = Curve.generate_key_pair().private_key
    for method, size in ((Curve.calculate_signature, 64), (Curve.calculate_vrf_signature, 32)):
        randomness = bytes(range(size))
        assert method(private, b"message", random=wrapper(randomness)) == method(
            private, b"message", random=randomness
        )


def test_key_inputs_are_copied_before_callers_reuse_mutable_buffers():
    raw = bytearray(range(32))
    private, public = ECPrivateKey(raw), ECPublicKey(memoryview(raw))
    pair = KemKeyPair.generate(seed=bytes(range(64)))
    kem_bytes = bytearray(pair.public_key.serialize())
    kem = KemPublicKey.from_bytes(memoryview(kem_bytes))
    raw[:] = bytes(32)
    kem_bytes[:] = bytes(len(kem_bytes))
    assert private.serialize() == bytes(range(32))
    assert public.serialize() == b"\x05" + bytes(range(32))
    assert kem == pair.public_key
