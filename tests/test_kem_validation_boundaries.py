"""Malformed ML-KEM keys fail before either backend can change protocol state."""

from dataclasses import replace
from hashlib import sha3_256

import pytest

from signal_protocol import WHATSAPP, Curve, InMemorySignalProtocolStore, KeyHelper
from signal_protocol.exceptions import InvalidKeyException
from signal_protocol.kem import KemKeyPair, KemKeyType, KemPublicKey, KemSecretKey
from signal_protocol.session_builder import SessionBuilder
from signal_protocol.session_cipher import SessionCipher
from tests.helpers import ALICE, BOB, bundle


@pytest.fixture(params=list(KemKeyType))
def pair(request):
    return KemKeyPair.generate(request.param, seed=bytes(range(64)))


def with_coefficient(public, value, *, last=False):
    """Encode the first or last 12-bit coefficient, preserving its neighbor."""
    raw = bytearray(public)
    if last:
        raw[-34] = (raw[-34] & 15) | ((value & 15) << 4)
        raw[-33] = value >> 4
    else:
        raw[0] = value & 255
        raw[1] = (raw[1] & 240) | (value >> 8)
    return bytes(raw)


@pytest.mark.parametrize("backend", ["native", "reference"])
@pytest.mark.parametrize("last", [False, True])
@pytest.mark.parametrize("value", [3329, 4095])
def test_noncanonical_public_coefficients_are_rejected(pair, backend, last, value):
    public = KemPublicKey.from_bytes(with_coefficient(pair.public_key.key, value, last=last))
    with pytest.raises(InvalidKeyException):
        public.encapsulate(backend=backend)


@pytest.mark.parametrize("backend", ["native", "reference"])
@pytest.mark.parametrize("value", [0, 3328])
def test_canonical_extremes_and_unrestricted_public_seed_remain_accepted(pair, backend, value):
    raw = with_coefficient(pair.public_key.key, value)
    raw = with_coefficient(raw, value, last=True)
    public = KemPublicKey.from_bytes(raw[:-32] + b"\xff" * 32)
    result = public.encapsulate(backend=backend)
    assert len(result.ciphertext) == pair.public_key.key_type.ciphertext_length
    assert len(result.shared_secret) == 32


def test_invalid_public_key_is_rejected_before_requesting_entropy(pair):
    def forbidden(length):
        raise AssertionError("Entropy requested before validating the public key")

    public = KemPublicKey.from_bytes(with_coefficient(pair.public_key.key, 3329))
    with pytest.raises(InvalidKeyException):
        public.encapsulate(random_bytes=forbidden)


@pytest.mark.parametrize("backend", ["native", "reference"])
@pytest.mark.parametrize("offset", [-96, -64, -33])
def test_decapsulation_rejects_corrupted_embedded_public_key_or_hash(pair, backend, offset):
    capsule = pair.public_key.encapsulate(seed=bytes(range(32)))
    raw = bytearray(pair.secret_key.key)
    raw[offset] ^= 1
    secret = KemSecretKey.from_bytes(raw)
    with pytest.raises(InvalidKeyException):
        secret.decapsulate(capsule.ciphertext, backend=backend)


@pytest.mark.parametrize("backend", ["native", "reference"])
def test_embedded_noncanonical_public_key_is_rejected_even_with_matching_hash(pair, backend):
    capsule = pair.public_key.encapsulate(seed=bytes(range(32)))
    public = with_coefficient(pair.public_key.key, 4095, last=True)
    offset = len(public) - 32
    raw = (
        pair.secret_key.key[:offset]
        + public
        + sha3_256(public).digest()
        + pair.secret_key.key[-32:]
    )
    secret = KemSecretKey.from_bytes(raw)
    with pytest.raises(InvalidKeyException):
        secret.decapsulate(capsule.ciphertext, backend=backend)


def test_rejection_secret_is_not_included_in_embedded_public_key_hash(pair):
    capsule = pair.public_key.encapsulate(seed=bytes(range(32)))
    secret = KemSecretKey.from_bytes(pair.secret_key.key[:-32] + bytes(32))
    altered = capsule.ciphertext[:-1] + bytes([capsule.ciphertext[-1] ^ 1])
    assert secret.decapsulate(capsule.ciphertext) == capsule.shared_secret
    rejected = secret.decapsulate(altered)
    assert rejected == secret.decapsulate(altered, backend="reference")
    assert rejected != pair.secret_key.decapsulate(altered)


def hybrid_bundle(store, key_type):
    prekey = bundle(store)
    kem = KeyHelper.generate_kyber_pre_key(
        store.identity_key_pair, 71, key_type=key_type, seed=bytes(range(64))
    )
    store.store_kyber_pre_key(kem.id, kem)
    return replace(
        prekey,
        kyber_pre_key_id=kem.id,
        kyber_pre_key=kem.key_pair.public_key,
        kyber_pre_key_signature=kem.signature,
    )


def snapshot(store):
    return tuple(
        dict(values)
        for values in (
            store.sessions,
            store.pre_keys,
            store.signed_pre_keys,
            store.kyber_pre_keys,
            store.trusted_keys,
        )
    )


@pytest.mark.parametrize("key_type", list(KemKeyType))
def test_invalid_signed_kem_bundle_preserves_existing_session_and_identity(key_type):
    alice, bob = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    prekey = hybrid_bundle(bob, key_type)
    builder = SessionBuilder(alice, BOB, profile=WHATSAPP)
    builder.process(prekey)
    before = snapshot(alice)
    invalid = KemPublicKey.from_bytes(with_coefficient(prekey.kyber_pre_key.key, 3329))
    signature = Curve.calculate_signature(bob.identity_key_pair.private_key, invalid.key)
    with pytest.raises(InvalidKeyException):
        builder.process(replace(prekey, kyber_pre_key=invalid, kyber_pre_key_signature=signature))
    assert snapshot(alice) == before
    message = SessionCipher(alice, BOB, profile=WHATSAPP).encrypt(b"existing session")
    assert SessionCipher(bob, ALICE, profile=WHATSAPP).decrypt(message) == b"existing session"


@pytest.mark.parametrize("key_type", list(KemKeyType))
def test_corrupted_kem_private_key_does_not_commit_or_consume_prekeys(key_type):
    alice, bob = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    prekey = hybrid_bundle(bob, key_type)
    SessionBuilder(alice, BOB, profile=WHATSAPP).process(prekey)
    message = SessionCipher(alice, BOB, profile=WHATSAPP).encrypt(b"retry after key repair")
    original = bob.load_kyber_pre_key(71)
    corrupted = bob.load_kyber_pre_key(71)
    raw = bytearray(corrupted.structure.privateKey)
    raw[-64] ^= 1
    corrupted.structure.privateKey = bytes(raw)
    bob.store_kyber_pre_key(71, corrupted)
    before = snapshot(bob)
    callback = []
    cipher = SessionCipher(bob, ALICE, profile=WHATSAPP)
    with pytest.raises(InvalidKeyException):
        cipher.decrypt(message, callback.append)
    assert snapshot(bob) == before
    assert callback == []
    bob.store_kyber_pre_key(71, original)
    assert cipher.decrypt(message) == b"retry after key repair"
    assert not bob.contains_pre_key(prekey.pre_key_id)
    assert not bob.contains_kyber_pre_key(71)
