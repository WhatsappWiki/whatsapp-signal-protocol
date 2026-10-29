"""WhatsApp business-boundary behavior, including permissive unpadding."""

import base64
import json
from pathlib import Path

import pytest
from nacl import bindings

from signal_protocol import Curve, ECPublicKey
from signal_protocol.ecc import montgomery_to_edwards
from signal_protocol.exceptions import InvalidKeyException, InvalidMessageException
from signal_protocol.whatsapp import (
    decode_identity_key,
    pad_message,
    unpad_message,
    validate_public_key,
)

_CAPTURE = json.loads((Path(__file__).parent / "vectors/whatsapp-runtime.json").read_text())


@pytest.mark.parametrize("length", range(1, 17))
def test_business_padding_lengths(length):
    message = b"WhatsApp business payload"
    padded = pad_message(message, padding_length=length)
    assert padded == message + bytes([length]) * length
    assert unpad_message(padded) == message


def test_padding_randomness_callback_has_exact_range():
    calls = []

    def select(limit):
        calls.append(limit)
        return 15

    assert pad_message(b"message", randbelow=select) == b"message" + b"\x10" * 16
    assert calls == [16]


@pytest.mark.parametrize("count", (0, 17, -1, 256, True, 1.5))
def test_padding_rejects_invalid_explicit_counts(count):
    with pytest.raises(ValueError):
        pad_message(b"message", padding_length=count)


def test_padding_receiver_uses_only_last_byte():
    # CYN.A02 checks neither preceding byte values nor the producer's <=16 bound.
    assert unpad_message(b"payload\x99\x98\x03") == b"payload"
    assert unpad_message(b"payload" + b"x" * 31 + b"\x20") == b"payload"
    assert unpad_message(b"payload" + b"x" * 254 + b"\xff") == b"payload"


@pytest.mark.parametrize("message", (None, b"", b"payload\x00", b"\x01", b"xx\x03", b"x\xff"))
def test_invalid_business_padding(message):
    with pytest.raises(InvalidMessageException):
        unpad_message(message)


def test_empty_payload_is_not_a_valid_receiver_message():
    with pytest.raises(InvalidMessageException):
        unpad_message(pad_message(b"", padding_length=8))


def test_all_captured_padding_records_roundtrip():
    rows = [r for r in _CAPTURE["core"] if r["request"]["op"] == "padding"]
    assert len(rows) == 24
    for row in rows:
        raw = base64.b64decode(row["request"]["message"])
        padded = base64.b64decode(row["response"]["value"])
        assert pad_message(raw, padding_length=padded[-1]) == padded
        assert unpad_message(padded) == raw


def test_strict_decoder_matches_captured_android_acceptance():
    rows = [r for r in _CAPTURE["boundaries"] if r["request"]["op"] == "strict"]
    assert len(rows) == 8
    for row in rows:
        q = row["request"]
        public = base64.b64decode(q["public"])
        if row["response"]["ok"]:
            assert decode_identity_key(public, strict=q["strict"]).serialize() == public
        else:
            with pytest.raises(InvalidKeyException):
                decode_identity_key(public, strict=q["strict"])


def test_generated_curve_keys_pass_strict_validation():
    for _ in range(24):
        public = Curve.generate_key_pair().public_key
        validate_public_key(public)
        assert decode_identity_key(public.serialize()) == public


@pytest.mark.parametrize("coordinate", (2, 3, 5, 12, 14))
def test_strict_validation_rejects_twist_points(coordinate):
    public = ECPublicKey(coordinate.to_bytes(32, "little"))
    with pytest.raises(InvalidKeyException, match="not torsion-free"):
        validate_public_key(public)


@pytest.mark.parametrize("coordinate", (0, 1))
def test_strict_validation_rejects_small_order_points(coordinate):
    with pytest.raises(InvalidKeyException, match="not torsion-free"):
        validate_public_key(ECPublicKey(coordinate.to_bytes(32, "little")))


@pytest.mark.parametrize("coordinate", (4, 6, 7, 8, 10))
def test_strict_rule_does_not_substitute_prime_subgroup_policy(coordinate):
    public = ECPublicKey(coordinate.to_bytes(32, "little"))
    assert not bindings.crypto_core_ed25519_is_valid_point(montgomery_to_edwards(public.key))
    validate_public_key(public)


def test_identity_decoder_offsets_trailing_bytes_and_optional_strict():
    public = Curve.generate_key_pair().public_key
    assert decode_identity_key(b"prefix" + public.serialize() + b"trailing", offset=6) == public
    unusual = b"\x05" + bytes(32)
    assert decode_identity_key(unusual, strict=False) == Curve.decode_point(unusual)
    for encoded in (b"", b"\x05", b"\x06" + bytes(32)):
        with pytest.raises(InvalidKeyException):
            decode_identity_key(encoded, strict=False)


@pytest.mark.parametrize("coordinate", (2**255 - 19, 2**255, 2**256 - 1))
def test_strict_public_range_is_not_reduced(coordinate):
    with pytest.raises(InvalidKeyException, match="out of range"):
        validate_public_key(ECPublicKey(coordinate.to_bytes(32, "little")))
