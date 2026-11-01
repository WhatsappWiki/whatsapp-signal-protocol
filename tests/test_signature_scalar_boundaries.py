"""Raw imported scalar boundaries match the unchanged Java and JNI signers."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import signal_protocol.ecc as ecc
from signal_protocol import Curve, ECPrivateKey

VECTORS = json.loads(
    (Path(__file__).parent / "vectors/signature-scalar-boundaries.json").read_text()
)["vectors"]


@pytest.mark.parametrize("vector", VECTORS)
def test_imported_scalar_signature_matches_java_and_jni(vector):
    raw = {name: bytes.fromhex(value) for name, value in vector.items()}
    assert (
        Curve.calculate_signature(
            ECPrivateKey(raw["private"]), raw["message"], random=raw["random"]
        )
        == raw["signature"]
    )


def test_zero_nonce_produces_identity_point_and_a_verifiable_signature(monkeypatch):
    pair = Curve.generate_key_pair()

    def force_zero_nonce(data):
        if data.startswith(b"\xfe" + b"\xff" * 31):
            return SimpleNamespace(digest=lambda: bytes(64))
        return hashlib.sha512(data)

    monkeypatch.setattr(ecc, "sha512", force_zero_nonce)
    signature = Curve.calculate_signature(pair.private_key, b"zero nonce boundary")
    assert signature[:32] == b"\x01" + bytes(31)
    assert Curve.verify_signature(pair.public_key, b"zero nonce boundary", signature)
    assert not Curve.verify_signature(pair.public_key, b"changed message", signature)
