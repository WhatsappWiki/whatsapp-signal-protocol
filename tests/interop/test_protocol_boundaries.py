"""The common wire fixes also match the unmodified Java upstream parser."""

import pytest

from signal_protocol import Curve, PreKeyRecord, PreKeySignalMessage, SignalMessage


@pytest.mark.parametrize("length", [6, 10, 11, 21])
def test_original_java_array_signal_route(java, length):
    public = Curve.generate_key_pair().public_key.serialize()
    raw = b"\x33\x0a\x21" + public + b"\x10" + b"\x80" * (length - 1) + b"\x00\x22\x01x" + bytes(8)
    assert java.raw("roundtrip", "signal", raw) == SignalMessage.from_bytes(raw).serialize() == raw


@pytest.mark.parametrize("length", [10, 11, 21])
def test_original_java_coded_prekey_route(java, length):
    public = Curve.generate_key_pair().public_key.serialize()
    inner = b"\x33\x0a\x21" + public + b"\x10\x00\x22\x01x" + bytes(8)
    raw = (
        b"\x33\x08"
        + b"\x80" * (length - 1)
        + b"\x00\x12\x21"
        + public
        + b"\x1a\x21"
        + public
        + b"\x22"
        + bytes([len(inner)])
        + inner
        + b"\x30\x00"
    )
    if length <= 10:
        assert (
            java.raw("roundtrip", "prekey_message", raw)
            == PreKeySignalMessage.from_bytes(raw).serialize()
            == raw
        )
    else:
        with pytest.raises(RuntimeError):
            java.raw("roundtrip", "prekey_message", raw)
        with pytest.raises(Exception):
            PreKeySignalMessage.from_bytes(raw)


def test_original_java_key_record_array_route(java):
    raw = b"\x08\x83" + b"\x80" * 20 + b"\x00"
    assert (
        java.raw("roundtrip", "prekey", raw)
        == PreKeyRecord.from_bytes(raw).serialize()
        == b"\x08\x03"
    )
