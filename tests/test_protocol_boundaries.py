"""Java-lite wire edges, checked without changing the original authenticated bytes."""

import pytest
from google.protobuf.message import DecodeError

from signal_protocol import (
    WHATSAPP,
    Curve,
    IdentityKey,
    PreKeySignalMessage,
    SignalMessage,
)
from signal_protocol.exceptions import InvalidMessageException, LegacyMessageException
from signal_protocol.kdf import mac
from signal_protocol.protobuf import LocalStorageProtocol_pb2 as storage
from signal_protocol.protobuf import WhisperTextProtocol_pb2 as wire
from signal_protocol.protobuf_codec import normalize_java_protobuf, parse_java_protobuf
from signal_protocol.protocol import SenderKeyDistributionMessage, SenderKeyMessage


def key_material():
    pair = Curve.generate_key_pair()
    return pair, IdentityKey(pair.public_key)


def signal_with_counter(counter_wire):
    pair, identity = key_material()
    public = pair.public_key.serialize()
    # Build explicitly so counter replacement cannot accidentally alter key bytes.
    body = b"\x33\x0a\x21" + public + b"\x10" + counter_wire + b"\x22\x01x"
    key = bytes(range(32))
    return body + mac(key, identity.serialize() * 2 + body)[:8], identity, key


@pytest.mark.parametrize("continuations", [10, 11, 20, 127])
def test_java_overlong_uint32_preserves_signal_mac_bytes(continuations):
    raw, identity, key = signal_with_counter(b"\x80" * continuations + b"\x00")
    message = SignalMessage.from_bytes(raw, profile=WHATSAPP)
    assert message.counter == 0 and message.serialize() == raw
    message.verify_mac(identity, identity, key)
    upstream = SignalMessage.from_bytes(raw)
    assert upstream.serialize() == raw and upstream.counter == 0
    upstream.verify_mac(identity, identity, key)


@pytest.mark.parametrize(
    "raw,expected",
    [(b"\xff" * 5 + b"\x80" * 6 + b"\x00", 0xFFFFFFFF), (b"\x80" * 5 + b"\x81\x00", 0)],
)
def test_java_uint32_uses_only_first_five_bytes(raw, expected):
    data, _, _ = signal_with_counter(raw)
    assert SignalMessage.from_bytes(data, profile=WHATSAPP).counter == expected


@pytest.mark.parametrize(
    "value", [-1, -2147483648, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x1FFFFFFFF]
)
def test_message_constructors_encode_java_int_bits_as_uint32(value):
    pair, identity = key_material()
    expected = value & 0xFFFFFFFF
    signal = SignalMessage(3, bytes(32), pair.public_key, value, value, b"x", identity, identity)
    assert signal.counter == signal.previous_counter == expected
    p = wire.SignalMessage.FromString(signal.serialize()[1:-8])
    assert p.counter == p.previousCounter == expected
    prekey = PreKeySignalMessage(3, value, value, value, pair.public_key, identity, signal)
    assert prekey.registration_id == prekey.pre_key_id == prekey.signed_pre_key_id == expected
    distribution = SenderKeyDistributionMessage(value, value, bytes(32), pair.public_key)
    assert distribution.id == distribution.iteration == expected
    sender = SenderKeyMessage(value, value, b"x", pair.private_key)
    assert sender.key_id == sender.iteration == expected
    SenderKeyMessage.from_bytes(sender.serialize()).verify_signature(pair.public_key)


@pytest.mark.parametrize(
    "cls,proto,trailer",
    [
        (SenderKeyMessage, wire.SenderKeyMessage, 64),
        (SenderKeyDistributionMessage, wire.SenderKeyDistributionMessage, 0),
    ],
)
def test_group_whatsapp_decoder_accepts_long_varint_but_only_version_three(cls, proto, trailer):
    pair, _ = key_material()
    if cls is SenderKeyMessage:
        payload = b"\x08" + b"\x80" * 10 + b"\x00\x10\x00\x1a\x01x"
    else:
        public = pair.public_key.serialize()
        payload = b"\x08" + b"\x80" * 10 + b"\x00\x10\x00\x1a\x00\x22\x21" + public
    parsed = cls.from_bytes(b"\x33" + payload + bytes(trailer), profile=WHATSAPP)
    assert (parsed.key_id if cls is SenderKeyMessage else parsed.id) == 0
    with pytest.raises(LegacyMessageException):
        cls.from_bytes(b"\x23" + payload + bytes(trailer), profile=WHATSAPP)
    with pytest.raises(InvalidMessageException):
        cls.from_bytes(b"\x43" + payload + bytes(trailer), profile=WHATSAPP)


@pytest.mark.parametrize(
    "overlong,canonical",
    [
        (b"\x80" * 10 + b"\x01", b"\x40"),
        (b"\x81" * 10 + b"\x01", bytes.fromhex("c1818181818181818101")),
        (b"\xff" * 20 + b"\x01", b"\xff" * 9 + b"\x01"),
    ],
)
def test_java_unknown_varint64_shift_wrap_matches_javalite_vectors(overlong, canonical):
    # Canonical outputs independently obtained from original Java PreKeyRecord.
    original = storage.PreKeyRecordStructure(id=7).SerializeToString()
    actual = parse_java_protobuf(storage.PreKeyRecordStructure, original + b"\x48" + overlong)
    assert actual.SerializeToString() == original + b"\x48" + canonical


def test_java_tags_and_lengths_use_low32_and_keep_bytes_opaque():
    # Field 4 length=1 with extra high bits after the fifth varint byte.
    length = b"\x81" + b"\x80" * 10 + b"\x00"
    p = parse_java_protobuf(wire.SignalMessage, b"\x22" + length + b"x")
    assert p.ciphertext == b"x"
    # Known bytes content is not interpreted as nested protobuf.
    assert parse_java_protobuf(wire.SignalMessage, b"\x22\x02\xff\xff").ciphertext == b"\xff\xff"


@pytest.mark.parametrize(
    "payload",
    [
        b"\x00",
        b"\x0f",
        b"\x0e",
        b"\x08\x80",
        b"\x22\x80",
        b"\x22\xff\xff\xff\xff\x07",
        b"\x22\xff\xff\xff\xff\x0f",
        b"\x09\x00",
        b"\x0d\x00",
        b"\x4b",
        b"\x4b\x54",
        b"\x4c",
    ],
)
def test_java_normalizer_keeps_invalid_tags_truncation_and_groups_invalid(payload):
    with pytest.raises(DecodeError):
        normalize_java_protobuf(payload, wire.SignalMessage.DESCRIPTOR)


def test_java_group_limit_and_matching_end_tags():
    valid = b"\x4b" * 99 + b"\x48\x01" + b"\x4c" * 99
    assert normalize_java_protobuf(valid, wire.SignalMessage.DESCRIPTOR) == valid
    with pytest.raises(DecodeError, match="recursion"):
        normalize_java_protobuf(b"\x4b" * 100 + b"\x4c" * 100, wire.SignalMessage.DESCRIPTOR)


def test_duplicate_known_fields_last_wins_and_unknowns_are_retained():
    payload = b"\x10\x01\x48\x80" + b"\x80" * 9 + b"\x01\x10\x02"
    p = parse_java_protobuf(wire.SignalMessage, payload)
    assert p.counter == 2
    assert p.SerializeToString() == b"\x10\x02\x48\x40"


@pytest.mark.parametrize("size", [10, 11, 12, 21])
@pytest.mark.parametrize("kind", ["signal", "prekey", "distribution", "group"])
def test_actual_whatsapp_array_and_coded_parser_route_matrix(kind, size):
    # Matrix independently observed with core-parse in the actual APK:
    # all four accept ten bytes; only PreKey's ByteString route rejects >10.
    pair, identity = key_material()
    integer = b"\x80" * (size - 1) + b"\x00"
    public = pair.public_key.serialize()
    if kind == "signal":
        raw, _, _ = signal_with_counter(integer)
        cls = SignalMessage
    elif kind == "distribution":
        raw = b"\x33\x08" + integer + b"\x10\x00\x1a\x00\x22\x21" + public
        cls = SenderKeyDistributionMessage
    elif kind == "group":
        raw = b"\x33\x08" + integer + b"\x10\x00\x1a\x01x" + bytes(64)
        cls = SenderKeyMessage
    else:
        message = SignalMessage(3, bytes(32), pair.public_key, 0, 0, b"x", identity, identity)
        outer = PreKeySignalMessage(3, 1, None, 2, pair.public_key, identity, message)
        raw = outer.serialize() + b"\x08" + integer
        cls = PreKeySignalMessage
    if kind == "prekey" and size > 10:
        with pytest.raises(InvalidMessageException, match="Malformed protobuf"):
            cls.from_bytes(raw, profile=WHATSAPP)
    else:
        assert cls.from_bytes(raw, profile=WHATSAPP).serialize() == raw


@pytest.mark.parametrize("size", [11, 12, 21])
def test_prekey_coded_outer_keeps_nested_signal_array_route(size):
    raw, identity, key = signal_with_counter(b"\x80" * (size - 1) + b"\x00")
    inner = SignalMessage.from_bytes(raw, profile=WHATSAPP)
    outer = PreKeySignalMessage(3, 1, None, 2, identity.public_key, identity, inner)
    parsed = PreKeySignalMessage.from_bytes(outer.serialize(), profile=WHATSAPP)
    assert parsed.message.serialize() == raw and parsed.message.counter == 0
    parsed.message.verify_mac(identity, identity, key)


@pytest.mark.parametrize("tail", [b"\x00", b"\x01", b"\x7f"])
def test_coded_uint32_tenth_byte_ignores_bits_after_first_five(tail):
    raw = b"\x10" + b"\xff" * 9 + tail
    result = parse_java_protobuf(wire.SignalMessage, raw, route="coded")
    assert result.counter == 0xFFFFFFFF


@pytest.mark.parametrize(
    "raw",
    [
        b"\x88" + b"\x80" * 9 + b"\x00\x00",
        b"\x22\x81" + b"\x80" * 9 + b"\x00x",
        b"\x10" + b"\x80" * 10 + b"\x00",
    ],
)
def test_coded_ten_byte_cap_applies_to_tags_lengths_and_values(raw):
    normalize_java_protobuf(raw, wire.SignalMessage.DESCRIPTOR, route="array")
    with pytest.raises(DecodeError, match="CodedInputStream"):
        normalize_java_protobuf(raw, wire.SignalMessage.DESCRIPTOR, route="coded")
