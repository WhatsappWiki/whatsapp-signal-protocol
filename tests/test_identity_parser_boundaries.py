"""Identity-related byte-array protobuf parsers retain Java's varint behavior."""

import pytest

from signal_protocol import KeyHelper
from signal_protocol.devices import DeviceConsistencyCommitment, DeviceConsistencyMessage
from signal_protocol.exceptions import FingerprintParsingException, InvalidMessageException
from signal_protocol.fingerprint import ScannableFingerprint


def overlong_first_varint(serialized, width):
    assert serialized[0] == 8  # generation/version field
    end = 1
    while serialized[end] & 128:
        end += 1
    value = serialized[1:end] + bytes([serialized[end] | 128])
    return b"\x08" + value + b"\x80" * (width - len(value) - 1) + b"\x00" + serialized[end + 1 :]


@pytest.mark.parametrize("width", [6, 11, 21])
@pytest.mark.parametrize("version", [1, 0xFFFFFFFF])
def test_scanned_fingerprint_accepts_java_array_varints(version, width):
    local = ScannableFingerprint(version, b"a" * 32, b"b" * 32)
    remote = ScannableFingerprint(version, b"b" * 32, b"a" * 32)
    scanned = overlong_first_varint(remote.serialize(), width)
    assert local.compare_to(scanned)
    wrong = ScannableFingerprint(version, b"x" * 32, b"a" * 32)
    assert not local.compare_to(overlong_first_varint(wrong.serialize(), width))


@pytest.mark.parametrize("width", [6, 11, 21])
@pytest.mark.parametrize("generation", [1, 0xFFFFFFFF])
def test_device_message_accepts_java_array_varints_and_retains_original_bytes(generation, width):
    identity = KeyHelper.generate_identity_key_pair()
    commitment = DeviceConsistencyCommitment(generation, [identity.public_key])
    message = DeviceConsistencyMessage(commitment, identity)
    serialized = overlong_first_varint(message.serialize(), width)
    restored = DeviceConsistencyMessage.from_bytes(commitment, serialized, identity.public_key)

    assert restored.generation == generation
    assert restored.signature == message.signature
    assert restored.serialize() == serialized
    tampered = serialized[:-1] + bytes([serialized[-1] ^ 1])
    with pytest.raises(InvalidMessageException):
        DeviceConsistencyMessage.from_bytes(commitment, tampered, identity.public_key)


@pytest.mark.parametrize("serialized", [b"\x08\x80", b"\x12\xff", b"\x00"])
def test_identity_parsers_still_translate_malformed_protobuf_errors(serialized):
    with pytest.raises(FingerprintParsingException):
        ScannableFingerprint(1, b"a" * 32, b"b" * 32).compare_to(serialized)
    identity = KeyHelper.generate_identity_key_pair()
    commitment = DeviceConsistencyCommitment(1, [identity.public_key])
    with pytest.raises(InvalidMessageException):
        DeviceConsistencyMessage.from_bytes(commitment, serialized, identity.public_key)
