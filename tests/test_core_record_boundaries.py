"""Record decoder and public integer views use the same wire bit patterns."""

import pytest

from signal_protocol import (
    WHATSAPP,
    Curve,
    InMemorySignalProtocolStore,
    KeyHelper,
    KyberPreKeyRecord,
    PreKeyRecord,
    SessionRecord,
    SessionState,
    SignedPreKeyRecord,
)
from signal_protocol.devices import DeviceConsistencyCommitment, DeviceConsistencyMessage
from signal_protocol.fingerprint import ScannableFingerprint
from signal_protocol.groups import SenderKeyRecord


@pytest.mark.parametrize(
    "start,expected",
    [
        (-2147483648, [256, 4294967041, 4294967042, 4294967043]),
        (-2147483647, [4294967041, 4294967042, 4294967043, 4294967044]),
        (-1, [4294967295, 0, 1, 2]),
        (0, [0, 1, 2, 3]),
        (16777214, [16777214, 1, 2, 3]),
        (2147483646, [254, 255, 256, 4294967041]),
        (2147483647, [255, 256, 4294967041, 4294967042]),
    ],
)
def test_prekey_batch_ids_match_original_java_int_overflow(start, expected):
    # Captured from the original KeyHelper.generatePreKeys(start, 4).
    records = KeyHelper.generate_pre_keys(start, len(expected))
    assert [record.id for record in records] == expected
    assert [PreKeyRecord.from_bytes(record.serialize()).id for record in records] == expected


@pytest.mark.parametrize("cls", [PreKeyRecord, SignedPreKeyRecord, KyberPreKeyRecord])
def test_overlong_record_id_decodes_with_java_profile(cls):
    # Low32 is all ones; trailing groups only consume bytes for Java uint32.
    raw = b"\x08" + b"\xff" * 4 + b"\x8f" + b"\x80" * 7 + b"\x00"
    record = cls.from_bytes(raw, profile=WHATSAPP)
    assert record.id == 0xFFFFFFFF
    assert record.serialize() == b"\x08\xff\xff\xff\xff\x0f"
    assert cls.from_bytes(raw).serialize() == record.serialize()


def test_session_and_nested_state_overlong_varints():
    state = b"\x08\x83" + b"\x80" * 10 + b"\x00"
    assert SessionState(state, profile=WHATSAPP).serialize() == b"\x08\x03"
    raw = b"\x0a" + bytes([len(state)]) + state
    assert SessionRecord(raw, profile=WHATSAPP).serialize() == b"\x0a\x02\x08\x03"
    group = b"\x08\x81" + b"\x80" * 10 + b"\x00"
    raw = b"\x0a" + bytes([len(group)]) + group
    assert SenderKeyRecord(raw, profile=WHATSAPP).serialize() == b"\x0a\x02\x08\x01"


def test_store_ids_accept_both_signed_and_unsigned_spellings():
    store = InMemorySignalProtocolStore()
    pair = Curve.generate_key_pair()
    store.store_pre_key(-1, PreKeyRecord(-1, pair))
    assert store.load_pre_key(0xFFFFFFFF).id == 0xFFFFFFFF
    store.remove_pre_key(-1)
    assert not store.contains_pre_key(0xFFFFFFFF)
    signed = KeyHelper.generate_signed_pre_key(store.identity_key_pair, -1)
    store.store_signed_pre_key(-1, signed)
    assert store.load_signed_pre_key(0xFFFFFFFF).serialize() == signed.serialize()
    store.remove_signed_pre_key(0xFFFFFFFF)
    assert not store.contains_signed_pre_key(-1)
    kem = KeyHelper.generate_kyber_pre_key(store.identity_key_pair, -1)
    store.store_kyber_pre_key(-1, kem)
    assert store.load_kyber_pre_key(0xFFFFFFFF).id == 0xFFFFFFFF
    store.mark_kyber_pre_key_used(-1)
    assert not store.contains_kyber_pre_key(0xFFFFFFFF)


def test_uint32_device_generation_and_fingerprint_version():
    identity = KeyHelper.generate_identity_key_pair()
    commitment = DeviceConsistencyCommitment(-1, [identity.public_key])
    message = DeviceConsistencyMessage(commitment, identity)
    assert (
        DeviceConsistencyMessage.from_bytes(
            commitment, message.serialize(), identity.public_key
        ).generation
        == 0xFFFFFFFF
    )
    a = ScannableFingerprint(-1, b"a" * 32, b"b" * 32)
    b = ScannableFingerprint(0xFFFFFFFF, b"b" * 32, b"a" * 32)
    assert a.compare_to(b.serialize())
