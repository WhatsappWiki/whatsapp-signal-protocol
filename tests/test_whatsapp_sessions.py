"""WhatsApp hybrid-session behavior and failure/lifecycle transactions.

Uses independent synthetic peers. Native APK interoperability is tested by the
separate capture runner; these cases cover offline state/failure combinations.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from signal_protocol import (
    Curve,
    ECPublicKey,
    IdentityKey,
    InMemorySignalProtocolStore,
    KeyHelper,
    PreKeyBundle,
    PreKeyRecord,
    PreKeySignalMessage,
    SessionBuilder,
    SessionCipher,
    SignalMessage,
    SignalProtocolAddress,
)
from signal_protocol.adapters import (
    WhatsAppGroupCipher,
    WhatsAppSessionBuilder,
    WhatsAppSessionCipher,
)
from signal_protocol.exceptions import (
    DuplicateMessageException,
    InvalidKeyException,
    InvalidMessageException,
)
from signal_protocol.groups import (
    GroupCipher,
    GroupSessionBuilder,
    InMemorySenderKeyStore,
    SenderKeyName,
)
from signal_protocol.profiles import WHATSAPP

from .helpers import initialize_sessions

ALICE = SignalProtocolAddress("synthetic-alice", 1)
BOB = SignalProtocolAddress("synthetic-bob", 1)


def make_bundle(store, *, version=4, one_time=True, curve_id=37, kem_id=71, last_resort=False):
    signed = KeyHelper.generate_signed_pre_key(store.identity_key_pair, 11)
    store.store_signed_pre_key(signed.id, signed)
    pre = PreKeyRecord(curve_id, Curve.generate_key_pair())
    store.store_pre_key(curve_id, pre)
    kem = (
        KeyHelper.generate_kyber_pre_key(
            store.identity_key_pair,
            kem_id,
            last_resort=last_resort,
            seed=bytes(range(64)),
        )
        if version == 4
        else None
    )
    if kem is not None:
        store.store_kyber_pre_key(kem.id, kem)
    return PreKeyBundle(
        store.registration_id,
        BOB.device_id,
        pre.id,
        pre.key_pair.public_key if one_time else None,
        signed.id,
        signed.key_pair.public_key,
        signed.signature,
        store.identity_key_pair.public_key,
        kem.id if kem is not None else None,
        kem.key_pair.public_key if kem is not None else None,
        kem.signature if kem is not None else None,
    )


def peers(*, version=4, one_time=True, curve_id=37, last_resort=False, adapters=False):
    a, b = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    bundle = make_bundle(
        b, version=version, one_time=one_time, curve_id=curve_id, last_resort=last_resort
    )
    if adapters:
        WhatsAppSessionBuilder(a, BOB).process(bundle)
        ac, bc = WhatsAppSessionCipher(a, BOB), WhatsAppSessionCipher(b, ALICE)
    else:
        SessionBuilder(a, BOB, profile=WHATSAPP).process(bundle)
        ac, bc = SessionCipher(a, BOB, profile=WHATSAPP), SessionCipher(b, ALICE, profile=WHATSAPP)
    return SimpleNamespace(a=a, b=b, ac=ac, bc=bc, bundle=bundle)


def parse(message):
    cls = PreKeySignalMessage if message.type == 3 else SignalMessage
    return cls.from_bytes(message.serialize(), profile=WHATSAPP)


def clone_prekey(message, *, inner=None, capsule=None, base_key=None):
    return PreKeySignalMessage(
        message.message_version,
        message.registration_id,
        message.pre_key_id,
        message.signed_pre_key_id,
        message.base_key if base_key is None else base_key,
        message.identity_key,
        message.message if inner is None else inner,
        kyber_pre_key_id=message.kyber_pre_key_id,
        kyber_ciphertext=message.kyber_ciphertext if capsule is None else capsule,
        profile=WHATSAPP,
    )


@pytest.mark.parametrize("version", (3, 4))
@pytest.mark.parametrize("one_time", (False, True))
def test_whatsapp_prekey_handshake_and_replies(version, one_time):
    p = peers(version=version, one_time=one_time)
    initial = parse(p.ac.encrypt(b"initial hybrid handshake"))
    assert initial.message_version == version
    assert initial.serialize()[0] == (0x44 if version == 4 else 0x33)
    assert (initial.kyber_pre_key_id is not None) == (version == 4)
    assert p.bc.decrypt(initial) == b"initial hybrid handshake"
    assert p.b.contains_pre_key(37) == (not one_time)
    if version == 4:
        assert not p.b.contains_kyber_pre_key(71)
    reply = parse(p.bc.encrypt(b"receiver reply"))
    assert reply.type == 2
    assert p.ac.decrypt(reply) == b"receiver reply"
    state = p.a.load_session(BOB).session_state
    assert not state.has_unacknowledged_pre_key_message()
    assert state.pending_kyber_pre_key is None
    assert p.ac.get_session_version() == p.bc.get_session_version() == version


@pytest.mark.parametrize("last_resort", (False, True))
def test_kem_record_consumption_and_pending_repeated_prekey(last_resort):
    p = peers(last_resort=last_resort)
    first, second = parse(p.ac.encrypt(b"first")), parse(p.ac.encrypt(b"second before reply"))
    assert first.base_key == second.base_key
    assert p.bc.decrypt(first) == b"first"
    assert p.b.contains_kyber_pre_key(71) == last_resort
    # The matching session must suffice after one-time keys have disappeared.
    assert not p.b.contains_pre_key(37)
    assert p.bc.decrypt(second) == b"second before reply"
    assert p.b.contains_kyber_pre_key(71) == last_resort
    committed = dict(p.b.sessions)
    with pytest.raises(DuplicateMessageException):
        p.bc.decrypt(first)
    assert p.b.sessions == committed


def test_last_resort_kem_can_be_used_by_an_independent_new_session():
    p = peers(last_resort=True, one_time=False)
    first = parse(p.ac.encrypt(b"first sender"))
    assert p.bc.decrypt(first) == b"first sender"
    preserved = p.b.load_kyber_pre_key(71).serialize()
    other = InMemorySignalProtocolStore()
    other_address = SignalProtocolAddress("independent-sender", 1)
    SessionBuilder(other, BOB, profile=WHATSAPP).process(p.bundle)
    message = parse(SessionCipher(other, BOB, profile=WHATSAPP).encrypt(b"second sender"))
    assert message.base_key != first.base_key
    assert SessionCipher(p.b, other_address, profile=WHATSAPP).decrypt(message) == b"second sender"
    assert p.b.load_kyber_pre_key(71).serialize() == preserved


@pytest.mark.parametrize("version", (3, 4))
def test_curve_last_resort_prekey_is_retained(version):
    p = peers(version=version, curve_id=0xFFFFFF)
    assert p.bc.decrypt(parse(p.ac.encrypt(b"reserved prekey"))) == b"reserved prekey"
    assert p.b.contains_pre_key(0xFFFFFF)


@pytest.mark.parametrize("version", (3, 4))
@pytest.mark.parametrize("failure", ("callback", "store"))
def test_prekey_callback_and_store_failure_do_not_commit_or_consume(version, failure, monkeypatch):
    p = peers(version=version)
    message = parse(p.ac.encrypt(b"atomic handshake"))
    before, curve = dict(p.b.sessions), dict(p.b.pre_keys)
    kem = dict(p.b.kyber_pre_keys)

    def abort(*arguments):
        assert p.b.sessions == before
        assert p.b.pre_keys == curve and p.b.kyber_pre_keys == kem
        raise RuntimeError("synthetic transaction failure")

    if failure == "store":
        original = p.b.store_session
        monkeypatch.setattr(p.b, "store_session", abort)
        callback = None
    else:
        callback = abort
    with pytest.raises(RuntimeError, match="transaction failure"):
        p.bc.decrypt(message, callback)
    assert p.b.sessions == before
    assert p.b.pre_keys == curve and p.b.kyber_pre_keys == kem
    if failure == "store":
        monkeypatch.setattr(p.b, "store_session", original)
    assert p.bc.decrypt(message) == b"atomic handshake"


def test_full_size_corrupted_capsule_uses_implicit_rejection_and_mac_rollback():
    p = peers()
    message = parse(p.ac.encrypt(b"authenticated hybrid message"))
    modified = bytearray(message.kyber_ciphertext)
    modified[25] ^= 0x40
    wrong = bytes(modified)
    secret = p.b.load_kyber_pre_key(71).key_pair.secret_key.decapsulate(wrong)
    assert len(secret) == 32
    before = dict(p.b.sessions)
    with pytest.raises(InvalidMessageException):
        p.bc.decrypt(clone_prekey(message, capsule=wrong))
    assert p.b.sessions == before
    assert p.b.contains_pre_key(37) and p.b.contains_kyber_pre_key(71)
    assert p.bc.decrypt(message) == b"authenticated hybrid message"


@pytest.mark.parametrize("capsule", (b"", bytes(1567), bytes(1569)))
def test_wrong_length_capsule_fails_without_consuming_keys(capsule):
    p = peers()
    message = parse(p.ac.encrypt(b"capsule length"))
    with pytest.raises(InvalidKeyException):
        p.bc.decrypt(clone_prekey(message, capsule=capsule))
    assert not p.b.contains_session(ALICE)
    assert p.b.contains_pre_key(37) and p.b.contains_kyber_pre_key(71)
    assert p.bc.decrypt(message) == b"capsule length"


@pytest.mark.parametrize(
    "fault", ("signature", "missing-id", "missing-public", "missing-signature")
)
def test_invalid_signed_kem_bundle_is_rejected_without_downgrade(fault):
    a, b = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    bundle = make_bundle(b)
    changes = {
        "signature": {"kyber_pre_key_signature": bytes(64)},
        "missing-id": {"kyber_pre_key_id": None},
        "missing-public": {"kyber_pre_key": None},
        "missing-signature": {"kyber_pre_key_signature": None},
    }[fault]
    with pytest.raises(InvalidKeyException):
        SessionBuilder(a, BOB, profile=WHATSAPP).process(replace(bundle, **changes))
    assert not a.contains_session(BOB)
    assert b.contains_pre_key(37) and b.contains_kyber_pre_key(71)


def create_two_pending_sessions():
    p = peers()
    old_first, old_late = parse(p.ac.encrypt(b"old first")), parse(p.ac.encrypt(b"old delayed"))
    assert p.bc.decrypt(old_first) == b"old first"
    second = make_bundle(p.b, curve_id=38, kem_id=72)
    SessionBuilder(p.a, BOB, profile=WHATSAPP).process(second)
    archived = p.a.load_session(BOB).previous_states[0]
    assert not archived.has_unacknowledged_pre_key_message()
    new_first = parse(p.ac.encrypt(b"new first"))
    assert p.bc.decrypt(new_first) == b"new first"
    return p, old_late, new_first


def test_delayed_prekey_promotes_exact_matching_archived_session_without_key_reload():
    p, old_late, new_first = create_two_pending_sessions()
    assert p.b.load_session(ALICE).session_state.alice_base_key == new_first.base_key.serialize()
    assert not p.b.contains_kyber_pre_key(71)
    assert p.bc.decrypt(old_late) == b"old delayed"
    record = p.b.load_session(ALICE)
    assert record.session_state.alice_base_key == old_late.base_key.serialize()
    assert record.previous_states[0].alice_base_key == new_first.base_key.serialize()


def test_prekey_never_falls_back_to_a_different_archived_session():
    p, old_late, new_first = create_two_pending_sessions()
    # Outer envelope selects current/new; the inner ciphertext belongs to old.
    mismatched = clone_prekey(new_first, inner=old_late.message)
    committed = dict(p.b.sessions)
    with pytest.raises(InvalidMessageException):
        p.bc.decrypt(mismatched)
    assert p.b.sessions == committed
    # The same inner ciphertext is valid for its archived session. Ordinary
    # Signal message decryption is allowed to find/promote that session.
    assert p.bc.decrypt(old_late.message) == b"old delayed"


@pytest.mark.parametrize("version", (3, 4))
def test_business_adapter_callback_gets_content_before_prekeys_are_consumed(version):
    p = peers(version=version, adapters=True)
    message = p.ac.encrypt(b"business content", padding_length=13)
    calls = []

    def receive(content):
        assert content == b"business content"
        assert not p.b.contains_session(ALICE)
        assert p.b.contains_pre_key(37)
        if version == 4:
            assert p.b.contains_kyber_pre_key(71)
        calls.append(content)

    assert p.bc.decrypt(message.serialize(), receive, message_type=3) == b"business content"
    assert calls == [b"business content"]


def test_business_unpadding_and_callback_failure_roll_back_prekey_state():
    p = peers(adapters=True)
    raw_sender = SessionCipher(p.a, BOB, profile=WHATSAPP)
    invalid = parse(raw_sender.encrypt(b"invalid business padding\x00"))
    before = dict(p.b.sessions)
    with pytest.raises(InvalidMessageException):
        p.bc.decrypt(invalid)
    assert p.b.sessions == before
    assert p.b.contains_pre_key(37) and p.b.contains_kyber_pre_key(71)
    good = p.ac.encrypt(b"application content", padding_length=4)

    def reject(content):
        assert content == b"application content"
        raise RuntimeError("content rejected")

    with pytest.raises(RuntimeError, match="content rejected"):
        p.bc.decrypt(good, reject)
    assert p.b.sessions == before
    assert p.b.contains_pre_key(37) and p.b.contains_kyber_pre_key(71)
    assert p.bc.decrypt(good) == b"application content"


@pytest.mark.parametrize("failure", ("callback", "store"))
def test_established_v4_failure_does_not_advance_persisted_ratchet(failure, monkeypatch):
    p = peers()
    assert p.bc.decrypt(parse(p.ac.encrypt(b"establish"))) == b"establish"
    assert p.ac.decrypt(parse(p.bc.encrypt(b"acknowledge"))) == b"acknowledge"
    message = parse(p.ac.encrypt(b"ratcheted regular message"))
    assert message.type == 2
    before = p.b.load_session(ALICE).serialize()

    def abort(*arguments):
        assert p.b.load_session(ALICE).serialize() == before
        raise RuntimeError("regular-message transaction failed")

    original = p.b.store_session
    if failure == "store":
        monkeypatch.setattr(p.b, "store_session", abort)
    with pytest.raises(RuntimeError, match="regular-message transaction failed"):
        p.bc.decrypt(message, abort if failure == "callback" else None)
    assert p.b.load_session(ALICE).serialize() == before
    monkeypatch.setattr(p.b, "store_session", original)
    assert p.bc.decrypt(message) == b"ratcheted regular message"


def test_strict_identity_configuration_controls_existing_session_encryption():
    ar, br = initialize_sessions()
    # The root/chain keys remain valid while the MAC receiver identity is made
    # unusual. This isolates strict identity policy from handshake signatures.
    unusual = IdentityKey(ECPublicKey(bytes(32)))
    ar.session_state.remote_identity_key = unusual
    br.session_state.local_identity_key = unusual
    a, b = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    a.store_session(BOB, ar)
    b.store_session(ALICE, br)
    before = a.load_session(BOB).serialize()
    with pytest.raises(InvalidKeyException):
        SessionCipher(a, BOB, profile=WHATSAPP).encrypt(b"policy check")
    assert a.load_session(BOB).serialize() == before
    message = SessionCipher(a, BOB, profile=WHATSAPP, strict_identity=False).encrypt(
        b"policy check"
    )
    assert SessionCipher(b, ALICE, profile=WHATSAPP).decrypt(parse(message)) == b"policy check"


def test_group_adapter_unpads_callback_and_rolls_back_failure():
    name = SenderKeyName("synthetic-group", ALICE)
    a, b = InMemorySenderKeyStore(), InMemorySenderKeyStore()
    distribution = GroupSessionBuilder(a).create(name)
    GroupSessionBuilder(b).process(name, distribution)
    sender, receiver = WhatsAppGroupCipher(a, name), WhatsAppGroupCipher(b, name)
    invalid = GroupCipher(a, name).encrypt(b"invalid business padding\x00")
    before = dict(b.keys)
    with pytest.raises(InvalidMessageException):
        receiver.decrypt(invalid)
    assert b.keys == before
    message = sender.encrypt(b"group content", padding_length=16)
    calls = []

    def receive(content):
        assert b.keys == before
        calls.append(content)

    assert receiver.decrypt(message, receive) == b"group content"
    assert calls == [b"group content"]
