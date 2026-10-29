"""APK-derived state-transition and Java int32 boundary regressions."""

import hashlib
import hmac

import pytest

from signal_protocol import (
    UPSTREAM,
    WHATSAPP,
    Curve,
    InMemorySignalProtocolStore,
    SessionCipher,
    SessionRecord,
    SessionState,
    SignalMessage,
    SignalProtocolAddress,
)
from signal_protocol.exceptions import DuplicateMessageException, InvalidMessageException
from signal_protocol.groups import (
    GroupCipher,
    GroupSessionBuilder,
    InMemorySenderKeyStore,
    SenderChainKey,
    SenderKeyName,
    SenderKeyRecord,
)
from signal_protocol.integers import int32, uint32
from signal_protocol.kdf import HKDF
from signal_protocol.protobuf import LocalStorageProtocol_pb2 as pb
from signal_protocol.protocol import SenderKeyDistributionMessage, SenderKeyMessage
from signal_protocol.ratchet import ChainKey
from tests.helpers import ALICE, BOB, initialize_sessions

ADDRESS = SignalProtocolAddress("boundary-peer", 1)
GROUP = SenderKeyName("boundary-group", ADDRESS)


@pytest.mark.parametrize(
    "value,unsigned,signed",
    [
        (-1, 0xFFFFFFFF, -1),
        (0x80000000, 0x80000000, -0x80000000),
        (0xFFFFFFFF, 0xFFFFFFFF, -1),
        (0x100000005, 5, 5),
    ],
)
def test_public_uint32_and_java_signed_view(value, unsigned, signed):
    assert uint32(value) == unsigned
    assert int32(value) == signed


@pytest.mark.parametrize("index,next_index", [(0x7FFFFFFF, 0x80000000), (0xFFFFFFFF, 0)])
@pytest.mark.parametrize("group", [False, True])
def test_chain_overflow_keeps_key_derivation_and_low32(index, next_index, group):
    seed = bytes(range(32))
    key = SenderChainKey(index, seed) if group else ChainKey(HKDF(3), seed, index)
    next_key = key.next() if group else key.next_chain_key()
    assert (next_key.iteration if group else next_key.index) == next_index
    assert (next_key.seed if group else next_key.key) == hmac.new(
        seed, b"\x02", hashlib.sha256
    ).digest()


def sender_store(iteration):
    record = SenderKeyRecord()
    pair = Curve.generate_key_pair()
    record.set_sender_key_state(7, iteration, bytes(range(32)), pair)
    store = InMemorySenderKeyStore()
    store.store_sender_key(GROUP, record)
    return store, pair


def test_senderkey_encrypt_at_uint32_max_wraps_saved_state():
    store, _ = sender_store(0xFFFFFFFF)
    encoded = GroupCipher(store, GROUP, profile=WHATSAPP).encrypt(b"last uint32 counter")
    message = SenderKeyMessage.from_bytes(encoded)
    assert message.iteration == 0xFFFFFFFF
    assert store.load_sender_key(GROUP).get_sender_key_state().sender_chain_key.iteration == 0


def test_senderkey_wrap_can_skip_then_consume_cached_negative_counter():
    sender, _ = sender_store(0xFFFFFFFF)
    receiver = InMemorySenderKeyStore()
    receiver.store_sender_key(GROUP, sender.load_sender_key(GROUP))
    cipher = GroupCipher(sender, GROUP, profile=WHATSAPP)
    before_wrap, after_wrap = cipher.encrypt(b"counter -1"), cipher.encrypt(b"counter 0")
    receiver_cipher = GroupCipher(receiver, GROUP, profile=WHATSAPP)
    assert receiver_cipher.decrypt(after_wrap) == b"counter 0"
    assert receiver_cipher.decrypt(before_wrap) == b"counter -1"
    state = receiver.load_sender_key(GROUP).get_sender_key_state()
    assert state.sender_chain_key.iteration == 1
    with pytest.raises(DuplicateMessageException):
        receiver_cipher.decrypt(before_wrap)


def test_negative_senderkey_counter_is_old_without_cache():
    store, pair = sender_store(0)
    encoded = SenderKeyMessage(7, 0xFFFFFFFF, b"not reached", pair.private_key).serialize()
    before = store.load_sender_key(GROUP).serialize()
    with pytest.raises(DuplicateMessageException):
        GroupCipher(store, GROUP, profile=WHATSAPP).decrypt(encoded)
    assert store.load_sender_key(GROUP).serialize() == before


def test_signed_difference_overflow_does_not_bypass_real_group_work_limit(monkeypatch):
    store, pair = sender_store(0x80000000)
    encoded = SenderKeyMessage(7, 0, b"not reached", pair.private_key).serialize()

    def unexpected_work(self):
        raise AssertionError("overflow gap must be rejected before deriving skipped keys")

    monkeypatch.setattr(SenderChainKey, "sender_message_key", unexpected_work)
    with pytest.raises(InvalidMessageException):
        GroupCipher(store, GROUP, profile=WHATSAPP).decrypt(encoded)


def test_signed_difference_overflow_does_not_bypass_real_session_work_limit(monkeypatch):
    state = SessionState()
    public = Curve.generate_key_pair().public_key
    chain = ChainKey(HKDF(3), bytes(32), 0x80000000)
    state.add_receiver_chain(public, chain)

    def unexpected_work(self):
        raise AssertionError("overflow gap must be rejected before deriving skipped keys")

    monkeypatch.setattr(ChainKey, "message_keys", unexpected_work)
    cipher = SessionCipher(InMemorySignalProtocolStore(), ADDRESS, profile=WHATSAPP)
    with pytest.raises(InvalidMessageException):
        cipher._get_or_create_message_keys(state, public, chain, 0)


def test_negative_session_counter_is_old_without_cache():
    state = SessionState()
    public = Curve.generate_key_pair().public_key
    chain = ChainKey(HKDF(3), bytes(32), 0)
    state.add_receiver_chain(public, chain)
    cipher = SessionCipher(InMemorySignalProtocolStore(), ADDRESS, profile=WHATSAPP)
    with pytest.raises(DuplicateMessageException):
        cipher._get_or_create_message_keys(state, public, chain, 0xFFFFFFFF)


@pytest.mark.parametrize("profile,remaining", [(WHATSAPP, 41), (UPSTREAM, 41)])
def test_imported_over_limit_archive_removes_one_in_whatsapp_mode(profile, remaining):
    structure = pb.RecordStructure()
    structure.currentSession.SetInParent()
    for index in range(41):
        structure.previousSessions.add(aliceBaseKey=bytes([index]))
    record = SessionRecord(structure.SerializeToString(), profile=profile)
    record.archive_current_state()
    assert len(record.previous_states) == remaining
    assert record.previous_states[0].alice_base_key == b""
    assert record.previous_states[-1].alice_base_key == bytes([remaining - 2])


@pytest.mark.parametrize("profile,remaining", [(WHATSAPP, 6), (UPSTREAM, 6)])
def test_imported_over_limit_sender_states_remove_one_in_whatsapp_mode(profile, remaining):
    structure = pb.SenderKeyRecordStructure()
    for index in range(6):
        structure.senderKeyStates.add(senderKeyId=index)
    store = InMemorySenderKeyStore()
    store.store_sender_key(GROUP, SenderKeyRecord(structure.SerializeToString()))
    pair = Curve.generate_key_pair()
    incoming = SenderKeyDistributionMessage(99, 0, bytes(32), pair.public_key)
    GroupSessionBuilder(store, profile=profile).process(GROUP, incoming)
    record = store.load_sender_key(GROUP)
    assert [state.key_id for state in record.states] == [99] + list(range(remaining - 1))


class TracingStore(InMemorySignalProtocolStore):
    def __init__(self):
        super().__init__()
        self.events = []

    def is_trusted_identity(self, address, identity, direction):
        self.events.append("trust_identity")
        return True

    def save_identity(self, address, identity):
        self.events.append("save_identity")
        return super().save_identity(address, identity)

    def store_session(self, address, record):
        self.events.append("store_session")
        super().store_session(address, record)


@pytest.mark.parametrize("profile", [WHATSAPP, UPSTREAM])
def test_existing_session_identity_callback_order_matches_selected_profile(profile):
    alice_record, bob_record = initialize_sessions()
    alice, bob = TracingStore(), TracingStore()
    alice.store_session(BOB, alice_record)
    bob.store_session(ALICE, bob_record)
    alice.events.clear()
    bob.events.clear()
    message = SessionCipher(alice, BOB, profile=profile).encrypt(b"existing session")
    expected = (
        ["store_session"]
        if profile.whatsapp
        else ["trust_identity", "save_identity", "store_session"]
    )
    assert alice.events == expected
    plaintext = SessionCipher(bob, ALICE, profile=profile).decrypt(
        SignalMessage.from_bytes(message.serialize(), profile=profile),
        lambda value: bob.events.append("plaintext_callback"),
    )
    assert plaintext == b"existing session"
    expected = (
        ["plaintext_callback", "store_session"]
        if profile.whatsapp
        else ["trust_identity", "save_identity", "plaintext_callback", "store_session"]
    )
    assert bob.events == expected


def test_session_encrypt_at_uint32_max_wraps_saved_state():
    alice, _ = initialize_sessions()
    state = alice.session_state
    state.sender_chain_key = ChainKey(HKDF(3), bytes(range(32)), 0xFFFFFFFF)
    store = InMemorySignalProtocolStore()
    store.store_session(ADDRESS, alice)
    encoded = SessionCipher(store, ADDRESS, profile=WHATSAPP).encrypt(b"last counter")
    assert encoded.counter == 0xFFFFFFFF
    assert store.load_session(ADDRESS).session_state.sender_chain_key.index == 0
