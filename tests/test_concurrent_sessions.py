"""Separate cipher instances sharing a store serialize each ratchet update."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from signal_protocol import (
    UPSTREAM,
    WHATSAPP,
    InMemorySignalProtocolStore,
    SessionBuilder,
    SessionCipher,
    SignalMessage,
)
from signal_protocol.exceptions import DuplicateMessageException
from signal_protocol.groups import (
    GroupCipher,
    GroupSessionBuilder,
    InMemorySenderKeyStore,
    SenderKeyName,
)
from signal_protocol.protocol import SenderKeyMessage
from tests.helpers import ALICE, BOB, bundle, initialize_sessions
from tests.test_whatsapp_sessions import peers as hybrid_peers


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
def test_concurrent_session_ciphers_do_not_reuse_counters_or_lose_updates(profile):
    alice_state, bob_state = initialize_sessions()
    alice, bob = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    alice.store_session(BOB, alice_state)
    bob.store_session(ALICE, bob_state)

    def encrypt(index):
        plaintext = f"message-{index}".encode()
        cipher = SessionCipher(alice, BOB, profile=profile)
        return plaintext, cipher.encrypt(plaintext)

    def decrypt(item):
        plaintext, message = item
        cipher = SessionCipher(bob, ALICE, profile=profile)
        parsed = SignalMessage.from_bytes(message.serialize(), profile=profile)
        assert cipher.decrypt(parsed) == plaintext

    with ThreadPoolExecutor(max_workers=8) as pool:
        messages = list(pool.map(encrypt, range(32)))
        list(pool.map(decrypt, messages))
    assert {message.counter for _, message in messages} == set(range(32))
    assert alice.load_session(BOB).session_state.sender_chain_key.index == 32
    state = bob.load_session(ALICE).session_state
    public = messages[0][1].sender_ratchet_key
    assert state.get_receiver_chain_key(public).index == 32
    assert not any(state.has_message_keys(public, index) for index in range(32))


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
def test_concurrent_group_ciphers_do_not_reuse_counters_or_lose_updates(profile):
    name = SenderKeyName("group", ALICE)
    alice, bob = InMemorySenderKeyStore(), InMemorySenderKeyStore()
    distribution = GroupSessionBuilder(alice, profile=profile).create(name)
    GroupSessionBuilder(bob, profile=profile).process(name, distribution)

    def encrypt(index):
        plaintext = f"group-{index}".encode()
        return plaintext, GroupCipher(alice, name, profile=profile).encrypt(plaintext)

    def decrypt(item):
        plaintext, message = item
        assert GroupCipher(bob, name, profile=profile).decrypt(message) == plaintext

    with ThreadPoolExecutor(max_workers=8) as pool:
        messages = list(pool.map(encrypt, range(32)))
        list(pool.map(decrypt, messages))
    assert {SenderKeyMessage.from_bytes(message).iteration for _, message in messages} == set(
        range(32)
    )
    assert alice.load_sender_key(name).get_sender_key_state().sender_chain_key.iteration == 32
    state = bob.load_sender_key(name).get_sender_key_state()
    assert state.sender_chain_key.iteration == 32
    assert not any(state.has_sender_message_key(index) for index in range(32))


@pytest.mark.parametrize("profile,hybrid", [(UPSTREAM, False), (WHATSAPP, False), (WHATSAPP, True)])
def test_concurrent_prekey_delivery_commits_and_consumes_once(profile, hybrid):
    if hybrid:
        p = hybrid_peers()
        sender, store, address, prekey_id = p.ac, p.b, p.bc.remote_address, 37
    else:
        alice, store = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
        prekey = bundle(store)
        SessionBuilder(alice, BOB, profile=profile).process(prekey)
        sender = SessionCipher(alice, BOB, profile=profile)
        address, prekey_id = ALICE, prekey.pre_key_id
    message = sender.encrypt(b"one initial delivery")
    barrier = Barrier(8, timeout=5)
    delivered = []

    def decrypt(_):
        receiver = SessionCipher(store, address, profile=profile)
        barrier.wait()
        try:
            return receiver.decrypt(message, delivered.append)
        except DuplicateMessageException:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(decrypt, range(8)))
    assert results.count(b"one initial delivery") == 1 and results.count(None) == 7
    assert delivered == [b"one initial delivery"]
    assert not store.contains_pre_key(prekey_id)
    if hybrid:
        assert not store.contains_kyber_pre_key(71)
