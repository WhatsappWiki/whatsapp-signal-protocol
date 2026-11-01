"""Reentrant callbacks and Store hooks must not lose updates or invert locks."""

import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from signal_protocol import (
    UPSTREAM,
    WHATSAPP,
    InMemorySignalProtocolStore,
    SessionBuilder,
    SessionCipher,
)
from signal_protocol.adapters import WhatsAppGroupCipher, WhatsAppSessionCipher
from signal_protocol.exceptions import (
    DuplicateMessageException,
    NoSessionException,
    ReentrantOperationException,
)
from signal_protocol.groups import (
    GroupCipher,
    GroupSessionBuilder,
    InMemorySenderKeyStore,
    SenderKeyName,
)
from tests.helpers import ALICE, BOB, bundle


def established(profile):
    a, b = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    prekey = bundle(b)
    SessionBuilder(a, BOB, profile=profile).process(prekey)
    sender, receiver = (
        SessionCipher(a, BOB, profile=profile),
        SessionCipher(b, ALICE, profile=profile),
    )
    receiver.decrypt(sender.encrypt(b"establish"))
    sender.decrypt(receiver.encrypt(b"ack"))
    receiver.decrypt(sender.encrypt(b"ratchet ack"))
    return SimpleNamespace(a=a, b=b, sender=sender, receiver=receiver, prekey=prekey)


def group_peers(profile):
    a, b = InMemorySenderKeyStore(), InMemorySenderKeyStore()
    name = SenderKeyName("reentrant", ALICE)
    builder = GroupSessionBuilder(a, profile=profile)
    distribution = builder.create(name)
    GroupSessionBuilder(b, profile=profile).process(name, distribution)
    return SimpleNamespace(
        a=a,
        b=b,
        name=name,
        distribution=distribution,
        sender=GroupCipher(a, name, profile=profile),
        receiver=GroupCipher(b, name, profile=profile),
    )


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
def test_callback_reply_cannot_reuse_sender_key_and_counter(profile):
    peers = established(profile)
    incoming = peers.sender.encrypt(b"incoming")
    before = dict(peers.b.sessions)
    nested = SessionCipher(peers.b, ALICE, profile=profile)
    with pytest.raises(ReentrantOperationException):
        peers.receiver.decrypt(incoming, lambda _: nested.encrypt(b"callback reply"))
    assert peers.b.sessions == before
    assert peers.receiver.decrypt(incoming) == b"incoming"
    first, second = nested.encrypt(b"first"), nested.encrypt(b"second")
    assert first.sender_ratchet_key == second.sender_ratchet_key
    assert second.counter == first.counter + 1
    assert peers.sender.decrypt(first) == b"first"
    assert peers.sender.decrypt(second) == b"second"


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
def test_group_nested_decrypt_cannot_lose_replay_state(profile):
    peers = group_peers(profile)
    first, second = peers.sender.encrypt(b"first"), peers.sender.encrypt(b"second")
    before = dict(peers.b.keys)
    with pytest.raises(ReentrantOperationException):
        peers.receiver.decrypt(first, lambda _: peers.receiver.decrypt(second))
    assert peers.b.keys == before
    assert peers.receiver.decrypt(first) == b"first"
    assert peers.receiver.decrypt(second) == b"second"
    with pytest.raises(DuplicateMessageException):
        peers.receiver.decrypt(second)


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
@pytest.mark.parametrize(
    "outer,operation",
    [
        (outer, operation)
        for outer in ("session", "group")
        for operation in (
            "session_encrypt",
            "session_decrypt",
            "session_setup",
            "prekey_setup",
            "group_encrypt",
            "group_decrypt",
            "group_create",
            "group_process",
        )
        if not (outer == "session" and operation.startswith("group_"))
    ],
)
def test_unsafe_mutating_entries_reject_nesting_before_store_changes(profile, outer, operation):
    session, group = established(profile), group_peers(profile)
    fresh_a, fresh_b = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    fresh_bundle = bundle(fresh_b)
    SessionBuilder(fresh_a, BOB, profile=profile).process(fresh_bundle)
    initial = SessionCipher(fresh_a, BOB, profile=profile).encrypt(b"initial")
    record = fresh_b.load_session(ALICE)
    record_before = record.serialize()
    incoming = session.sender.encrypt(b"incoming")
    group_message = group.sender.encrypt(b"group incoming")
    actions = {
        "session_encrypt": lambda: session.receiver.encrypt(b"nested"),
        "session_decrypt": lambda: session.receiver.decrypt(incoming),
        "session_setup": lambda: SessionBuilder(session.a, BOB, profile=profile).process(
            session.prekey
        ),
        "prekey_setup": lambda: SessionBuilder(fresh_b, ALICE, profile=profile).process_message(
            record, initial
        ),
        "group_encrypt": lambda: group.sender.encrypt(b"nested"),
        "group_decrypt": lambda: group.receiver.decrypt(group_message),
        "group_create": lambda: GroupSessionBuilder(group.a, profile=profile).create(group.name),
        "group_process": lambda: GroupSessionBuilder(group.b, profile=profile).process(
            group.name, group.distribution
        ),
    }

    def snapshot():
        return [dict(s.sessions) for s in (session.a, session.b, fresh_a, fresh_b)] + [
            dict(group.a.keys),
            dict(group.b.keys),
            dict(fresh_b.trusted_keys),
            record.serialize(),
        ]

    before = snapshot()

    def callback(_):
        with pytest.raises(ReentrantOperationException):
            actions[operation]()
        assert snapshot() == before

    cipher, message = (
        (session.receiver, incoming) if outer == "session" else (group.receiver, group_message)
    )
    cipher.decrypt(message, callback)
    assert record.serialize() == record_before


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
def test_session_callback_can_process_group_operations_in_lock_order(profile):
    session, group = established(profile), group_peers(profile)
    contents = []

    def callback(_):
        distribution = GroupSessionBuilder(group.a, profile=profile).create(group.name)
        GroupSessionBuilder(group.b, profile=profile).process(group.name, distribution)
        ciphertext = group.sender.encrypt(b"group inside session callback")

        def accept_group(content):
            # This thread already owns SESSION_LOCK, so reading it under GROUP_LOCK
            # does not reverse acquisition order or discard either active guard.
            assert session.receiver.get_session_version() == 3
            with pytest.raises(ReentrantOperationException):
                session.receiver.encrypt(b"must not overwrite outer session")
            with pytest.raises(ReentrantOperationException):
                group.sender.encrypt(b"must not overwrite outer group")
            contents.append(content)

        group.receiver.decrypt(ciphertext, accept_group)

    assert (
        session.receiver.decrypt(session.sender.encrypt(b"distribution"), callback)
        == b"distribution"
    )
    assert contents == [b"group inside session callback"]
    assert group.receiver.decrypt(group.sender.encrypt(b"after callback")) == b"after callback"


@pytest.mark.parametrize(
    "hook_name", ["load_session", "store_session", "is_trusted_identity", "save_identity"]
)
def test_store_hook_reentry_is_rejected_and_guard_is_released(hook_name, monkeypatch):
    peers = established(UPSTREAM)
    before = dict(peers.b.sessions)
    original = getattr(peers.b, hook_name)
    fired = False

    def hook(*args):
        nonlocal fired
        if not fired:
            fired = True
            peers.receiver.encrypt(b"nested from Store")
        return original(*args)

    monkeypatch.setattr(peers.b, hook_name, hook)
    with pytest.raises(ReentrantOperationException):
        peers.receiver.encrypt(b"outer")
    assert peers.b.sessions == before
    monkeypatch.setattr(peers.b, hook_name, original)
    assert peers.sender.decrypt(peers.receiver.encrypt(b"after failure")) == b"after failure"


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
def test_same_domain_read_only_getters_remain_available_in_callback(profile):
    peers = established(profile)
    observed = []

    def callback(_):
        observed.append(
            (peers.receiver.get_session_version(), peers.receiver.get_remote_registration_id())
        )
        with pytest.raises(ReentrantOperationException):
            peers.receiver.encrypt(b"read must not clear outer guard")

    peers.receiver.decrypt(peers.sender.encrypt(b"read only"), callback)
    assert observed == [(3, peers.a.registration_id)]


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
def test_failed_read_only_getter_preserves_outer_operation_guard(profile):
    peers = established(profile)
    missing = SessionCipher(InMemorySignalProtocolStore(), BOB, profile=profile)

    def callback(_):
        with pytest.raises(NoSessionException):
            missing.get_session_version()
        with pytest.raises(ReentrantOperationException):
            peers.receiver.encrypt(b"read exception must not clear guard")

    assert peers.receiver.decrypt(peers.sender.encrypt(b"incoming"), callback) == b"incoming"
    assert peers.sender.decrypt(peers.receiver.encrypt(b"after callback")) == b"after callback"


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
def test_public_prekey_processing_remains_available_outside_cipher_operation(profile):
    alice, bob = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    prekey = bundle(bob)
    SessionBuilder(alice, BOB, profile=profile).process(prekey)
    initial = SessionCipher(alice, BOB, profile=profile).encrypt(b"initial")
    record = bob.load_session(ALICE)
    builder = SessionBuilder(bob, ALICE, profile=profile)
    assert builder.process_message(record, initial) == prekey.pre_key_id
    assert record.session_state.session_version == 3
    assert not bob.contains_session(ALICE)
    assert bob.contains_pre_key(prekey.pre_key_id)
    assert SessionCipher(bob, ALICE, profile=profile).decrypt(initial) == b"initial"


@pytest.mark.parametrize("group", [False, True])
def test_business_adapter_keeps_content_callback_inside_reentry_guard(group):
    peers = group_peers(WHATSAPP) if group else established(WHATSAPP)
    sender = (
        WhatsAppGroupCipher(peers.a, peers.name) if group else WhatsAppSessionCipher(peers.a, BOB)
    )
    receiver = (
        WhatsAppGroupCipher(peers.b, peers.name) if group else WhatsAppSessionCipher(peers.b, ALICE)
    )
    delivered = []

    def callback(content):
        delivered.append(content)
        with pytest.raises(ReentrantOperationException):
            sender.encrypt(b"nested content")

    assert receiver.decrypt(sender.encrypt(b"content"), callback) == b"content"
    assert delivered == [b"content"]
    assert receiver.decrypt(sender.encrypt(b"next content")) == b"next content"


@pytest.mark.parametrize("opposite", ["write", "read"])
def test_opposite_lock_callbacks_respect_order_without_deadlocking(opposite):
    # Isolate lock inversion in a process so a regression cannot hang pytest.
    script = textwrap.dedent("""
        import sys
        sys.path[:0] = [sys.argv[2], sys.argv[2] + '/src']
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from signal_protocol import UPSTREAM
        from signal_protocol.exceptions import ReentrantOperationException, DuplicateMessageException
        from tests.test_reentrant_operations import established, group_peers
        session, group = established(UPSTREAM), group_peers(UPSTREAM)
        incoming = session.sender.encrypt(b'incoming')
        group_message = group.sender.encrypt(b'group')
        before = dict(session.b.sessions), dict(group.b.keys)
        barrier = Barrier(2, timeout=4)
        nested = []
        def session_callback(_):
            barrier.wait()
            nested.append(group.sender.encrypt(b'cross lock'))
        def group_callback(_):
            barrier.wait()
            if sys.argv[1] == 'read':
                session.receiver.get_session_version()
            else:
                session.receiver.encrypt(b'cross lock')
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(session.receiver.decrypt, incoming, session_callback),
                       pool.submit(group.receiver.decrypt, group_message, group_callback)]
            assert futures[0].result(timeout=5) == b'incoming'
            try:
                futures[1].result(timeout=5)
            except ReentrantOperationException:
                pass
            else:
                raise AssertionError('Reverse lock acquisition unexpectedly succeeded')
        assert session.b.sessions != before[0] and group.b.keys == before[1]
        try:
            session.receiver.decrypt(incoming)
        except DuplicateMessageException:
            pass
        else:
            raise AssertionError('Committed session message was accepted twice')
        assert group.receiver.decrypt(group_message) == b'group'
        assert group.receiver.decrypt(nested[0]) == b'cross lock'
    """)
    result = subprocess.run(
        [sys.executable, "-c", script, opposite, str(Path(__file__).resolve().parents[1])],
        capture_output=True,
        text=True,
        timeout=12,
    )
    assert result.returncode == 0, result.stdout + result.stderr
