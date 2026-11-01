"""Operation guards preserve application policies and exception identities."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from threading import Event

import pytest

from signal_protocol import UPSTREAM, WHATSAPP, SessionBuilder
from signal_protocol.exceptions import ReentrantOperationException
from signal_protocol.groups import GroupSessionBuilder
from tests.helpers import setup_prekey
from tests.test_reentrant_operations import established, group_peers
from tests.test_whatsapp_sessions import peers as whatsapp_peers


@dataclass(frozen=True)
class FrozenCallbackError(Exception):
    reason: str


@dataclass(frozen=True)
class FrozenRuntimeError(RuntimeError):
    reason: str


@dataclass(frozen=True)
class FrozenStopIteration(StopIteration):
    reason: str


@dataclass(frozen=True)
class FrozenCancellation(BaseException):
    reason: str


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
@pytest.mark.parametrize("group", [False, True])
@pytest.mark.parametrize(
    "error_type", [FrozenCallbackError, FrozenRuntimeError, FrozenStopIteration, FrozenCancellation]
)
def test_callback_exception_is_propagated_unchanged(profile, group, error_type):
    peers = group_peers(profile) if group else established(profile)
    message = peers.sender.encrypt(b"retry after original error")
    persisted = peers.b.keys if group else peers.b.sessions
    before = dict(persisted)
    error = error_type("application aborted")

    def abort(_):
        raise error

    with pytest.raises(error_type) as caught:
        peers.receiver.decrypt(message, abort)
    assert caught.value is error
    assert persisted == before
    assert peers.receiver.decrypt(message) == b"retry after original error"


@pytest.mark.parametrize("operation", ["encrypt", "read", "setup", "group_create"])
def test_store_exception_is_propagated_unchanged_and_releases_guard(operation, monkeypatch):
    session, group = established(UPSTREAM), group_peers(UPSTREAM)
    error = FrozenCallbackError("store unavailable")

    def abort(*_):
        raise error

    if operation == "group_create":
        owner, hook = group.a, "load_sender_key"

        def invoke():
            return group.sender.encrypt(b"retry")

        def invoke_setup():
            return GroupSessionBuilder(group.a).create(group.name)
    else:
        owner = session.b
        hook = "load_session" if operation != "setup" else "is_trusted_identity"

        def invoke():
            return session.receiver.encrypt(b"retry")

        invoke_setup = {
            "encrypt": invoke,
            "read": session.receiver.get_session_version,
            "setup": lambda: SessionBuilder(session.b, session.receiver.remote_address).process(
                session.prekey
            ),
        }[operation]
    with monkeypatch.context() as patch:
        patch.setattr(owner, hook, abort)
        with pytest.raises(FrozenCallbackError) as caught:
            invoke_setup()
        assert caught.value is error
    invoke()


def initial_peers(kind):
    if kind == "upstream":
        a, b, sender, receiver, prekey = setup_prekey()
        return a, b, sender, receiver, prekey
    p = whatsapp_peers(version=3 if kind == "whatsapp_v3" else 4)
    return p.a, p.b, p.ac, p.bc, p.bundle


@pytest.mark.parametrize("kind", ["upstream", "whatsapp_v3", "whatsapp_v4"])
@pytest.mark.parametrize("after_setup", [False, True])
def test_prekey_policy_override_can_reject_without_committing(kind, after_setup):
    _, store, sender, receiver, prekey = initial_peers(kind)
    initial = sender.encrypt(b"application policy")
    original = receiver.builder
    error = FrozenCallbackError("policy rejected")
    visited = []

    class PolicyBuilder(SessionBuilder):
        def process_message(self, record, message):
            visited.append(message)
            if after_setup:
                super().process_message(record, message)
            raise error

    receiver.builder = PolicyBuilder(store, receiver.remote_address, profile=receiver.profile)
    delivered = []
    with pytest.raises(FrozenCallbackError) as caught:
        receiver.decrypt(initial, delivered.append)
    assert caught.value is error
    assert visited == [initial] and delivered == [] and not store.sessions
    assert store.contains_pre_key(prekey.pre_key_id)
    if prekey.kyber_pre_key_id is not None:
        assert store.contains_kyber_pre_key(prekey.kyber_pre_key_id)
    receiver.builder = original
    assert receiver.decrypt(initial) == b"application policy"


@pytest.mark.parametrize("kind", ["upstream", "whatsapp_v3", "whatsapp_v4"])
def test_prekey_wrapper_delegates_once_without_authorizing_store_reentry(kind, monkeypatch):
    _, store, sender, receiver, _ = initial_peers(kind)
    initial = sender.encrypt(b"wrapped prekey")
    original = receiver.builder.process_message
    trust = store.is_trusted_identity
    active = []
    events = []

    def trust_hook(*args):
        # The continuation must have been consumed before any external Store call.
        with pytest.raises(ReentrantOperationException):
            original(*active[0])
        return trust(*args)

    def wrapper(record, message):
        active.append((record, message))
        events.append("before")
        with pytest.raises(ReentrantOperationException):
            receiver.encrypt(b"unsafe policy write")
        # The permit applies to this builder, record and envelope only.
        for builder, draft, envelope in (
            (receiver.builder, type(record)(record.serialize()), message),
            (
                receiver.builder,
                record,
                type(message).from_bytes(message.serialize(), profile=receiver.profile),
            ),
            (
                SessionBuilder(store, receiver.remote_address, profile=receiver.profile),
                record,
                message,
            ),
        ):
            with pytest.raises(ReentrantOperationException):
                process = original if builder is receiver.builder else builder.process_message
                process(draft, envelope)
        result = original(record, message)
        events.append("after")
        with pytest.raises(ReentrantOperationException):
            original(record, message)
        return result

    monkeypatch.setattr(store, "is_trusted_identity", trust_hook)
    monkeypatch.setattr(receiver.builder, "process_message", wrapper)
    assert receiver.decrypt(initial) == b"wrapped prekey"
    assert events == ["before", "after"]
    assert receiver.decrypt(sender.encrypt(b"next")) == b"next"


def test_prekey_continuation_is_not_shared_with_another_thread(monkeypatch):
    _, store, sender, receiver, prekey = initial_peers("upstream")
    initial = sender.encrypt(b"thread-local delegation")
    original = receiver.builder.process_message
    entered = Event()
    pending = []

    def concurrent_setup(record, message):
        entered.set()
        return original(record, message)

    with ThreadPoolExecutor(max_workers=1) as pool:

        def wrapper(record, message):
            pending.append(pool.submit(concurrent_setup, record, message))
            assert entered.wait(timeout=2)
            with pytest.raises(TimeoutError):
                pending[0].result(timeout=0.05)
            return original(record, message)

        monkeypatch.setattr(receiver.builder, "process_message", wrapper)
        assert receiver.decrypt(initial) == b"thread-local delegation"
        assert pending[0].result(timeout=2) is None
    assert not store.contains_pre_key(prekey.pre_key_id)
