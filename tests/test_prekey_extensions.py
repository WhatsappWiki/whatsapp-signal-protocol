"""Composed PreKey policies and cancellation on persistent worker threads."""

import gc
import weakref
from concurrent.futures import ThreadPoolExecutor

import pytest

from signal_protocol.exceptions import ReentrantOperationException
from tests.test_guard_compatibility import FrozenCallbackError, FrozenCancellation, initial_peers


class BuilderProxy:
    def __init__(self, wrapped, policy):
        self.wrapped, self.policy = wrapped, policy

    def __getattr__(self, name):
        return getattr(self.wrapped, name)

    def process_message(self, record, message):
        return self.policy(self.wrapped.process_message, record, message)


@pytest.mark.parametrize("kind", ["upstream", "whatsapp_v3", "whatsapp_v4"])
@pytest.mark.parametrize("layers", [1, 2])
@pytest.mark.parametrize("after_setup", [False, True])
def test_proxy_policy_rejection_is_not_bypassed_and_can_retry(kind, layers, after_setup):
    _, store, sender, receiver, prekey = initial_peers(kind)
    message = sender.encrypt(b"proxy policy")
    error = FrozenCallbackError("composed policy rejected")
    reject = True
    events = []

    def policy(delegate, record, envelope):
        events.append("policy")
        if not reject:
            return delegate(record, envelope)
        if after_setup:
            delegate(record, envelope)
        raise error

    for _ in range(layers):
        receiver.builder = BuilderProxy(receiver.builder, policy)
    delivered = []
    with pytest.raises(FrozenCallbackError) as caught:
        receiver.decrypt(message, delivered.append)
    assert caught.value is error
    assert events and not delivered and not store.sessions
    assert store.contains_pre_key(prekey.pre_key_id)
    if prekey.kyber_pre_key_id is not None:
        assert store.contains_kyber_pre_key(prekey.kyber_pre_key_id)
    reject = False
    events.clear()
    assert receiver.decrypt(message, delivered.append) == b"proxy policy"
    assert len(events) == layers and delivered == [b"proxy policy"]
    assert not store.contains_pre_key(prekey.pre_key_id)


@pytest.mark.parametrize("kind", ["upstream", "whatsapp_v3", "whatsapp_v4"])
@pytest.mark.parametrize("layers", [1, 2])
def test_proxy_delegation_is_consumed_before_store_reentry(kind, layers, monkeypatch):
    _, store, sender, receiver, _ = initial_peers(kind)
    message = sender.encrypt(b"once only")
    base = receiver.builder
    original = base.process_message
    trust = store.is_trusted_identity
    active = []
    events = []

    def policy(delegate, record, envelope):
        active[:] = [(record, envelope)]
        events.append("before")
        with pytest.raises(ReentrantOperationException):
            receiver.encrypt(b"nested write")
        result = delegate(record, envelope)
        with pytest.raises(ReentrantOperationException):
            original(record, envelope)
        events.append("after")
        return result

    def trust_hook(*args):
        with pytest.raises(ReentrantOperationException):
            original(*active[0])
        return trust(*args)

    for _ in range(layers):
        receiver.builder = BuilderProxy(receiver.builder, policy)
    monkeypatch.setattr(store, "is_trusted_identity", trust_hook)
    assert receiver.decrypt(message) == b"once only"
    assert events.count("before") == events.count("after") == layers


@pytest.mark.parametrize("kind", ["upstream", "whatsapp_v3", "whatsapp_v4"])
@pytest.mark.parametrize("error_type", [FrozenCallbackError, FrozenCancellation])
def test_policy_lookup_failure_propagates_and_worker_can_retry(kind, error_type):
    _, store, sender, receiver, prekey = initial_peers(kind)
    message = sender.encrypt(b"policy lookup")
    error = error_type("policy descriptor failed")
    fail = True

    class DescriptorProxy:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def __getattr__(self, name):
            return getattr(self.wrapped, name)

        @property
        def process_message(self):
            if fail:
                raise error
            return self.wrapped.process_message

    receiver.builder = DescriptorProxy(receiver.builder)

    def failed_job():
        with pytest.raises(error_type) as caught:
            receiver.decrypt(message)
        assert caught.value is error
        assert not store.sessions and store.contains_pre_key(prekey.pre_key_id)

    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(failed_job).result(timeout=3)
        fail = False
        assert pool.submit(receiver.decrypt, message).result(timeout=3) == b"policy lookup"


@pytest.mark.parametrize("kind", ["upstream", "whatsapp_v3", "whatsapp_v4"])
@pytest.mark.parametrize("after_setup", [False, True])
@pytest.mark.parametrize(
    "error_type", [KeyboardInterrupt, FrozenCancellation, GeneratorExit, SystemExit]
)
def test_cancelled_policy_releases_worker_state_and_draft(
    kind, after_setup, error_type, monkeypatch
):
    _, store, sender, receiver, prekey = initial_peers(kind)
    message = sender.encrypt(b"worker retry")
    original = receiver.builder.process_message
    drafts = []
    cancelled = False

    def policy(record, envelope):
        nonlocal cancelled
        if cancelled:
            return original(record, envelope)
        cancelled = True
        drafts.append(weakref.ref(record))
        if after_setup:
            original(record, envelope)
        raise error_type("cancelled policy")

    monkeypatch.setattr(receiver.builder, "process_message", policy)

    def cancelled_job():
        with pytest.raises(error_type):
            receiver.decrypt(message)
        assert not store.sessions and store.contains_pre_key(prekey.pre_key_id)

    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(cancelled_job).result(timeout=3)
        # Run collection on the still-live worker; a leaked thread-local permit
        # would keep its detached record alive even after exception cycles clear.
        pool.submit(gc.collect).result(timeout=3)
        assert len(drafts) == 1 and drafts[0]() is None
        assert pool.submit(receiver.decrypt, message).result(timeout=3) == b"worker retry"
        reply = pool.submit(receiver.encrypt, b"after cancellation").result(timeout=3)
        assert sender.decrypt(reply) == b"after cancellation"
    assert not store.contains_pre_key(prekey.pre_key_id)
