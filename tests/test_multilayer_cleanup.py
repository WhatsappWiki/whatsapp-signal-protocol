"""Distinct proxy layers preserve error chains and clear worker permissions."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from signal_protocol.exceptions import (
    DuplicateMessageException,
    NoSessionException,
    ReentrantOperationException,
)
from tests.test_guard_compatibility import FrozenCallbackError, FrozenCancellation, initial_peers
from tests.test_prekey_extensions import BuilderProxy
from tests.test_reentrant_operations import group_peers


@pytest.mark.parametrize("kind", ["upstream", "whatsapp_v3", "whatsapp_v4"])
@pytest.mark.parametrize("failing_layer", [0, 1, 2])
@pytest.mark.parametrize("after_delegate", [False, True])
@pytest.mark.parametrize("error_type", [RuntimeError, FrozenCallbackError, FrozenCancellation])
def test_distinct_layers_preserve_exception_chain_and_worker_lock_order(
    kind, failing_layer, after_delegate, error_type
):
    _, store, sender, receiver, prekey = initial_peers(kind)
    message = sender.encrypt(b"three distinct policies")
    cause = LookupError("policy source unavailable")
    error = error_type("layer rejected")
    events, delivered = [], []
    reject = True

    def policy(layer):
        def invoke(delegate, record, envelope):
            events.append((layer, "before"))
            if reject:
                # Failed reads must not clear the surrounding write guard.
                with pytest.raises(NoSessionException):
                    receiver.get_session_version()
                with pytest.raises(ReentrantOperationException):
                    receiver.encrypt(b"nested policy write")
            if reject and layer == failing_layer and not after_delegate:
                raise error from cause
            result = delegate(record, envelope)
            events.append((layer, "after"))
            if reject and layer == failing_layer:
                raise error from cause
            return result

        return invoke

    for layer in range(3):
        receiver.builder = BuilderProxy(receiver.builder, policy(layer))

    def group_check():
        peers = group_peers(receiver.profile)

        def callback(_):
            # This worker has no session operation now. A stale SESSION_LOCK
            # entry could incorrectly authorize this reverse-order read.
            with pytest.raises(ReentrantOperationException):
                receiver.get_session_version()

        ciphertext = peers.sender.encrypt(b"group after rejected policy")
        assert peers.receiver.decrypt(ciphertext, callback) == b"group after rejected policy"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with pytest.raises(error_type) as caught:
            pool.submit(receiver.decrypt, message, delivered.append).result(timeout=3)
        assert caught.value is error and caught.value.__cause__ is cause
        assert not store.sessions and not delivered
        assert store.contains_pre_key(prekey.pre_key_id)
        if prekey.kyber_pre_key_id is not None:
            assert store.contains_kyber_pre_key(prekey.kyber_pre_key_id)
        assert events[0] == (2, "before")
        assert (failing_layer, "before") in events
        pool.submit(group_check).result(timeout=3)
        reject = False
        events.clear()
        assert pool.submit(receiver.decrypt, message, delivered.append).result(timeout=3) == (
            b"three distinct policies"
        )
        assert events == [
            (2, "before"),
            (1, "before"),
            (0, "before"),
            (0, "after"),
            (1, "after"),
            (2, "after"),
        ]
        reply = pool.submit(receiver.encrypt, b"worker reply").result(timeout=3)
        assert sender.decrypt(reply) == b"worker reply"
    assert delivered == [b"three distinct policies"]
    assert not store.contains_pre_key(prekey.pre_key_id)


@pytest.mark.parametrize("kind", ["upstream", "whatsapp_v3", "whatsapp_v4"])
@pytest.mark.parametrize("layers", [2, 3])
def test_unused_delegation_is_revoked_before_plaintext_and_store_hooks(kind, layers, monkeypatch):
    _, store, sender, receiver, _ = initial_peers(kind)
    message = sender.encrypt(b"already prepared")
    base = receiver.builder
    record = store.load_session(receiver.remote_address)
    unsigned_id = base.process_message(record, message)
    store.store_session(receiver.remote_address, record)
    active, events = [], []

    def prepared_policy(record, envelope):
        active[:] = [(record, envelope)]
        events.append("prepared")
        return unsigned_id

    def delegate_policy(delegate, record, envelope):
        events.append("wrapper")
        return delegate(record, envelope)

    monkeypatch.setattr(base, "process_message", prepared_policy)
    # Keep the original base implementation for attempted reentry, rather than
    # calling the replacement policy which intentionally performs no setup.
    original = type(base).process_message.__get__(base, type(base))
    original_store = store.store_session

    def reject_reentry():
        with pytest.raises(ReentrantOperationException):
            original(*active[0])

    def store_hook(address, draft):
        reject_reentry()
        original_store(address, draft)

    def callback(plaintext):
        assert plaintext == b"already prepared"
        reject_reentry()

    for _ in range(layers):
        receiver.builder = BuilderProxy(receiver.builder, delegate_policy)
    monkeypatch.setattr(store, "store_session", store_hook)
    assert receiver.decrypt(message, callback) == b"already prepared"
    assert events == ["wrapper"] * layers + ["prepared"]


@pytest.mark.parametrize("kind", ["upstream", "whatsapp_v3", "whatsapp_v4"])
@pytest.mark.parametrize("layers", [2, 3])
def test_shared_proxy_concurrent_duplicates_leave_each_worker_usable(kind, layers):
    _, store, sender, receiver, prekey = initial_peers(kind)
    message = sender.encrypt(b"simultaneous proxy delivery")
    barrier = Barrier(8, timeout=4)
    events, delivered = [], []

    def policy(layer):
        def invoke(delegate, record, envelope):
            events.append(layer)
            return delegate(record, envelope)

        return invoke

    for layer in range(layers):
        receiver.builder = BuilderProxy(receiver.builder, policy(layer))

    def receive(index):
        barrier.wait()
        try:
            assert receiver.decrypt(message, delivered.append) == b"simultaneous proxy delivery"
            accepted = True
        except DuplicateMessageException:
            accepted = False
        # Both accepted and rejected calls must leave this worker free to write.
        plaintext = b"worker reply " + str(index).encode()
        return accepted, plaintext, receiver.encrypt(plaintext)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(receive, i) for i in range(8)]
        results = [future.result(timeout=5) for future in futures]
    assert sum(accepted for accepted, _, _ in results) == 1
    assert delivered == [b"simultaneous proxy delivery"]
    assert events == list(reversed(range(layers))) * 8
    assert not store.contains_pre_key(prekey.pre_key_id)
    assert sorted(reply.counter for _, _, reply in results) == list(range(8))
    for _, plaintext, reply in reversed(results):
        assert sender.decrypt(reply) == plaintext
