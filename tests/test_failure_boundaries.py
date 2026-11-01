"""Authentication, cancellation, and post-commit cleanup have distinct boundaries."""

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from signal_protocol import UPSTREAM, WHATSAPP, SignalMessage
from signal_protocol.exceptions import DuplicateMessageException, InvalidMessageException
from signal_protocol.protocol import SenderKeyMessage
from tests.helpers import ALICE
from tests.test_reentrant_operations import established, group_peers
from tests.test_whatsapp_sessions import parse
from tests.test_whatsapp_sessions import peers as hybrid_peers


def invalid_ciphertext(kind, key):
    if kind == "empty":
        return b""
    if kind == "unaligned":
        return bytes(15)
    encryptor = Cipher(algorithms.AES(key.cipher_key), modes.CBC(key.iv)).encryptor()
    return encryptor.update(bytes(16)) + encryptor.finalize()


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
@pytest.mark.parametrize("kind", ["empty", "unaligned", "zero_padding"])
@pytest.mark.parametrize("group", [False, True])
def test_authenticated_bad_cbc_does_not_consume_skipped_message_key(profile, kind, group):
    p = group_peers(profile) if group else established(profile)
    messages = [p.sender.encrypt(b"first"), p.sender.encrypt(b"second"), p.sender.encrypt(b"third")]
    assert p.receiver.decrypt(messages[2]) == b"third"
    if group:
        message = SenderKeyMessage.from_bytes(messages[0], profile=profile)
        state = p.b.load_sender_key(p.name).get_sender_key_state()
        key = state.remove_sender_message_key(message.iteration)
        private = p.a.load_sender_key(p.name).get_sender_key_state().signing_key_private
        invalid = SenderKeyMessage(
            message.key_id, message.iteration, invalid_ciphertext(kind, key), private
        ).serialize()
        persisted = p.b.keys
    else:
        message = messages[0]
        state = p.b.load_session(ALICE).session_state
        key = state.remove_message_keys(message.sender_ratchet_key, message.counter)
        invalid = SignalMessage(
            message.message_version,
            key.mac_key,
            message.sender_ratchet_key,
            message.counter,
            message.previous_counter,
            invalid_ciphertext(kind, key),
            state.remote_identity_key,
            state.local_identity_key,
            profile=profile,
        )
        persisted = p.b.sessions
    before = dict(persisted)
    delivered = []
    with pytest.raises(InvalidMessageException):
        p.receiver.decrypt(invalid, delivered.append)
    assert persisted == before and delivered == []
    assert p.receiver.decrypt(messages[0]) == b"first"
    with pytest.raises(DuplicateMessageException):
        p.receiver.decrypt(messages[0])
    assert p.receiver.decrypt(messages[1]) == b"second"


class ApplicationCancelled(BaseException):
    pass


@pytest.mark.parametrize("profile", [UPSTREAM, WHATSAPP])
@pytest.mark.parametrize("group", [False, True])
@pytest.mark.parametrize("error_type", [KeyboardInterrupt, ApplicationCancelled])
def test_base_exception_preserves_state_and_allows_same_thread_retry(profile, group, error_type):
    p = group_peers(profile) if group else established(profile)
    p.sender.encrypt(b"skipped")
    message = p.sender.encrypt(b"retry")
    persisted = p.b.keys if group else p.b.sessions
    before = dict(persisted)
    error = error_type("cancelled")

    def abort(_):
        raise error

    with pytest.raises(error_type) as caught:
        p.receiver.decrypt(message, abort)
    assert caught.value is error
    assert persisted == before
    assert p.receiver.decrypt(message) == b"retry"


@pytest.mark.parametrize("cleanup", ["curve", "kem"])
def test_cleanup_failure_after_commit_does_not_roll_back_or_redeliver(cleanup, monkeypatch):
    # External Store calls are not a transaction: cleanup may fail after the
    # plaintext callback and session commit. Never rewind the committed ratchet.
    p = hybrid_peers()
    message = parse(p.ac.encrypt(b"already committed"))
    method = "remove_pre_key" if cleanup == "curve" else "mark_kyber_pre_key_used"
    original = getattr(p.b, method)

    def fail(_):
        raise OSError("cleanup unavailable")

    monkeypatch.setattr(p.b, method, fail)
    delivered = []
    with pytest.raises(OSError, match="cleanup unavailable"):
        p.bc.decrypt(message, delivered.append)
    assert delivered == [b"already committed"]
    assert p.b.sessions
    committed = dict(p.b.sessions)
    assert p.b.contains_pre_key(37) == (cleanup == "curve")
    assert p.b.contains_kyber_pre_key(71)
    monkeypatch.setattr(p.b, method, original)
    with pytest.raises(DuplicateMessageException):
        p.bc.decrypt(message, delivered.append)
    assert p.b.sessions == committed and delivered == [b"already committed"]
