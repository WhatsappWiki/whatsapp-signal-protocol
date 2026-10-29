"""Additional parser, state-transaction, storage, and native-reference regressions."""

import json
from pathlib import Path

import pytest

from signal_protocol import (
    Curve,
    ECPrivateKey,
    IdentityKeyPair,
    KeyHelper,
    PreKeySignalMessage,
    SessionCipher,
    SessionRecord,
    SessionState,
    SignalMessage,
)
from signal_protocol.exceptions import (
    DuplicateMessageException,
    FingerprintParsingException,
    FingerprintVersionMismatchException,
    InvalidMessageException,
    InvalidVersionException,
    LegacyMessageException,
    UntrustedIdentityException,
    VrfSignatureVerificationFailedException,
)
from signal_protocol.fingerprint import ScannableFingerprint
from signal_protocol.groups import SenderKeyRecord
from signal_protocol.kdf import HKDF
from signal_protocol.protocol import SenderKeyDistributionMessage, SenderKeyMessage
from signal_protocol.ratchet import ChainKey, RatchetingSession, SymmetricSignalProtocolParameters
from signal_protocol.store import Direction, InMemorySignalProtocolStore, SignalProtocolAddress

from .helpers import ALICE, BOB, TEXT, decode, initialized_ciphers, setup_prekey
from .test_upstream_groups import peers


@pytest.mark.parametrize(
    "cls", [SignalMessage, PreKeySignalMessage, SenderKeyMessage, SenderKeyDistributionMessage]
)
@pytest.mark.parametrize("raw", [b"", b"\x33", b"\x33\xff", b"\x33" + b"\0" * 70])
def test_malformed_envelopes(cls, raw):
    with pytest.raises(InvalidMessageException):
        cls.from_bytes(raw)


@pytest.mark.parametrize(
    "cls,trailer",
    [
        (SignalMessage, 8),
        (PreKeySignalMessage, 0),
        (SenderKeyMessage, 64),
        (SenderKeyDistributionMessage, 0),
    ],
)
def test_version_errors(cls, trailer):
    old = InvalidMessageException if cls is PreKeySignalMessage else LegacyMessageException
    future = InvalidVersionException if cls is PreKeySignalMessage else InvalidMessageException
    with pytest.raises(old):
        cls.from_bytes(b"\x23" + bytes(trailer))
    with pytest.raises(future):
        cls.from_bytes(b"\x43" + bytes(trailer))


def test_prekey_authentication_and_callback_are_transactional():
    _, bob, ac, bc, _ = setup_prekey()
    message = ac.encrypt(TEXT)
    inner = bytearray(message.message.serialize())
    inner[-1] ^= 1
    bad = PreKeySignalMessage(
        message.message_version,
        message.registration_id,
        message.pre_key_id,
        message.signed_pre_key_id,
        message.base_key,
        message.identity_key,
        SignalMessage.from_bytes(bytes(inner)),
    )
    before = dict(bob.sessions)
    with pytest.raises(InvalidMessageException):
        bc.decrypt(decode(bad))
    assert bob.sessions == before and bob.contains_pre_key(31337)

    def abort(plaintext):
        assert plaintext == TEXT and bob.sessions == before and bob.contains_pre_key(31337)
        raise RuntimeError("application transaction failed")

    with pytest.raises(RuntimeError):
        bc.decrypt(decode(message), abort)
    assert bob.sessions == before and bob.contains_pre_key(31337)
    assert bc.decrypt(decode(message)) == TEXT
    assert not bob.contains_pre_key(31337)
    committed = dict(bob.sessions)
    with pytest.raises(DuplicateMessageException):
        bc.decrypt(decode(message))
    assert bob.sessions == committed


def test_signal_authentication_padding_callback_and_replay_do_not_commit():
    _, bob, ac, bc = initialized_ciphers()
    original = ac.encrypt(TEXT)
    before = dict(bob.sessions)
    altered = bytearray(original.serialize())
    altered[-1] ^= 1
    with pytest.raises(InvalidMessageException):
        bc.decrypt(SignalMessage.from_bytes(bytes(altered)))
    assert bob.sessions == before

    def abort(_):
        raise RuntimeError("abort")

    with pytest.raises(RuntimeError):
        bc.decrypt(decode(original), abort)
    assert bob.sessions == before
    assert bc.decrypt(decode(original)) == TEXT
    committed = dict(bob.sessions)
    with pytest.raises(DuplicateMessageException):
        bc.decrypt(decode(original))
    assert bob.sessions == committed


def test_group_failure_does_not_commit():
    _, b, _, _, ac, bc = peers()
    message = ac.encrypt(TEXT)
    before = dict(b.keys)
    bad = bytearray(message)
    bad[-1] ^= 1
    with pytest.raises(InvalidMessageException):
        bc.decrypt(bytes(bad))
    assert b.keys == before

    def abort(_):
        raise RuntimeError("abort")

    with pytest.raises(RuntimeError):
        bc.decrypt(message, abort)
    assert b.keys == before
    assert bc.decrypt(message) == TEXT


def test_identity_changes_block_send_receive_without_committing_session():
    a, b, ac, bc = initialized_ciphers()
    original = ac.encrypt(TEXT)
    wrong = KeyHelper.generate_identity_key_pair().public_key
    a.save_identity(BOB, wrong)
    before = dict(a.sessions)
    with pytest.raises(UntrustedIdentityException):
        ac.encrypt(TEXT)
    assert a.sessions == before
    b.save_identity(ALICE, wrong)
    before = dict(b.sessions)
    with pytest.raises(UntrustedIdentityException):
        bc.decrypt(decode(original))
    assert b.sessions == before


def test_session_and_sender_record_limits_and_copy_isolation():
    record = SessionRecord()
    for i in range(50):
        record.session_state.alice_base_key = bytes([i])
        record.archive_current_state()
    assert len(record.previous_states) == 40
    assert record.previous_states[0].alice_base_key == bytes([49])
    assert record.previous_states[-1].alice_base_key == bytes([10])
    restored = SessionRecord(record.serialize())
    restored.previous_states[0].alice_base_key = b"changed"
    assert record.previous_states[0].alice_base_key == bytes([49])
    state = SessionState()
    pairs = [Curve.generate_key_pair() for _ in range(6)]
    for pair in pairs:
        state.add_receiver_chain(pair.public_key, ChainKey(HKDF(), bytes(32), 0))
    assert not state.has_receiver_chain(pairs[0].public_key)
    assert state.has_receiver_chain(pairs[1].public_key)
    sender = SenderKeyRecord()
    for i in range(6):
        sender.add_sender_key_state(i, 0, bytes(32), pairs[0].public_key)
    assert len(sender.states) == 5 and [s.key_id for s in sender.states] == [5, 4, 3, 2, 1]
    sender.set_sender_key_state(8, 0, bytes(32), pairs[0])
    assert len(sender.states) == 1 and sender.get_sender_key_state().key_id == 8


def test_inmemory_store_contracts():
    store = InMemorySignalProtocolStore()
    id1 = store.identity_key_pair.public_key
    id2 = KeyHelper.generate_identity_key_pair().public_key
    assert store.is_trusted_identity(ALICE, id1, Direction.SENDING)
    assert store.save_identity(ALICE, id1)
    assert not store.save_identity(ALICE, id1)
    assert not store.is_trusted_identity(ALICE, id2, Direction.RECEIVING)
    assert store.get_identity(ALICE) == id1
    pre = KeyHelper.generate_pre_keys(1, 1)[0]
    store.store_pre_key(1, pre)
    loaded = store.load_pre_key(1)
    loaded.structure.id = 2
    assert store.load_pre_key(1).id == 1
    signed = KeyHelper.generate_signed_pre_key(store.identity_key_pair, 3)
    store.store_signed_pre_key(3, signed)
    assert store.load_signed_pre_keys()[0].signature == signed.signature
    store.remove_signed_pre_key(3)
    assert not store.contains_signed_pre_key(3)
    for device in (1, 2, 3):
        store.store_session(SignalProtocolAddress("a", device), SessionRecord())
    assert sorted(store.get_sub_device_sessions("a")) == [2, 3]
    store.delete_all_sessions("a")
    assert store.get_sub_device_sessions("a") == []


def test_key_generation_ranges_and_records():
    assert [p.id for p in KeyHelper.generate_pre_keys(0, 3)] == [0, 1, 2]
    assert [p.id for p in KeyHelper.generate_pre_keys(0xFFFFFE, 3)] == [0xFFFFFE, 1, 2]
    for _ in range(30):
        assert 1 <= KeyHelper.generate_registration_id() <= 16380
        assert 1 <= KeyHelper.generate_registration_id(True) < 2147483647
        assert 0 <= KeyHelper.get_random_sequence(31) < 31
    identity = KeyHelper.generate_identity_key_pair()
    assert IdentityKeyPair.from_bytes(identity.serialize()) == identity
    signed = KeyHelper.generate_signed_pre_key(identity, 22)
    assert Curve.verify_signature(
        identity.public_key.public_key, signed.key_pair.public_key.serialize(), signed.signature
    )


def test_symmetric_initialization_agrees_with_signed_big_integer_ordering():
    # Exercise both branches; unsigned byte sorting is wrong for Java BigInteger.
    for _ in range(8):
        ai, bi = KeyHelper.generate_identity_key_pair(), KeyHelper.generate_identity_key_pair()
        ab, bb, ar, br = [Curve.generate_key_pair() for _ in range(4)]
        a, b = SessionRecord(), SessionRecord()
        RatchetingSession.initialize_session(
            a.session_state,
            SymmetricSignalProtocolParameters(
                ai, ab, ar, bi.public_key, bb.public_key, br.public_key
            ),
        )
        RatchetingSession.initialize_session(
            b.session_state,
            SymmetricSignalProtocolParameters(
                bi, bb, br, ai.public_key, ab.public_key, ar.public_key
            ),
        )
        ast, bst = InMemorySignalProtocolStore(ai), InMemorySignalProtocolStore(bi)
        ast.store_session(BOB, a)
        bst.store_session(ALICE, b)
        ac, bc = SessionCipher(ast, BOB), SessionCipher(bst, ALICE)
        assert bc.decrypt(decode(ac.encrypt(TEXT))) == TEXT
        assert ac.decrypt(decode(bc.encrypt(TEXT))) == TEXT


def test_fingerprint_parse_and_version_errors():
    f = ScannableFingerprint(2, bytes(64), bytes([1]) * 64)
    with pytest.raises(FingerprintParsingException):
        f.compare_to(b"\xff")
    with pytest.raises(FingerprintVersionMismatchException):
        f.compare_to(b"")
    with pytest.raises(FingerprintVersionMismatchException):
        f.compare_to(ScannableFingerprint(1, bytes(64), bytes(64)).serialize())


VRF_VECTORS = json.loads((Path(__file__).parent / "vectors/native-vrf.json").read_text())


@pytest.mark.parametrize("row", VRF_VECTORS, ids=[f"native-{i}" for i in range(len(VRF_VECTORS))])
def test_native_reference_vrf_vectors(row):
    v = {k: bytes.fromhex(x) for k, x in row.items()}
    private, public = ECPrivateKey(v["private"]), Curve.decode_point(v["public"])
    assert (
        Curve.calculate_vrf_signature(private, v["message"], random=v["random"]) == v["signature"]
    )
    assert Curve.verify_vrf_signature(public, v["message"], v["signature"]) == v["output"]
    altered = bytearray(v["signature"])
    altered[45] ^= 1
    with pytest.raises(VrfSignatureVerificationFailedException):
        Curve.verify_vrf_signature(public, v["message"], bytes(altered))
    with pytest.raises(VrfSignatureVerificationFailedException):
        Curve.verify_vrf_signature(public, v["message"] + b"x", v["signature"])
    again = Curve.calculate_vrf_signature(private, v["message"])
    assert again != v["signature"]
    assert Curve.verify_vrf_signature(public, v["message"], again) == v["output"]


def test_native_arithmetic_backend_for_generated_keys(monkeypatch):
    from signal_protocol import ecc

    calls = []
    real = ecc.sodium.crypto_scalarmult

    def observe(private, public):
        calls.append((private, public))
        return real(private, public)

    monkeypatch.setattr(ecc.sodium, "crypto_scalarmult", observe)
    alice, bob = Curve.generate_key_pair(), Curve.generate_key_pair()
    shared = Curve.calculate_agreement(alice.public_key, bob.private_key)
    assert len(calls) == 1 and shared == real(bob.private_key.key, alice.public_key.key)
