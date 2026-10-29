"""All SessionBuilderTest and SessionCipherTest scenarios, with original loop bounds."""

import random
from dataclasses import replace

import pytest

from signal_protocol import (
    Curve,
    InMemorySignalProtocolStore,
    PreKeyBundle,
    PreKeySignalMessage,
    SessionBuilder,
    SessionCipher,
)
from signal_protocol.exceptions import (
    DuplicateMessageException,
    InvalidKeyException,
    InvalidMessageException,
    UntrustedIdentityException,
)

from .helpers import (
    ALICE,
    BOB,
    TEXT,
    bundle,
    decode,
    initialized_ciphers,
    run_interaction,
    setup_prekey,
)


class TestSessionBuilder:
    def testBasicPreKeyV2(self):
        alice, bob = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
        prekey = PreKeyBundle(
            bob.registration_id,
            1,
            31337,
            Curve.generate_key_pair().public_key,
            0,
            None,
            None,
            bob.identity_key_pair.public_key,
        )
        with pytest.raises(InvalidKeyException):
            SessionBuilder(alice, BOB).process(prekey)

    def testBasicPreKeyV3(self):
        alice, bob, ac, bc, _ = setup_prekey()
        assert alice.contains_session(BOB)
        assert alice.load_session(BOB).session_state.session_version == 3
        outgoing = ac.encrypt(TEXT)
        assert outgoing.type == 3

        def callback(plaintext):
            assert plaintext == TEXT
            assert not bob.contains_session(ALICE)

        assert bc.decrypt(decode(outgoing), callback) == TEXT
        assert bob.contains_session(ALICE)
        state = bob.load_session(ALICE).session_state
        assert state.session_version == 3 and state.alice_base_key is not None
        reply = bc.encrypt(TEXT)
        assert reply.type == 2
        assert ac.decrypt(decode(reply)) == TEXT
        run_interaction(alice, bob)

        alice = InMemorySignalProtocolStore()
        prekey = bundle(bob, 31338, 23)
        builder, ac = SessionBuilder(alice, BOB), SessionCipher(alice, BOB)
        builder.process(prekey)
        outgoing = ac.encrypt(TEXT)
        with pytest.raises(UntrustedIdentityException):
            bc.decrypt(decode(outgoing))
        bob.save_identity(ALICE, decode(outgoing).identity_key)
        assert bc.decrypt(decode(outgoing)) == TEXT
        changed_identity = replace(
            prekey,
            pre_key_id=31337,
            pre_key=Curve.generate_key_pair().public_key,
            identity_key=alice.identity_key_pair.public_key,
        )
        with pytest.raises(UntrustedIdentityException):
            builder.process(changed_identity)

    def testBadSignedPreKeySignature(self):
        alice, bob = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
        prekey = bundle(bob)
        builder = SessionBuilder(alice, BOB)
        for i in range(len(prekey.signed_pre_key_signature) * 8):
            modified = bytearray(prekey.signed_pre_key_signature)
            modified[i // 8] ^= 1 << (i % 8)
            with pytest.raises(InvalidKeyException):
                builder.process(replace(prekey, signed_pre_key_signature=bytes(modified)))
        builder.process(prekey)

    def testRepeatBundleMessageV2(self):
        alice, bob = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
        prekey = replace(
            bundle(bob), signed_pre_key_id=0, signed_pre_key=None, signed_pre_key_signature=None
        )
        with pytest.raises(InvalidKeyException):
            SessionBuilder(alice, BOB).process(prekey)

    def testRepeatBundleMessageV3(self):
        _, _, ac, bc, _ = setup_prekey()
        first, second = ac.encrypt(TEXT), ac.encrypt(TEXT)
        assert first.type == second.type == 3
        assert bc.decrypt(decode(first)) == TEXT
        assert ac.decrypt(decode(bc.encrypt(TEXT))) == TEXT
        assert bc.decrypt(PreKeySignalMessage.from_bytes(decode(second).serialize())) == TEXT
        assert ac.decrypt(decode(bc.encrypt(TEXT))) == TEXT

    def testBadMessageBundle(self):
        _, bob, ac, bc, _ = setup_prekey()
        good = ac.encrypt(TEXT)
        assert good.type == 3
        bad = bytearray(good.serialize())
        bad[-10] ^= 1
        with pytest.raises(InvalidMessageException):
            bc.decrypt(PreKeySignalMessage.from_bytes(bytes(bad)))
        assert bob.contains_pre_key(31337)
        assert bc.decrypt(decode(good)) == TEXT
        assert not bob.contains_pre_key(31337)

    def testOptionalOneTimePreKey(self):
        alice, bob, ac, bc, _ = setup_prekey(one_time=False)
        assert alice.contains_session(BOB)
        assert alice.load_session(BOB).session_state.session_version == 3
        outgoing = ac.encrypt(TEXT)
        assert outgoing.type == 3
        message = decode(outgoing)
        assert message.pre_key_id is None
        assert bc.decrypt(message) == TEXT
        assert bob.contains_session(ALICE)
        state = bob.load_session(ALICE).session_state
        assert state.session_version == 3 and state.alice_base_key is not None


class TestSessionCipher:
    def testBasicSessionV3(self):
        _, _, ac, bc = initialized_ciphers()
        assert (
            bc.decrypt(decode(ac.encrypt(b"This is a plaintext message.")))
            == b"This is a plaintext message."
        )
        assert (
            ac.decrypt(decode(bc.encrypt(b"This is a message from Bob.")))
            == b"This is a message from Bob."
        )
        pending_a = [
            (f"смерть за смерть {i}".encode(), ac.encrypt(f"смерть за смерть {i}".encode()))
            for i in range(50)
        ]
        random.Random(42).shuffle(pending_a)
        for plaintext, message in pending_a[:25]:
            assert bc.decrypt(decode(message)) == plaintext
        pending_b = [
            (f"смерть за смерть {i}".encode(), bc.encrypt(f"смерть за смерть {i}".encode()))
            for i in range(20)
        ]
        random.Random(43).shuffle(pending_b)
        for plaintext, message in pending_b[:10]:
            assert ac.decrypt(decode(message)) == plaintext
        for plaintext, message in pending_a[25:]:
            assert bc.decrypt(decode(message)) == plaintext
        for plaintext, message in pending_b[10:]:
            assert ac.decrypt(decode(message)) == plaintext

    def testMessageKeyLimits(self):
        _, _, ac, bc = initialized_ciphers()
        inflight = [
            ac.encrypt(b"you've never been so hungry, you've never been so cold")
            for _ in range(2010)
        ]
        bc.decrypt(decode(inflight[1000]))
        bc.decrypt(decode(inflight[-1]))
        with pytest.raises(DuplicateMessageException):
            bc.decrypt(decode(inflight[0]))
