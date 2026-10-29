"""Literal JUnit vectors and all ECC/KDF/ratchet test cases."""

import sys

import pytest

from signal_protocol import (
    Curve,
    ECKeyPair,
    ECPrivateKey,
    IdentityKey,
    IdentityKeyPair,
    SessionState,
)
from signal_protocol.exceptions import InvalidKeyException
from signal_protocol.kdf import HKDF
from signal_protocol.ratchet import (
    AliceSignalProtocolParameters,
    BobSignalProtocolParameters,
    ChainKey,
    RatchetingSession,
    RootKey,
)

from .helpers import vector


class TestCurve:
    def testPureJava(self):
        # The JVM-provider selection assertion becomes Python runtime independence.
        # Native arithmetic libraries are allowed; no Java/JNI bridge is imported.
        assert Curve.__module__ == "signal_protocol.ecc"
        assert "jpype" not in sys.modules and "jnius" not in sys.modules

    def testLargeSignatures(self):
        pair = Curve.generate_key_pair()
        message = bytes(1024 * 1024)
        sig = Curve.calculate_signature(pair.private_key, message)
        assert Curve.verify_signature(pair.public_key, message, sig)
        assert not Curve.verify_signature(pair.public_key, b"\x01" + message[1:], sig)


class TestCurve25519:
    def testAgreement(self):
        v = vector("Curve25519Test.testAgreement")
        assert (
            Curve.calculate_agreement(
                Curve.decode_point(v["alicePublic"]), ECPrivateKey(v["bobPrivate"])
            )
            == v["shared"]
        )
        assert (
            Curve.calculate_agreement(
                Curve.decode_point(v["bobPublic"]), ECPrivateKey(v["alicePrivate"])
            )
            == v["shared"]
        )

    def testRandomAgreements(self):
        for _ in range(50):
            a, b = Curve.generate_key_pair(), Curve.generate_key_pair()
            assert Curve.calculate_agreement(
                a.public_key, b.private_key
            ) == Curve.calculate_agreement(b.public_key, a.private_key)

    def testSignature(self):
        v = vector("Curve25519Test.testSignature")
        public = Curve.decode_point(v["aliceIdentityPublic"])
        message, signature = v["aliceEphemeralPublic"], v["aliceSignature"]
        assert Curve.verify_signature(public, message, signature)
        for i in range(len(signature)):
            altered = bytearray(signature)
            altered[i] ^= 1
            assert not Curve.verify_signature(public, message, bytes(altered))

    def testDecodeSize(self):
        public = Curve.generate_key_pair().public_key.serialize()
        assert Curve.decode_point(public).serialize() == public
        for raw, offset in ((public, 1), (b"", 0), (b"\x01" + public[1:], 0)):
            with pytest.raises(InvalidKeyException):
                Curve.decode_point(raw, offset)
        assert Curve.decode_point(public + b"\0").serialize() == public
        assert Curve.decode_point(b"\0" + public, 1).serialize() == public


class TestHKDF:
    def check(self, method, version):
        v = vector("HKDFTest." + method)
        assert (
            HKDF(version).derive_secrets(v["ikm"], v["info"], len(v["okm"]), v["salt"]) == v["okm"]
        )

    def testVectorV3(self):
        self.check("testVectorV3", 3)

    def testVectorLongV3(self):
        self.check("testVectorLongV3", 3)

    def testVectorV2(self):
        self.check("testVectorV2", 2)


class TestChainKey:
    def check(self, version):
        v = vector(f"ChainKeyTest.testChainKeyDerivationV{version}")
        chain = ChainKey(HKDF(version), v["seed"], 0)
        assert chain.key == v["seed"]
        assert chain.message_keys().cipher_key == v["messageKey"]
        assert chain.message_keys().mac_key == v["macKey"]
        assert chain.next_chain_key().key == v["nextChainKey"]
        assert chain.index == chain.message_keys().counter == 0
        assert chain.next_chain_key().index == chain.next_chain_key().message_keys().counter == 1

    def testChainKeyDerivationV2(self):
        self.check(2)

    def testChainKeyDerivationV3(self):
        self.check(3)


class TestRootKey:
    def testRootKeyDerivationV2(self):
        v = vector("RootKeyTest.testRootKeyDerivationV2")
        root = RootKey(HKDF(2), v["rootKeySeed"])
        alice = ECKeyPair(Curve.decode_point(v["alicePublic"]), ECPrivateKey(v["alicePrivate"]))
        next_root, next_chain = root.create_chain(Curve.decode_point(v["bobPublic"]), alice)
        assert root.key == v["rootKeySeed"]
        assert next_root.key == v["nextRoot"]
        assert next_chain.key == v["nextChain"]


class TestRatchetingSession:
    def testRatchetingSessionAsBob(self):
        v = vector("RatchetingSessionTest.testRatchetingSessionAsBob")
        bob_identity = IdentityKeyPair(
            IdentityKey.from_bytes(v["bobIdentityPublic"]), ECPrivateKey(v["bobIdentityPrivate"])
        )
        bob_ratchet = ECKeyPair(Curve.decode_point(v["bobPublic"]), ECPrivateKey(v["bobPrivate"]))
        bob_signed = ECKeyPair(
            Curve.decode_point(v["bobSignedPreKeyPublic"]),
            ECPrivateKey(v["bobSignedPreKeyPrivate"]),
        )
        alice_identity = IdentityKey.from_bytes(v["aliceIdentityPublic"])
        state = SessionState()
        RatchetingSession.initialize_session(
            state,
            BobSignalProtocolParameters(
                bob_identity,
                bob_signed,
                bob_ratchet,
                alice_identity,
                Curve.decode_point(v["aliceBasePublic"]),
            ),
        )
        assert state.local_identity_key == bob_identity.public_key
        assert state.remote_identity_key == alice_identity
        assert state.sender_chain_key.key == v["senderChain"]

    def testRatchetingSessionAsAlice(self):
        v = vector("RatchetingSessionTest.testRatchetingSessionAsAlice")
        alice_identity = IdentityKeyPair(
            IdentityKey.from_bytes(v["aliceIdentityPublic"]),
            ECPrivateKey(v["aliceIdentityPrivate"]),
        )
        alice_base = ECKeyPair(
            Curve.decode_point(v["aliceBasePublic"]), ECPrivateKey(v["aliceBasePrivate"])
        )
        bob_identity = IdentityKey.from_bytes(v["bobIdentityPublic"])
        bob_ephemeral = Curve.decode_point(v["bobPublic"])
        state = SessionState()
        RatchetingSession.initialize_session(
            state,
            AliceSignalProtocolParameters(
                alice_identity,
                alice_base,
                bob_identity,
                Curve.decode_point(v["bobSignedPreKeyPublic"]),
                bob_ephemeral,
            ),
        )
        assert state.local_identity_key == alice_identity.public_key
        assert state.remote_identity_key == bob_identity
        assert state.get_receiver_chain_key(bob_ephemeral).key == v["receiverChain"]
