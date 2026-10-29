"""Test fixtures ported from the upstream JUnit store and interaction helpers."""

import json
import random
from pathlib import Path

from signal_protocol import (
    Curve,
    InMemorySignalProtocolStore,
    KeyHelper,
    PreKeyBundle,
    PreKeyRecord,
    PreKeySignalMessage,
    SessionBuilder,
    SessionCipher,
    SessionRecord,
    SignalMessage,
    SignalProtocolAddress,
    SignedPreKeyRecord,
)
from signal_protocol.ratchet import (
    AliceSignalProtocolParameters,
    BobSignalProtocolParameters,
    RatchetingSession,
)

ALICE = SignalProtocolAddress("+14151111111", 1)
BOB = SignalProtocolAddress("+14152222222", 1)
TEXT = "L'homme est condamné à être libre".encode()


def vector(name):
    values = json.loads((Path(__file__).parent / "vectors/upstream.json").read_text())[name][
        "arrays"
    ]
    return {k: bytes.fromhex(v) for k, v in values.items()}


def bundle(store, pre_id=31337, signed_id=22, one_time=True, signed_pair=None):
    pre = Curve.generate_key_pair()
    signed = signed_pair or Curve.generate_key_pair()
    signature = Curve.calculate_signature(
        store.get_identity_key_pair().private_key, signed.public_key.serialize()
    )
    store.store_pre_key(pre_id, PreKeyRecord(pre_id, pre))
    store.store_signed_pre_key(signed_id, SignedPreKeyRecord(signed_id, 1, signed, signature))
    return PreKeyBundle(
        store.get_local_registration_id(),
        1,
        pre_id,
        pre.public_key if one_time else None,
        signed_id,
        signed.public_key,
        signature,
        store.get_identity_key_pair().public_key,
    )


def decode(message):
    cls = PreKeySignalMessage if message.type == 3 else SignalMessage
    return cls.from_bytes(message.serialize())


def setup_prekey(one_time=True):
    alice, bob = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    prekey = bundle(bob, one_time=one_time)
    SessionBuilder(alice, BOB).process(prekey)
    return alice, bob, SessionCipher(alice, BOB), SessionCipher(bob, ALICE), prekey


def initialize_sessions():
    alice_identity, bob_identity = (
        KeyHelper.generate_identity_key_pair(),
        KeyHelper.generate_identity_key_pair(),
    )
    base, signed = Curve.generate_key_pair(), Curve.generate_key_pair()
    alice, bob = SessionRecord(), SessionRecord()
    RatchetingSession.initialize_session(
        alice.session_state,
        AliceSignalProtocolParameters(
            alice_identity, base, bob_identity.public_key, signed.public_key, signed.public_key
        ),
    )
    RatchetingSession.initialize_session(
        bob.session_state,
        BobSignalProtocolParameters(
            bob_identity, signed, signed, alice_identity.public_key, base.public_key
        ),
    )
    return alice, bob


def initialized_ciphers():
    ar, br = initialize_sessions()
    a, b = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
    a.store_session(BOB, ar)
    b.store_session(ALICE, br)
    return a, b, SessionCipher(a, BOB), SessionCipher(b, ALICE)


def run_interaction(alice, bob):
    ac, bc = SessionCipher(alice, BOB), SessionCipher(bob, ALICE)
    for sender, receiver in ((ac, bc), (bc, ac)):
        message = sender.encrypt(b"smert ze smert")
        assert message.type == 2
        assert receiver.decrypt(decode(message)) == b"smert ze smert"
    prefix = (
        "What do we mean by saying that existence precedes essence? "
        "We mean that man first of all exists, encounters himself, "
        "surges up in the world--and defines himself aftward. "
    )
    for sender, receiver in ((ac, bc), (bc, ac)):
        for i in range(10):
            plaintext = (prefix + str(i)).encode()
            assert receiver.decrypt(decode(sender.encrypt(plaintext))) == plaintext
    inflight = [
        ((prefix + str(i)).encode(), ac.encrypt((prefix + str(i)).encode())) for i in range(10)
    ]
    for i in range(10):
        plaintext = (prefix + str(i)).encode()
        assert bc.decrypt(decode(ac.encrypt(plaintext))) == plaintext
    for i in range(10):
        plaintext = ("You can only desire based on what you know: " + str(i)).encode()
        assert ac.decrypt(decode(bc.encrypt(plaintext))) == plaintext
    random.Random(734).shuffle(inflight)
    for plaintext, message in inflight:
        assert bc.decrypt(decode(message)) == plaintext
