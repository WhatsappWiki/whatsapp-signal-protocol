"""Real Java/Python differential and bidirectional protocol integration tests."""

import base64
import json
import secrets
from pathlib import Path

import pytest

from signal_protocol import (
    Curve,
    ECPrivateKey,
    IdentityKeyPair,
    InMemorySignalProtocolStore,
    KeyHelper,
    PreKeyBundle,
    PreKeyRecord,
    PreKeySignalMessage,
    SessionBuilder,
    SessionCipher,
    SessionRecord,
    SessionState,
    SignalMessage,
    SignalProtocolAddress,
    SignedPreKeyRecord,
)
from signal_protocol.fingerprint import NumericFingerprintGenerator
from signal_protocol.groups import (
    GroupCipher,
    GroupSessionBuilder,
    InMemorySenderKeyStore,
    SenderKeyName,
    SenderKeyRecord,
)
from signal_protocol.protocol import SenderKeyDistributionMessage, SenderKeyMessage
from tests.helpers import vector

REMOTE = SignalProtocolAddress("peer", 1)
NAME = SenderKeyName("interop", REMOTE)


def remote_material(java, name):
    identity, reg, pre, signed = java.call("init", name)
    return (
        IdentityKeyPair.from_bytes(base64.b64decode(identity)),
        int(reg),
        PreKeyRecord.from_bytes(base64.b64decode(pre)),
        SignedPreKeyRecord.from_bytes(base64.b64decode(signed)),
    )


def parse_message(type, data):
    return (PreKeySignalMessage if int(type) == 3 else SignalMessage).from_bytes(data)


def decrypt_python(cipher, response):
    type, data = response
    return cipher.decrypt(parse_message(type, base64.b64decode(data)))


def send_python(java, name, cipher, plaintext):
    msg = cipher.encrypt(plaintext)
    assert java.raw("decrypt", name, msg.type, msg.serialize()) == plaintext
    return msg


def test_random_and_unclamped_agreements(java):
    for _ in range(12):
        a, b = Curve.generate_key_pair(), Curve.generate_key_pair()
        assert java.raw(
            "dh", a.public_key.serialize(), b.private_key.serialize()
        ) == Curve.calculate_agreement(a.public_key, b.private_key)
    v = vector("RootKeyTest.testRootKeyDerivationV2")
    assert java.raw("dh", v["bobPublic"], v["alicePrivate"]) == Curve.calculate_agreement(
        Curve.decode_point(v["bobPublic"]), ECPrivateKey(v["alicePrivate"])
    )
    for private in (secrets.token_bytes(32), bytes(32), b"\xff" * 32):
        for public in (
            Curve.generate_key_pair().public_key.serialize(),
            b"\x05" + bytes(32),
            b"\x05" + b"\xff" * 32,
        ):
            assert java.raw("dh", public, private) == Curve.calculate_agreement(
                Curve.decode_point(public), ECPrivateKey(private)
            )


def test_exact_randomized_signatures(java):
    for _ in range(12):
        pair = Curve.generate_key_pair()
        msg = secrets.token_bytes(73)
        random = secrets.token_bytes(64)
        signature = Curve.calculate_signature(pair.private_key, msg, random=random)
        assert signature == java.raw("sign", pair.private_key.key, msg, random)
        assert java.call("verify", pair.public_key.serialize(), msg, signature) == ["true"]
        assert Curve.verify_signature(pair.public_key, msg, signature)
        assert java.call("verify", pair.public_key.serialize(), msg + b"x", signature) == ["false"]


def test_native_vrf_differential(native_java):
    rows = json.loads((Path(__file__).parents[1] / "vectors/native-vrf.json").read_text())
    for row in rows:
        v = {k: bytes.fromhex(x) for k, x in row.items()}
        assert native_java.raw("vrfSign", v["private"], v["message"], v["random"]) == v["signature"]
        assert (
            native_java.raw("vrfVerify", v["public"][1:], v["message"], v["signature"])
            == v["output"]
        )
        assert (
            Curve.calculate_vrf_signature(
                ECPrivateKey(v["private"]), v["message"], random=v["random"]
            )
            == v["signature"]
        )
        assert (
            Curve.verify_vrf_signature(
                Curve.decode_point(v["public"]), v["message"], v["signature"]
            )
            == v["output"]
        )


@pytest.mark.parametrize("initiator", ["python", "java"])
@pytest.mark.parametrize("one_time", [True, False])
def test_prekey_ratchet_bidirectional(java, initiator, one_time):
    name = f"{initiator}-{one_time}"
    ji, jreg, jpre, jsigned = remote_material(java, name)
    ps = InMemorySignalProtocolStore()
    pc = SessionCipher(ps, REMOTE)
    if initiator == "python":
        SessionBuilder(ps, REMOTE).process(
            PreKeyBundle(
                jreg,
                1,
                jpre.id,
                jpre.key_pair.public_key if one_time else None,
                jsigned.id,
                jsigned.key_pair.public_key,
                jsigned.signature,
                ji.public_key,
            )
        )
        send_python(java, name, pc, b"Python initial")
        assert java.call("hasPreKey", name, jpre.id) == [str(not one_time).lower()]
    else:
        pre = KeyHelper.generate_pre_keys(7, 1)[0]
        signed = KeyHelper.generate_signed_pre_key(ps.identity_key_pair, 8)
        ps.store_pre_key(7, pre)
        ps.store_signed_pre_key(8, signed)
        java.call(
            "bundle",
            name,
            ps.identity_key_pair.public_key.serialize(),
            ps.registration_id,
            pre.serialize(),
            signed.serialize(),
            "yes" if one_time else "none",
        )
        assert decrypt_python(pc, java.call("encrypt", name, b"Java initial")) == b"Java initial"
        assert ps.contains_pre_key(7) == (not one_time)
    for turn in range(5):
        pending_python = [
            (f"python {turn}/{i}".encode(), pc.encrypt(f"python {turn}/{i}".encode()))
            for i in range(6)
        ]
        for plain, msg in reversed(pending_python):
            assert java.raw("decrypt", name, msg.type, msg.serialize()) == plain
        pending_java = [
            (f"java {turn}/{i}".encode(), java.call("encrypt", name, f"java {turn}/{i}".encode()))
            for i in range(6)
        ]
        for plain, msg in reversed(pending_java):
            assert decrypt_python(pc, msg) == plain
    # Move both sides' live state across the language boundary, then continue.
    python_state = ps.load_session(REMOTE).serialize()
    java_state = java.raw("session", name)
    assert java.raw("roundtrip", "session", python_state) == python_state
    assert SessionRecord(java_state).serialize() == java_state
    shadow = name + "-shadow"
    java.call("init", shadow, ps.identity_key_pair.serialize())
    java.call("loadSession", shadow, python_state)
    python_as_java = InMemorySignalProtocolStore(ji, jreg)
    python_as_java.store_session(REMOTE, SessionRecord(java_state))
    receiver = SessionCipher(python_as_java, REMOTE)
    text = b"exact ciphertext from identical serialized state"
    java_message = java.call("encrypt", shadow, text)
    python_message = pc.encrypt(text)
    assert int(java_message[0]) == python_message.type
    assert base64.b64decode(java_message[1]) == python_message.serialize()
    assert receiver.decrypt(parse_message(python_message.type, python_message.serialize())) == text
    assert java.raw("session", shadow) == ps.load_session(REMOTE).serialize()


def test_group_both_directions_and_state(java):
    # Java sender -> Python receiver.
    distribution = java.raw("groupInit", "jgroup")
    ps = InMemorySenderKeyStore()
    GroupSessionBuilder(ps).process(NAME, SenderKeyDistributionMessage.from_bytes(distribution))
    pc = GroupCipher(ps, NAME)
    messages = [java.raw("groupEncrypt", "jgroup", f"java {i}".encode()) for i in range(20)]
    for i in reversed(range(20)):
        assert pc.decrypt(messages[i]) == f"java {i}".encode()
    state = java.raw("groupRecord", "jgroup")
    assert SenderKeyRecord(state).serialize() == state
    # Python sender -> Java receiver; verify signed envelope & record formats.
    send_store = InMemorySenderKeyStore()
    dist = GroupSessionBuilder(send_store).create(NAME)
    java.call("groupProcess", "pgroup", dist.serialize())
    sender = GroupCipher(send_store, NAME)
    pending = [sender.encrypt(f"python {i}".encode()) for i in range(20)]
    for i in reversed(range(20)):
        assert java.raw("groupDecrypt", "pgroup", pending[i]) == f"python {i}".encode()
    python_state = send_store.load_sender_key(NAME).serialize()
    assert java.raw("roundtrip", "sender", python_state) == python_state
    assert java.raw("roundtrip", "distribution", dist.serialize()) == dist.serialize()
    assert java.raw("roundtrip", "sender_message", pending[0]) == pending[0]
    # Same chain state yields same ciphertext body; signatures intentionally random.
    java.call("groupLoad", "clone", python_state)
    j = SenderKeyMessage.from_bytes(java.raw("groupEncrypt", "clone", b"clone"))
    p = SenderKeyMessage.from_bytes(sender.encrypt(b"clone"))
    assert (j.key_id, j.iteration, j.ciphertext) == (p.key_id, p.iteration, p.ciphertext)
    public = send_store.load_sender_key(NAME).get_sender_key_state().signing_key_public
    j.verify_signature(public)
    p.verify_signature(public)
    assert java.raw("groupRecord", "clone") == send_store.load_sender_key(NAME).serialize()


def test_records_and_unknown_fields(java):
    identity = KeyHelper.generate_identity_key_pair()
    pre = KeyHelper.generate_pre_keys(0xFFFFFE, 1)[0]
    signed = KeyHelper.generate_signed_pre_key(identity, 24)
    for kind, record, load in [
        ("identity", identity, IdentityKeyPair.from_bytes),
        ("prekey", pre, PreKeyRecord.from_bytes),
        ("signed", signed, SignedPreKeyRecord.from_bytes),
    ]:
        raw = record.serialize()
        assert java.raw("roundtrip", kind, raw) == raw
        assert load(raw).serialize() == raw
        unknown = raw + b"\xa0\x06\x07"  # unknown field 100, varint 7
        assert java.raw("roundtrip", kind, unknown) == load(unknown).serialize()
    state = SessionState()
    state.set_pending_key_exchange(
        3, Curve.generate_key_pair(), Curve.generate_key_pair(), identity
    )
    state.session_version = 3
    state.local_identity_key = identity.public_key
    state.local_registration_id = 16380
    raw = state.serialize() + b"\xa0\x06\x07"
    assert java.raw("roundtrip", "state", raw) == SessionState(raw).serialize()
    for kind, record, load in [
        ("session", SessionRecord(state), SessionRecord),
        ("sender", SenderKeyRecord(), SenderKeyRecord),
    ]:
        raw = record.serialize() + b"\xa0\x06\x07"
        assert java.raw("roundtrip", kind, raw) == load(raw).serialize()


def test_multi_identity_fingerprints(java):
    local = [KeyHelper.generate_identity_key_pair().public_key for _ in range(3)]
    remote = [KeyHelper.generate_identity_key_pair().public_key for _ in range(4)]
    j = java.call(
        "fingerprint",
        2,
        b"local",
        ",".join(base64.b64encode(k.serialize()).decode() for k in local),
        b"remote",
        ",".join(base64.b64encode(k.serialize()).decode() for k in remote),
    )
    p = NumericFingerprintGenerator(1024).create_for(2, b"local", local, b"remote", remote)
    assert j[0] == p.displayable.get_display_text()
    assert base64.b64decode(j[1]) == p.scannable.serialize()


def test_native_signature_provider_interoperability(native_java):
    for _ in range(8):
        pair = Curve.generate_key_pair()
        message = secrets.token_bytes(97)
        native_sig = native_java.raw(
            "nativeSign", pair.private_key.key, message, secrets.token_bytes(64)
        )
        assert Curve.verify_signature(pair.public_key, message, native_sig)
        python_sig = Curve.calculate_signature(pair.private_key, message)
        assert native_java.call("verify", pair.public_key.serialize(), message, python_sig) == [
            "true"
        ]


def test_legacy_signature_acceptance_matches_java(java):
    # Ref10 permits S+L when the top-three-bit guard still holds. Do not silently
    # replace this with the stricter acceptance policy of modern Ed25519 APIs.
    pair = Curve.generate_key_pair()
    message = b"legacy scalar encoding"
    signature = Curve.calculate_signature(pair.private_key, message)
    scalar = int.from_bytes(signature[32:63] + bytes([signature[63] & 127]), "little")
    order = 2**252 + 27742317777372353535851937790883648493
    altered_s = bytearray((scalar + order).to_bytes(32, "little"))
    altered_s[31] |= signature[63] & 128
    altered = signature[:32] + bytes(altered_s)
    assert java.call("verify", pair.public_key.serialize(), message, altered) == ["true"]
    assert Curve.verify_signature(pair.public_key, message, altered)
    # Small-order public points use upstream full-group verification semantics.
    for u in (0, 1, 2**255 - 20):
        public = Curve.decode_point(b"\x05" + u.to_bytes(32, "little"))
        for proof in (signature, b"\x01" + bytes(63), bytes(64)):
            expected = java.call("verify", public.serialize(), message, proof) == ["true"]
            assert Curve.verify_signature(public, message, proof) == expected
