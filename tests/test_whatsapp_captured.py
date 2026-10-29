"""Offline differential replay of synthetic inputs processed inside WhatsApp.

The fixture contains no real account keys or conversations. Passing the explicit
gap tests means the recorded difference still exists; it does not mean v4 support.
"""

import json
from base64 import b64decode as dec
from pathlib import Path

import pytest
from nacl import bindings

from signal_protocol import (
    WHATSAPP,
    Curve,
    ECPrivateKey,
    ECPublicKey,
    IdentityKey,
    InMemorySignalProtocolStore,
    PreKeySignalMessage,
    SessionCipher,
    SessionRecord,
    SignalMessage,
    SignalProtocolAddress,
)
from signal_protocol.exceptions import (
    InvalidMessageException,
    InvalidVersionException,
    LegacyMessageException,
)
from signal_protocol.groups import (
    GroupCipher,
    InMemorySenderKeyStore,
    SenderKeyName,
    SenderKeyRecord,
)
from signal_protocol.kdf import HKDF
from signal_protocol.protocol import SenderKeyDistributionMessage, SenderKeyMessage
from signal_protocol.ratchet import ChainKey

FIXTURE = json.loads((Path(__file__).parent / "vectors/whatsapp-runtime.json").read_text())
CORE = [row for row in FIXTURE["core"] if row["request"]["op"] != "info"]
GAPS = [
    row for row in FIXTURE["boundaries"] if row["request"]["op"] in ("strict", "parse", "archive")
]


@pytest.mark.parametrize("row", CORE, ids=[f"{r['request']['op']}-{i}" for i, r in enumerate(CORE)])
def test_captured_whatsapp_core(row):
    q, response = row["request"], row["response"]
    assert response["ok"]
    actual, op = response["value"], q["op"]
    if op == "dh":
        assert Curve.calculate_agreement(
            ECPublicKey(dec(q["public"])), ECPrivateKey(dec(q["private"]))
        ) == dec(actual)
    elif op == "sign":
        private = dec(q["private"])
        public = ECPublicKey(bindings.crypto_scalarmult_base(private))
        assert Curve.verify_signature(public, dec(q["message"]), dec(actual))
    elif op == "verify":
        assert (
            Curve.verify_signature(
                ECPublicKey(dec(q["public"])), dec(q["message"]), dec(q["signature"])
            )
            == actual
        )
    elif op == "vrf":
        private, public, message = (
            ECPrivateKey(dec(q["private"])),
            ECPublicKey(dec(q["public"])),
            dec(q["message"]),
        )
        assert Curve.calculate_vrf_signature(private, message, random=dec(q["random"])) == dec(
            actual["signature"]
        )
        assert Curve.verify_vrf_signature(public, message, dec(actual["signature"])) == dec(
            actual["output"]
        )
    elif op == "chain":
        # WhatsApp v4 uses the v3 chain KDF after hybrid initialisation.
        key = ChainKey(HKDF(3), dec(q["seed"]), q["index"]).message_keys()
        assert (key.cipher_key, key.mac_key, key.iv) == tuple(
            dec(actual[k]) for k in ("cipher", "mac", "iv")
        )
    elif op == "signal":
        message = SignalMessage(
            q["version"],
            dec(q["mac"]),
            ECPublicKey(dec(q["ratchet"])),
            q["counter"],
            q["previous"],
            dec(q["body"]),
            IdentityKey(ECPublicKey(dec(q["sender"]))),
            IdentityKey(ECPublicKey(dec(q["receiver"]))),
        )
        assert message.serialize() == dec(actual)
    elif op == "parse":
        cls = {
            "signal": SignalMessage,
            "prekey": PreKeySignalMessage,
            "group": SenderKeyMessage,
            "distribution": SenderKeyDistributionMessage,
        }[q["kind"]]
        assert cls.from_bytes(dec(q["message"])).serialize() == dec(actual)
    elif op == "record":
        cls = SessionRecord if q["kind"] == "session" else SenderKeyRecord
        assert cls(dec(q["record"])).serialize() == dec(actual)
    elif op == "session":
        store, address = InMemorySignalProtocolStore(), SignalProtocolAddress("synthetic-peer", 1)
        store.store_session(address, SessionRecord(dec(q["record"])))
        cipher = SessionCipher(store, address)
        if q["action"] == "encrypt":
            assert cipher.encrypt(dec(q["message"])).serialize() == dec(actual["data"])
            assert store.load_session(address).serialize() == dec(actual["record"])
        else:
            assert cipher.decrypt(SignalMessage.from_bytes(dec(q["message"]))) == dec(
                actual["data"]
            )
    elif op == "group":
        store = InMemorySenderKeyStore()
        name = SenderKeyName("synthetic-group", SignalProtocolAddress("synthetic-peer", 1))
        store.store_sender_key(name, SenderKeyRecord(dec(q["record"])))
        cipher = GroupCipher(store, name)
        if q["action"] == "encrypt":
            expected = SenderKeyMessage.from_bytes(dec(actual["data"]))
            key = store.load_sender_key(name).get_sender_key_state().signing_key_public
            expected.verify_signature(key)
            generated = SenderKeyMessage.from_bytes(cipher.encrypt(dec(q["message"])))
            assert (generated.key_id, generated.iteration, generated.ciphertext) == (
                expected.key_id,
                expected.iteration,
                expected.ciphertext,
            )
        else:
            assert cipher.decrypt(dec(q["message"])) == dec(actual["data"])
        assert store.load_sender_key(name).serialize() == dec(actual["record"])
    elif op == "padding":
        padded, raw = dec(actual), dec(q["message"])
        n = padded[-1]
        assert 1 <= n <= 16 and padded == raw + bytes([n]) * n
    else:
        raise AssertionError(op)


@pytest.mark.parametrize("row", GAPS, ids=[f"{r['request']['op']}-{i}" for i, r in enumerate(GAPS)])
def test_recorded_compatibility_gap(row):
    q, response = row["request"], row["response"]
    if q["op"] == "strict":
        public = dec(q["public"])
        Curve.decode_point(public)
        expected_accepts = not q["strict"] or public not in (
            b"\x05" + bytes(32),
            b"\x05" + (2**255 - 19).to_bytes(32, "little"),
            b"\x05" + bytes(31) + b"\x80",
        )
        assert response["ok"] == expected_accepts
    elif q["op"] == "archive":
        assert response["ok"]
        native = SessionRecord(dec(response["value"]))
        python = SessionRecord(dec(q["record"]))
        python.archive_current_state()
        assert not native.previous_states[0].has_unacknowledged_pre_key_message()
        assert python.previous_states[0].has_unacknowledged_pre_key_message()
    elif q["kind"] == "signal":
        assert response["ok"]
        message = dec(q["message"])
        if message[0] >> 4 == 3:
            SignalMessage.from_bytes(message)
        else:
            expected = LegacyMessageException if message[0] >> 4 == 2 else InvalidMessageException
            with pytest.raises(expected):
                SignalMessage.from_bytes(message)
    else:
        message = dec(q["message"])
        if not response["ok"]:
            assert "Incomplete message" in response["error"]
            PreKeySignalMessage.from_bytes(message)
        elif message[0] >> 4 == 4:
            with pytest.raises(InvalidVersionException):
                PreKeySignalMessage.from_bytes(message)
        else:
            PreKeySignalMessage.from_bytes(message)


@pytest.mark.parametrize("row", GAPS, ids=[f"{r['request']['op']}-{i}" for i, r in enumerate(GAPS)])
def test_whatsapp_policy_matches_recorded_boundaries(row):
    from signal_protocol.whatsapp import decode_identity_key

    q, response = row["request"], row["response"]
    if q["op"] == "strict":
        if response["ok"]:
            decode_identity_key(dec(q["public"]), strict=q["strict"])
        else:
            with pytest.raises(ValueError):
                decode_identity_key(dec(q["public"]), strict=q["strict"])
    elif q["op"] == "archive":
        record = SessionRecord(dec(q["record"]), profile=WHATSAPP)
        record.archive_current_state()
        assert record.serialize() == dec(response["value"])
    else:
        cls = SignalMessage if q["kind"] == "signal" else PreKeySignalMessage
        if response["ok"]:
            assert cls.from_bytes(dec(q["message"]), profile=WHATSAPP).serialize() == dec(
                response["value"]
            )
        else:
            with pytest.raises(InvalidMessageException):
                cls.from_bytes(dec(q["message"]), profile=WHATSAPP)
