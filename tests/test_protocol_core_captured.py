"""Replay primitive, parser and state results produced by the actual APK engine."""

import base64
import json
from pathlib import Path

import pytest

from signal_protocol import (
    WHATSAPP,
    Curve,
    ECPrivateKey,
    ECPublicKey,
    PreKeyRecord,
    PreKeySignalMessage,
    SessionRecord,
    SignalMessage,
    SignedPreKeyRecord,
)
from signal_protocol.exceptions import InvalidKeyException, InvalidMessageException
from signal_protocol.groups import (
    GroupCipher,
    GroupSessionBuilder,
    InMemorySenderKeyStore,
    SenderKeyName,
    SenderKeyRecord,
)
from signal_protocol.kem import KemKeyPair, KemKeyType, KemSecretKey
from signal_protocol.protocol import SenderKeyDistributionMessage, SenderKeyMessage
from tests.helpers import BOB

DATA = json.loads((Path(__file__).parent / "vectors/protocol-core-runtime.json").read_text())
ROWS = DATA["core"]
decode = base64.b64decode
PARSERS = {
    "signal": SignalMessage,
    "prekey": PreKeySignalMessage,
    "group": SenderKeyMessage,
    "distribution": SenderKeyDistributionMessage,
}


@pytest.mark.parametrize("row", ROWS, ids=[f"{r['request']['op']}-{i}" for i, r in enumerate(ROWS)])
def test_actual_engine_primitive_and_boundary(row):
    q, r = row["request"], row["response"]
    op = q["op"]
    if op == "core-dh":
        public, private = ECPublicKey(decode(q["public"])), ECPrivateKey(decode(q["private"]))
        if r["ok"]:
            assert Curve.calculate_agreement(public, private, profile=WHATSAPP) == decode(
                r["value"]
            )
        else:
            with pytest.raises(InvalidKeyException):
                Curve.calculate_agreement(public, private, profile=WHATSAPP)
    elif op == "core-verify":
        assert (
            Curve.verify_signature(
                ECPublicKey(decode(q["public"])), decode(q["message"]), decode(q["signature"])
            )
            is r["value"]
        )
    elif op == "core-parse":
        cls = PARSERS[q["kind"]]
        if r["ok"]:
            assert cls.from_bytes(decode(q["message"]), profile=WHATSAPP).serialize() == decode(
                r["value"]
            )
        else:
            with pytest.raises(InvalidMessageException):
                cls.from_bytes(decode(q["message"]), profile=WHATSAPP)
    elif op == "core-record":
        cls = {
            "session": SessionRecord,
            "group": SenderKeyRecord,
            "prekey": PreKeyRecord,
            "signed": SignedPreKeyRecord,
        }[q["kind"]]
        record = (
            cls.from_bytes(decode(q["record"]), profile=WHATSAPP)
            if q["kind"] in ("prekey", "signed")
            else cls(decode(q["record"]), profile=WHATSAPP)
        )
        assert record.serialize() == decode(r["value"])
    elif op == "core-archive":
        record = SessionRecord(decode(q["record"]), profile=WHATSAPP)
        record.archive_current_state()
        assert record.serialize() == decode(r["value"])
    elif op == "core-group":
        name = SenderKeyName("synthetic-group", BOB)
        store = InMemorySenderKeyStore()
        record = SenderKeyRecord(decode(q["record"]), profile=WHATSAPP)
        store.store_sender_key(name, record)
        cipher, expected = GroupCipher(store, name, profile=WHATSAPP), r["value"]
        if q["action"] == "encrypt":
            ours = SenderKeyMessage.from_bytes(
                cipher.encrypt(decode(q["message"])), profile=WHATSAPP
            )
            native = SenderKeyMessage.from_bytes(decode(expected["data"]), profile=WHATSAPP)
            assert (ours.key_id, ours.iteration, ours.ciphertext) == (
                native.key_id,
                native.iteration,
                native.ciphertext,
            )
            native.verify_signature(record.get_sender_key_state().signing_key_public)
        elif q["action"] == "decrypt":
            assert cipher.decrypt(decode(q["message"])) == decode(expected["data"])
        else:
            assert q["action"] == "distribution"
            message = SenderKeyDistributionMessage.from_bytes(
                decode(q["message"]), profile=WHATSAPP
            )
            GroupSessionBuilder(store, profile=WHATSAPP).process(name, message)
        assert store.load_sender_key(name).serialize() == decode(expected["record"])
    elif op == "kem-generate":
        pair = KemKeyPair.generate(KemKeyType[q["type"]], seed=decode(q["seed"]))
        assert pair.public_key.serialize() == decode(r["value"]["public"])
        assert pair.secret_key.serialize() == decode(r["value"]["private"])
    elif op == "kem-encapsulate":
        source = next(
            x
            for x in ROWS
            if x["request"]["op"] == "kem-generate"
            and x["response"]["value"]["public"] == q["public"]
        )
        key = KemSecretKey.from_bytes(decode(source["response"]["value"]["private"]))
        assert key.decapsulate(decode(r["value"]["ciphertext"])) == decode(r["value"]["secret"])
    else:
        assert op == "kem-decapsulate"
        key = KemSecretKey.from_bytes(decode(q["private"]))
        assert key.decapsulate(decode(q["ciphertext"])) == decode(r["value"])
