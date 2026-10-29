"""Replay original APK PreKey receive and cipher bytes without a phone."""

import base64
import json
from pathlib import Path

import pytest

from signal_protocol import (
    WHATSAPP,
    ECPrivateKey,
    ECPublicKey,
    IdentityKey,
    IdentityKeyPair,
    InMemorySignalProtocolStore,
    KyberPreKeyRecord,
    PreKeyRecord,
    PreKeySignalMessage,
    SessionCipher,
    SessionRecord,
    SignalMessage,
    SignalProtocolAddress,
    SignedPreKeyRecord,
)

DATA = json.loads((Path(__file__).parent / "vectors/whatsapp-v4-ciphers.json").read_text())
CORE = json.loads((Path(__file__).parent / "vectors/protocol-core-runtime.json").read_text())
CASES = DATA["cases"] + CORE["ciphers"]
decode = base64.b64decode


@pytest.mark.parametrize(
    "row",
    CASES,
    ids=[f"{r['request']['id']}-{r['request']['op']}-{i}" for i, r in enumerate(CASES)],
)
def test_actual_whatsapp_cipher(row):
    source, request, expected = row["store"], row["request"], row["expected"]
    identity = IdentityKeyPair(
        IdentityKey(ECPublicKey(decode(source["identity_public"]))),
        ECPrivateKey(decode(source["identity_private"])),
    )
    store = InMemorySignalProtocolStore(identity, source["registration_id"])
    address = SignalProtocolAddress("captured-synthetic-peer", 1)
    for key, value in source.get("prekeys", {}).items():
        store.store_pre_key(int(key), PreKeyRecord.from_bytes(decode(value)))
    for key, value in source.get("signed_prekeys", {}).items():
        store.store_signed_pre_key(int(key), SignedPreKeyRecord.from_bytes(decode(value)))
    for key, value in source.get("kem_prekeys", {}).items():
        store.store_kyber_pre_key(int(key), KyberPreKeyRecord.from_bytes(decode(value)))
    if source.get("record") is not None:
        store.store_session(address, SessionRecord(decode(source["record"]), profile=WHATSAPP))
    cipher = SessionCipher(store, address, profile=WHATSAPP)
    if request["op"] == "encrypt":
        message = cipher.encrypt(decode(request["message"]))
        assert message.type == expected["message_type"]
        assert message.serialize() == decode(expected["message"])
        assert store.load_session(address).serialize() == decode(expected["record"])
    else:
        cls = PreKeySignalMessage if request["message_type"] == 3 else SignalMessage
        plaintext = cipher.decrypt(cls.from_bytes(decode(request["message"]), profile=WHATSAPP))
        assert plaintext == decode(expected["plaintext"])
        # Fresh receiver ratchet RNG is independent; compare plaintext and key use.
        assert set(store.pre_keys) == set(expected["prekey_ids"])
        assert set(store.kyber_pre_keys) == set(expected["kem_prekey_ids"])
