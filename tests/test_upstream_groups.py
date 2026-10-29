"""All nine GroupCipherTest scenarios."""

import random
import secrets

import pytest

from signal_protocol import SignalProtocolAddress
from signal_protocol.exceptions import (
    DuplicateMessageException,
    InvalidMessageException,
    NoSessionException,
)
from signal_protocol.groups import (
    GroupCipher,
    GroupSessionBuilder,
    InMemorySenderKeyStore,
    SenderKeyName,
)
from signal_protocol.protocol import SenderKeyDistributionMessage

NAME = SenderKeyName("nihilist history reading group", SignalProtocolAddress("+14150001111", 1))


def peers(deliver=True):
    a, b = InMemorySenderKeyStore(), InMemorySenderKeyStore()
    ab, bb = GroupSessionBuilder(a), GroupSessionBuilder(b)
    ac, bc = GroupCipher(a, NAME), GroupCipher(b, NAME)
    distribution = SenderKeyDistributionMessage.from_bytes(ab.create(NAME).serialize())
    if deliver:
        bb.process(NAME, distribution)
    return a, b, ab, bb, ac, bc


class TestGroupCipher:
    def testNoSession(self):
        _, _, _, _, ac, bc = peers(False)
        ciphertext = ac.encrypt(b"smert ze smert")
        with pytest.raises(NoSessionException):
            bc.decrypt(ciphertext)

    def testBasicEncryptDecrypt(self):
        _, _, _, _, ac, bc = peers()
        assert bc.decrypt(ac.encrypt(b"smert ze smert")) == b"smert ze smert"

    def testLargeMessages(self):
        _, _, _, _, ac, bc = peers()
        plaintext = secrets.token_bytes(1024 * 1024)
        assert bc.decrypt(ac.encrypt(plaintext)) == plaintext

    def testBasicRatchet(self):
        _, _, _, _, ac, bc = peers()
        plaintexts = [b"smert ze smert", b"smert ze smert2", b"smert ze smert3"]
        messages = [ac.encrypt(p) for p in plaintexts]
        assert bc.decrypt(messages[0]) == plaintexts[0]
        with pytest.raises(DuplicateMessageException):
            bc.decrypt(messages[0])
        assert bc.decrypt(messages[1]) == plaintexts[1]
        assert bc.decrypt(messages[2]) == plaintexts[2]

    def testLateJoin(self):
        _, _, ab, bb, ac, bc = peers(False)
        for _ in range(100):
            ac.encrypt(b"up the punks up the punks up the punks")
        bb.process(NAME, SenderKeyDistributionMessage.from_bytes(ab.create(NAME).serialize()))
        assert bc.decrypt(ac.encrypt(b"welcome to the group")) == b"welcome to the group"

    def testOutOfOrder(self):
        _, _, _, _, ac, bc = peers()
        ciphertexts = [ac.encrypt(b"up the punks") for _ in range(100)]
        random.Random(42).shuffle(ciphertexts)
        for ciphertext in ciphertexts:
            assert bc.decrypt(ciphertext) == b"up the punks"

    def testEncryptNoSession(self):
        cipher = GroupCipher(InMemorySenderKeyStore(), NAME)
        with pytest.raises(NoSessionException):
            cipher.encrypt(b"up the punks")

    def testTooFarInFuture(self):
        _, _, _, _, ac, bc = peers()
        for _ in range(2001):
            ac.encrypt(b"up the punks")
        with pytest.raises(InvalidMessageException):
            bc.decrypt(ac.encrypt(b"notta gonna worka"))

    def testMessageKeyLimit(self):
        _, _, _, _, ac, bc = peers()
        inflight = [ac.encrypt(b"up the punks") for _ in range(2010)]
        bc.decrypt(inflight[1000])
        bc.decrypt(inflight[-1])
        with pytest.raises(DuplicateMessageException):
            bc.decrypt(inflight[0])
