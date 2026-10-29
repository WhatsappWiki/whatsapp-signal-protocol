"""All numeric-fingerprint and device-consistency JUnit cases."""

import json
import random
from pathlib import Path

from signal_protocol import IdentityKey, KeyHelper
from signal_protocol.devices import (
    DeviceConsistencyCodeGenerator,
    DeviceConsistencyCommitment,
    DeviceConsistencyMessage,
)
from signal_protocol.fingerprint import NumericFingerprintGenerator

VECTORS = json.loads((Path(__file__).parent / "vectors/fingerprints.json").read_text())
A_ID, B_ID = b"+14152222222", b"+14153333333"


def fingerprints(version=1, fixed=False, bad_key=False, bad_id=False):
    if fixed:
        a = IdentityKey.from_bytes(bytes.fromhex(VECTORS["ALICE_IDENTITY"]))
        b = IdentityKey.from_bytes(bytes.fromhex(VECTORS["BOB_IDENTITY"]))
    else:
        a, b = (
            KeyHelper.generate_identity_key_pair().public_key,
            KeyHelper.generate_identity_key_pair().public_key,
        )
    mitm = KeyHelper.generate_identity_key_pair().public_key if bad_key else b
    generator = NumericFingerprintGenerator(5200 if fixed else 1024)
    return (
        generator.create_for(version, b"+141512222222" if bad_id else A_ID, a, B_ID, mitm),
        generator.create_for(version, B_ID, b, A_ID, a),
    )


class TestNumericFingerprintGenerator:
    def check_vectors(self, version):
        a, b = fingerprints(version, fixed=True)
        assert a.displayable.get_display_text() == VECTORS["DISPLAYABLE_FINGERPRINT_V1"]
        assert b.displayable.get_display_text() == VECTORS["DISPLAYABLE_FINGERPRINT_V1"]
        assert a.scannable.serialize().hex() == VECTORS[f"ALICE_SCANNABLE_FINGERPRINT_V{version}"]
        assert b.scannable.serialize().hex() == VECTORS[f"BOB_SCANNABLE_FINGERPRINT_V{version}"]

    def testVectorsVersion1(self):
        self.check_vectors(1)

    def testVectorsVersion2(self):
        self.check_vectors(2)

    def testMatchingFingerprints(self):
        a, b = fingerprints()
        assert a.displayable.get_display_text() == b.displayable.get_display_text()
        assert len(a.displayable.get_display_text()) == 60
        assert a.scannable.compare_to(b.scannable.serialize())
        assert b.scannable.compare_to(a.scannable.serialize())

    def testMismatchingFingerprints(self):
        a, b = fingerprints(bad_key=True)
        assert a.displayable.get_display_text() != b.displayable.get_display_text()
        assert not a.scannable.compare_to(b.scannable.serialize())
        assert not b.scannable.compare_to(a.scannable.serialize())

    def testMismatchingIdentifiers(self):
        a, b = fingerprints(bad_id=True)
        assert a.displayable.get_display_text() != b.displayable.get_display_text()
        assert not a.scannable.compare_to(b.scannable.serialize())
        assert not b.scannable.compare_to(a.scannable.serialize())

    def testDifferentVersionsMakeSameFingerPrintsButDifferentScannable(self):
        v1, _ = fingerprints(1, fixed=True)
        v2, _ = fingerprints(2, fixed=True)
        assert v1.displayable.get_display_text() == v2.displayable.get_display_text()
        assert v1.scannable.serialize() != v2.scannable.serialize()


class TestDeviceConsistency:
    def testDeviceConsistency(self):
        devices = [KeyHelper.generate_identity_key_pair() for _ in range(3)]
        keys = [d.public_key for d in devices]
        commitments = []
        for i in range(3):
            random.Random(i).shuffle(keys)
            commitments.append(DeviceConsistencyCommitment(1, keys))
        assert (
            commitments[0].serialize() == commitments[1].serialize() == commitments[2].serialize()
        )
        messages = [DeviceConsistencyMessage(commitments[0], d) for d in devices]
        received = [
            DeviceConsistencyMessage.from_bytes(commitments[0], m.serialize(), d.public_key)
            for m, d in zip(messages, devices)
        ]
        for m, r in zip(messages, received):
            assert m.signature.vrf_output == r.signature.vrf_output
        codes = []
        for i in range(3):
            signatures = [messages[i].signature] + [
                received[j].signature for j in range(3) if j != i
            ]
            codes.append(DeviceConsistencyCodeGenerator.generate_for(commitments[i], signatures))
        assert codes[0] == codes[1] == codes[2]
