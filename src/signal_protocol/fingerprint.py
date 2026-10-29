"""Numeric safety numbers and QR fingerprint comparison."""

from dataclasses import dataclass
from hashlib import sha512
from hmac import compare_digest

from google.protobuf.message import DecodeError

from .exceptions import FingerprintParsingException, FingerprintVersionMismatchException
from .integers import uint32
from .keys import IdentityKey
from .protobuf import FingerprintProtocol_pb2 as pb


def digits(data):
    return "".join(
        f"{int.from_bytes(data[i : i + 5], 'big') % 100000:05d}" for i in range(0, 30, 5)
    )


class DisplayableFingerprint:
    def __init__(self, local, remote):
        self.local_fingerprint_numbers = digits(local)
        self.remote_fingerprint_numbers = digits(remote)

    def get_display_text(self):
        return "".join(sorted((self.local_fingerprint_numbers, self.remote_fingerprint_numbers)))


class ScannableFingerprint:
    def __init__(self, version, local, remote):
        self.version = uint32(version)
        self.fingerprints = pb.CombinedFingerprints(
            version=self.version,
            localFingerprint=pb.LogicalFingerprint(content=local[:32]),
            remoteFingerprint=pb.LogicalFingerprint(content=remote[:32]),
        )

    def serialize(self):
        return self.fingerprints.SerializeToString()

    def compare_to(self, scanned):
        try:
            p = pb.CombinedFingerprints.FromString(scanned)
        except DecodeError as exc:
            raise FingerprintParsingException(str(exc)) from exc
        if (
            not all(p.HasField(f) for f in ("version", "localFingerprint", "remoteFingerprint"))
            or p.version != self.version
        ):
            raise FingerprintVersionMismatchException(p.version, self.version)
        return compare_digest(
            self.fingerprints.localFingerprint.content, p.remoteFingerprint.content
        ) and compare_digest(
            self.fingerprints.remoteFingerprint.content, p.localFingerprint.content
        )


@dataclass(frozen=True)
class Fingerprint:
    displayable: DisplayableFingerprint
    scannable: ScannableFingerprint


class NumericFingerprintGenerator:
    def __init__(self, iterations):
        self.iterations = iterations

    def create_for(self, version, local_identifier, local_keys, remote_identifier, remote_keys):
        local = self._fingerprint(local_identifier, local_keys)
        remote = self._fingerprint(remote_identifier, remote_keys)
        return Fingerprint(
            DisplayableFingerprint(local, remote), ScannableFingerprint(version, local, remote)
        )

    def _fingerprint(self, identifier, keys):
        if isinstance(keys, IdentityKey):
            keys = [keys]
        public = b"".join(sorted(k.serialize() for k in keys))
        digest = b"\x00\x00" + public + identifier
        for _ in range(self.iterations):
            digest = sha512(digest + public).digest()
        return digest
