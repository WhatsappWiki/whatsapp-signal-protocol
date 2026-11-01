"""Multi-device consistency commitments, signatures, and six-digit codes."""

from dataclasses import dataclass
from hashlib import sha512

from google.protobuf.message import DecodeError

from signal_protocol.ecc import Curve
from signal_protocol.exceptions import (
    InvalidKeyException,
    InvalidMessageException,
    VrfSignatureVerificationFailedException,
)
from signal_protocol.integers import uint32
from signal_protocol.protobuf import WhisperTextProtocol_pb2 as pb

__all__ = [
    "DeviceConsistencyCommitment",
    "DeviceConsistencySignature",
    "DeviceConsistencyMessage",
    "DeviceConsistencyCodeGenerator",
]


class DeviceConsistencyCommitment:
    def __init__(self, generation, identity_keys):
        self.generation = uint32(generation)
        data = b"DeviceConsistencyCommitment_V0" + (generation & 0xFFFFFFFF).to_bytes(4, "big")
        self.serialized = sha512(
            data + b"".join(sorted(k.serialize() for k in identity_keys))
        ).digest()

    def serialize(self):
        return self.serialized


@dataclass(frozen=True)
class DeviceConsistencySignature:
    signature: bytes
    vrf_output: bytes


class DeviceConsistencyMessage:
    def __init__(self, commitment, identity):
        signature = Curve.calculate_vrf_signature(identity.private_key, commitment.serialize())
        output = Curve.verify_vrf_signature(
            identity.public_key.public_key, commitment.serialize(), signature
        )
        self.generation = commitment.generation
        self.signature = DeviceConsistencySignature(signature, output)
        self.serialized = pb.DeviceConsistencyCodeMessage(
            generation=self.generation, signature=signature
        ).SerializeToString()

    def serialize(self):
        return self.serialized

    @classmethod
    def from_bytes(cls, commitment, serialized, identity):
        try:
            p = pb.DeviceConsistencyCodeMessage.FromString(serialized)
            output = Curve.verify_vrf_signature(
                identity.public_key, commitment.serialize(), p.signature
            )
        except (DecodeError, InvalidKeyException, VrfSignatureVerificationFailedException) as exc:
            raise InvalidMessageException(str(exc)) from exc
        obj = cls.__new__(cls)
        obj.generation, obj.serialized = p.generation, bytes(serialized)
        obj.signature = DeviceConsistencySignature(p.signature, output)
        return obj


class DeviceConsistencyCodeGenerator:
    @staticmethod
    def generate_for(commitment, signatures):
        data = (
            b"\x00\x00"
            + commitment.serialize()
            + b"".join(sorted(s.vrf_output for s in signatures))
        )
        digest = sha512(data).digest()
        return "".join(f"{int.from_bytes(digest[i : i + 5], 'big') % 100000:05d}" for i in (0, 5))[
            :6
        ]
