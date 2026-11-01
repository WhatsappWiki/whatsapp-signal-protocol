"""Wire-compatible mutable session state; stores must return independent records."""

from dataclasses import dataclass
from typing import Optional

from signal_protocol.ecc import Curve, ECKeyPair, ECPrivateKey, ECPublicKey
from signal_protocol.exceptions import InvalidKeyException
from signal_protocol.integers import int32, uint32
from signal_protocol.kdf import HKDF
from signal_protocol.keys import IdentityKey, IdentityKeyPair
from signal_protocol.profiles import UPSTREAM, ProtocolProfile
from signal_protocol.protobuf import LocalStorageProtocol_pb2 as pb
from signal_protocol.protobuf_codec import parse_java_protobuf
from signal_protocol.ratchet import ChainKey, MessageKeys, RootKey

__all__ = ["UnacknowledgedPreKeyMessageItems", "SessionState", "SessionRecord"]


@dataclass(frozen=True)
class UnacknowledgedPreKeyMessageItems:
    pre_key_id: Optional[int]
    signed_pre_key_id: int
    base_key: ECPublicKey


class SessionState:
    MAX_MESSAGE_KEYS = 2000

    def __init__(self, source=None, *, profile=UPSTREAM):
        ProtocolProfile(profile)
        self.structure = pb.SessionStructure()
        if isinstance(source, bytes):
            self.structure.CopyFrom(parse_java_protobuf(pb.SessionStructure, source))
        elif source is not None:
            self.structure.CopyFrom(
                source.structure if isinstance(source, SessionState) else source
            )

    def serialize(self):
        return self.structure.SerializeToString()

    @property
    def session_version(self):
        return self.structure.sessionVersion or 2

    @session_version.setter
    def session_version(self, value):
        self.structure.sessionVersion = value

    @property
    def local_identity_key(self):
        return IdentityKey.from_bytes(self.structure.localIdentityPublic)

    @local_identity_key.setter
    def local_identity_key(self, key):
        self.structure.localIdentityPublic = key.serialize()

    @property
    def remote_identity_key(self):
        try:
            return IdentityKey.from_bytes(self.structure.remoteIdentityPublic)
        except InvalidKeyException:
            return None

    @remote_identity_key.setter
    def remote_identity_key(self, key):
        self.structure.remoteIdentityPublic = key.serialize()

    @property
    def root_key(self):
        return RootKey(HKDF(self.session_version), self.structure.rootKey)

    @root_key.setter
    def root_key(self, key):
        self.structure.rootKey = key.key

    @property
    def alice_base_key(self):
        return self.structure.aliceBaseKey

    @alice_base_key.setter
    def alice_base_key(self, key):
        self.structure.aliceBaseKey = key

    @property
    def previous_counter(self):
        return self.structure.previousCounter

    @previous_counter.setter
    def previous_counter(self, value):
        self.structure.previousCounter = uint32(value)

    @property
    def local_registration_id(self):
        return self.structure.localRegistrationId

    @local_registration_id.setter
    def local_registration_id(self, value):
        self.structure.localRegistrationId = uint32(value)

    @property
    def remote_registration_id(self):
        return self.structure.remoteRegistrationId

    @remote_registration_id.setter
    def remote_registration_id(self, value):
        self.structure.remoteRegistrationId = uint32(value)

    def has_sender_chain(self):
        return self.structure.HasField("senderChain")

    @property
    def sender_ratchet_key(self):
        return Curve.decode_point(self.structure.senderChain.senderRatchetKey)

    @property
    def sender_ratchet_key_pair(self):
        return ECKeyPair(
            self.sender_ratchet_key,
            ECPrivateKey(self.structure.senderChain.senderRatchetKeyPrivate),
        )

    @property
    def sender_chain_key(self):
        ck = self.structure.senderChain.chainKey
        return ChainKey(HKDF(self.session_version), ck.key, ck.index)

    @sender_chain_key.setter
    def sender_chain_key(self, key):
        self.structure.senderChain.chainKey.CopyFrom(
            pb.SessionStructure.Chain.ChainKey(index=uint32(key.index), key=key.key)
        )

    def set_sender_chain(self, pair, key):
        self.structure.senderChain.CopyFrom(
            pb.SessionStructure.Chain(
                senderRatchetKey=pair.public_key.serialize(),
                senderRatchetKeyPrivate=pair.private_key.serialize(),
                chainKey=pb.SessionStructure.Chain.ChainKey(index=uint32(key.index), key=key.key),
            )
        )

    def _receiver_chain(self, public):
        for chain in self.structure.receiverChains:
            try:
                if Curve.decode_point(chain.senderRatchetKey) == public:
                    return chain
            except InvalidKeyException:
                continue
        return None

    def has_receiver_chain(self, public):
        return self._receiver_chain(public) is not None

    def add_receiver_chain(self, public, key):
        self.structure.receiverChains.add(
            senderRatchetKey=public.serialize(),
            chainKey=pb.SessionStructure.Chain.ChainKey(index=uint32(key.index), key=key.key),
        )
        if len(self.structure.receiverChains) > 5:
            del self.structure.receiverChains[0]

    def get_receiver_chain_key(self, public):
        chain = self._receiver_chain(public)
        if chain is None:
            return None
        return ChainKey(HKDF(self.session_version), chain.chainKey.key, chain.chainKey.index)

    def set_receiver_chain_key(self, public, key):
        self._receiver_chain(public).chainKey.CopyFrom(
            pb.SessionStructure.Chain.ChainKey(index=uint32(key.index), key=key.key)
        )

    def has_message_keys(self, public, counter):
        counter = uint32(counter)
        chain = self._receiver_chain(public)
        return chain is not None and any(k.index == counter for k in chain.messageKeys)

    def remove_message_keys(self, public, counter):
        counter = uint32(counter)
        chain = self._receiver_chain(public)
        if chain is not None:
            for i, key in enumerate(chain.messageKeys):
                if key.index == counter:
                    result = MessageKeys(key.cipherKey, key.macKey, key.iv, key.index)
                    del chain.messageKeys[i]
                    return result
        return None

    def set_message_keys(self, public, keys):
        chain = self._receiver_chain(public)
        chain.messageKeys.add(
            index=uint32(keys.counter), cipherKey=keys.cipher_key, macKey=keys.mac_key, iv=keys.iv
        )
        if len(chain.messageKeys) > self.MAX_MESSAGE_KEYS:
            del chain.messageKeys[0]

    def set_pending_key_exchange(self, sequence, base, ratchet, identity):
        self.structure.pendingKeyExchange.CopyFrom(
            pb.SessionStructure.PendingKeyExchange(
                sequence=uint32(sequence),
                localBaseKey=base.public_key.serialize(),
                localBaseKeyPrivate=base.private_key.serialize(),
                localRatchetKey=ratchet.public_key.serialize(),
                localRatchetKeyPrivate=ratchet.private_key.serialize(),
                localIdentityKey=identity.public_key.serialize(),
                localIdentityKeyPrivate=identity.private_key.serialize(),
            )
        )

    def has_pending_key_exchange(self):
        return self.structure.HasField("pendingKeyExchange")

    @property
    def pending_key_exchange_sequence(self):
        return self.structure.pendingKeyExchange.sequence

    @property
    def pending_key_exchange_base_key(self):
        p = self.structure.pendingKeyExchange
        return ECKeyPair(Curve.decode_point(p.localBaseKey), ECPrivateKey(p.localBaseKeyPrivate))

    @property
    def pending_key_exchange_ratchet_key(self):
        p = self.structure.pendingKeyExchange
        return ECKeyPair(
            Curve.decode_point(p.localRatchetKey), ECPrivateKey(p.localRatchetKeyPrivate)
        )

    @property
    def pending_key_exchange_identity_key(self):
        p = self.structure.pendingKeyExchange
        return IdentityKeyPair(
            IdentityKey.from_bytes(p.localIdentityKey), ECPrivateKey(p.localIdentityKeyPrivate)
        )

    def set_unacknowledged_pre_key_message(self, pre_key_id, signed_pre_key_id, base_key):
        pending = pb.SessionStructure.PendingPreKey(
            signedPreKeyId=int32(signed_pre_key_id), baseKey=base_key.serialize()
        )
        if pre_key_id is not None:
            pending.preKeyId = uint32(pre_key_id)
        self.structure.pendingPreKey.CopyFrom(pending)

    def has_unacknowledged_pre_key_message(self):
        return self.structure.HasField("pendingPreKey")

    @property
    def unacknowledged_pre_key_message_items(self):
        p = self.structure.pendingPreKey
        return UnacknowledgedPreKeyMessageItems(
            p.preKeyId if p.HasField("preKeyId") else None,
            uint32(p.signedPreKeyId),
            Curve.decode_point(p.baseKey),
        )

    def clear_unacknowledged_pre_key_message(self):
        self.structure.ClearField("pendingPreKey")

    def set_pending_kyber_pre_key(self, id, ciphertext):
        self.structure.pendingKyberPreKey.CopyFrom(
            pb.SessionStructure.PendingKyberPreKey(preKeyId=uint32(id), ciphertext=ciphertext)
        )

    @property
    def pending_kyber_pre_key(self):
        if not self.structure.HasField("pendingKyberPreKey"):
            return None
        pending = self.structure.pendingKyberPreKey
        return pending.preKeyId, pending.ciphertext

    def clear_pending_kyber_pre_key(self):
        self.structure.ClearField("pendingKyberPreKey")


class SessionRecord:
    ARCHIVED_STATES_MAX_LENGTH = 40

    def __init__(self, source=None, *, profile=UPSTREAM):
        self.profile = ProtocolProfile(profile)
        self.previous_states = []
        self.fresh = source is None
        self._record = pb.RecordStructure()
        if isinstance(source, bytes):
            self._record.CopyFrom(parse_java_protobuf(pb.RecordStructure, source))
            self.session_state = SessionState(self._record.currentSession)
            self.previous_states = [SessionState(s) for s in self._record.previousSessions]
        else:
            self.session_state = source if source is not None else SessionState()

    def has_session_state(self, version, alice_base_key):
        return any(
            s.session_version == version and s.alice_base_key == alice_base_key
            for s in [self.session_state] + self.previous_states
        )

    def promote_matching_session(self, version, alice_base_key):
        if (
            self.session_state.session_version == version
            and self.session_state.alice_base_key == alice_base_key
        ):
            return True
        for index, state in enumerate(self.previous_states):
            if state.session_version == version and state.alice_base_key == alice_base_key:
                del self.previous_states[index]
                self.promote_state(state)
                return True
        return False

    def archive_current_state(self):
        self.promote_state(SessionState())

    def promote_state(self, state):
        self.previous_states.insert(0, self.session_state)
        if self.profile.whatsapp:
            self.session_state.clear_unacknowledged_pre_key_message()
        self.session_state = state
        if len(self.previous_states) > self.ARCHIVED_STATES_MAX_LENGTH:
            self.previous_states.pop()

    def remove_previous_session_states(self):
        self.previous_states.clear()

    def serialize(self):
        record = pb.RecordStructure()
        record.currentSession.CopyFrom(self.session_state.structure)
        del record.previousSessions[:]
        record.previousSessions.extend(s.structure for s in self.previous_states)
        return record.SerializeToString()
