"""Prekey validation and outgoing/incoming session establishment."""

from signal_protocol._locks import SESSION_LOCK, protocol_operation
from signal_protocol.address import Direction
from signal_protocol.ecc import Curve
from signal_protocol.exceptions import (
    InvalidKeyException,
    InvalidVersionException,
    UntrustedIdentityException,
)
from signal_protocol.profiles import UPSTREAM, ProtocolProfile
from signal_protocol.ratchet import (
    AliceSignalProtocolParameters,
    BobSignalProtocolParameters,
    RatchetingSession,
)

__all__ = ["SessionBuilder"]


class SessionBuilder:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.session"

    def __init__(
        self,
        store,
        remote_address,
        *,
        pre_key_store=None,
        signed_pre_key_store=None,
        identity_key_store=None,
        kyber_pre_key_store=None,
        profile=UPSTREAM,
        strict_identity=None,
    ):
        self.session_store = store
        self.remote_address = remote_address
        self.pre_key_store = store if pre_key_store is None else pre_key_store
        self.signed_pre_key_store = store if signed_pre_key_store is None else signed_pre_key_store
        self.identity_key_store = store if identity_key_store is None else identity_key_store
        self.kyber_pre_key_store = store if kyber_pre_key_store is None else kyber_pre_key_store
        self.profile = ProtocolProfile(profile)
        self.strict_identity = (
            self.profile.whatsapp if strict_identity is None else bool(strict_identity)
        )

    def _validate_identity(self, identity):
        if self.strict_identity:
            from signal_protocol.whatsapp import validate_public_key

            validate_public_key(identity.public_key)

    def _trust(self, identity, direction):
        self._validate_identity(identity)
        if not self.identity_key_store.is_trusted_identity(
            self.remote_address, identity, direction
        ):
            raise UntrustedIdentityException(self.remote_address.name, identity)

    def process(self, pre_key):
        with protocol_operation(SESSION_LOCK):
            self._trust(pre_key.identity_key, Direction.SENDING)
            encapsulated = self._validate_and_encapsulate(pre_key)
            record = self.session_store.load_session(self.remote_address)
            record.profile = self.profile
            base = Curve.generate_key_pair()
            self._initialize_outgoing_session(record, pre_key, base, encapsulated)
            self.identity_key_store.save_identity(self.remote_address, pre_key.identity_key)
            self.session_store.store_session(self.remote_address, record)

    def _validate_and_encapsulate(self, pre_key):
        """Validate all bundle material before loading or modifying session state."""
        if pre_key.signed_pre_key is None:
            raise InvalidKeyException("No signed prekey")
        if not Curve.verify_signature(
            pre_key.identity_key.public_key,
            pre_key.signed_pre_key.serialize(),
            pre_key.signed_pre_key_signature,
        ):
            raise InvalidKeyException("Invalid signature on device key")
        kem_parts = (
            pre_key.kyber_pre_key_id,
            pre_key.kyber_pre_key,
            pre_key.kyber_pre_key_signature,
        )
        has_kem = any(part is not None for part in kem_parts)
        if has_kem:
            from signal_protocol.kem import KemKeyType

            if not self.profile.whatsapp:
                raise InvalidKeyException("KEM prekeys require the WhatsApp profile")
            if any(part is None for part in kem_parts):
                raise InvalidKeyException("Incomplete signed KEM prekey")
            if pre_key.kyber_pre_key.key_type not in KemKeyType:
                raise InvalidKeyException("Unsupported WhatsApp ML-KEM parameter set")
            if not Curve.verify_signature(
                pre_key.identity_key.public_key,
                pre_key.kyber_pre_key.serialize(),
                pre_key.kyber_pre_key_signature,
            ):
                raise InvalidKeyException("Invalid signature on KEM prekey")
            return pre_key.kyber_pre_key.encapsulate()
        return None

    def _initialize_outgoing_session(self, record, pre_key, base, encapsulated):
        parameters = AliceSignalProtocolParameters(
            self.identity_key_store.get_identity_key_pair(),
            base,
            pre_key.identity_key,
            pre_key.signed_pre_key,
            pre_key.signed_pre_key,
            pre_key.pre_key,
            encapsulated.shared_secret if encapsulated is not None else None,
        )
        if not record.fresh:
            record.archive_current_state()
        state = record.session_state
        RatchetingSession.initialize_session(state, parameters, profile=self.profile)
        state.set_unacknowledged_pre_key_message(
            pre_key.pre_key_id if pre_key.pre_key is not None else None,
            pre_key.signed_pre_key_id,
            base.public_key,
        )
        if encapsulated is not None:
            state.set_pending_kyber_pre_key(pre_key.kyber_pre_key_id, encapsulated.ciphertext)
        state.local_registration_id = self.identity_key_store.get_local_registration_id()
        state.remote_registration_id = pre_key.registration_id
        state.alice_base_key = base.public_key.serialize()

    def process_message(self, record, message):
        """Prepare an incoming prekey record outside an active cipher operation."""
        with protocol_operation(SESSION_LOCK):
            return self._process_message(record, message)

    def _process_message(self, record, message):
        """Continue incoming setup under the caller's protocol operation guard."""
        record.profile = self.profile
        if not self.profile.whatsapp and message.kyber_pre_key_id is not None:
            raise InvalidVersionException("KEM messages require the WhatsApp profile")
        if message.message_version not in ((3, 4) if self.profile.whatsapp else (3,)):
            raise InvalidVersionException(f"Unsupported PreKey version: {message.message_version}")
        self._trust(message.identity_key, Direction.RECEIVING)
        unsigned_id = None
        matched = (
            record.promote_matching_session(message.message_version, message.base_key.serialize())
            if self.profile.whatsapp
            else record.has_session_state(message.message_version, message.base_key.serialize())
        )
        if not matched:
            signed = self.signed_pre_key_store.load_signed_pre_key(
                message.signed_pre_key_id
            ).key_pair
            one_time = (
                self.pre_key_store.load_pre_key(message.pre_key_id).key_pair
                if message.pre_key_id is not None
                else None
            )
            parameters = BobSignalProtocolParameters(
                self.identity_key_store.get_identity_key_pair(),
                signed,
                signed,
                message.identity_key,
                message.base_key,
                one_time,
                self.kyber_pre_key_store.load_kyber_pre_key(
                    message.kyber_pre_key_id
                ).key_pair.secret_key.decapsulate(message.kyber_ciphertext)
                if message.kyber_pre_key_id is not None
                else None,
            )
            if not record.fresh:
                record.archive_current_state()
            state = record.session_state
            RatchetingSession.initialize_session(state, parameters, profile=self.profile)
            state.local_registration_id = self.identity_key_store.get_local_registration_id()
            state.remote_registration_id = message.registration_id
            state.alice_base_key = message.base_key.serialize()
            unsigned_id = message.pre_key_id
            if self.profile.whatsapp and unsigned_id == 0xFFFFFF:
                unsigned_id = None
        self.identity_key_store.save_identity(self.remote_address, message.identity_key)
        return unsigned_id
