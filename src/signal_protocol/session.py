"""Prekey session setup and transactional double-ratchet encrypt/decrypt."""

from threading import RLock

from .ecc import Curve
from .exceptions import (
    DuplicateMessageException,
    InvalidKeyException,
    InvalidMessageException,
    InvalidVersionException,
    NoSessionException,
    UntrustedIdentityException,
)
from .integers import int32, uint32
from .kdf import crypt_ctr, decrypt_cbc, encrypt_cbc
from .profiles import UPSTREAM, ProtocolProfile
from .protocol import PreKeySignalMessage, SignalMessage
from .ratchet import AliceSignalProtocolParameters, BobSignalProtocolParameters, RatchetingSession
from .state import SessionState
from .store import Direction

SESSION_LOCK = RLock()


class SessionBuilder:
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
            from .whatsapp import validate_public_key

            validate_public_key(identity.public_key)

    def _trust(self, identity, direction):
        self._validate_identity(identity)
        if not self.identity_key_store.is_trusted_identity(
            self.remote_address, identity, direction
        ):
            raise UntrustedIdentityException(self.remote_address.name, identity)

    def process(self, pre_key):
        with SESSION_LOCK:
            self._trust(pre_key.identity_key, Direction.SENDING)
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
            encapsulated = None
            if has_kem:
                from .kem import KemKeyType

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
                encapsulated = pre_key.kyber_pre_key.encapsulate()
            record = self.session_store.load_session(self.remote_address)
            record.profile = self.profile
            base = Curve.generate_key_pair()
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
            self.identity_key_store.save_identity(self.remote_address, pre_key.identity_key)
            self.session_store.store_session(self.remote_address, record)

    def process_message(self, record, message):
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


class SessionCipher:
    SESSION_LOCK = SESSION_LOCK

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
        self.builder = SessionBuilder(
            store,
            remote_address,
            pre_key_store=pre_key_store,
            signed_pre_key_store=signed_pre_key_store,
            identity_key_store=identity_key_store,
            kyber_pre_key_store=kyber_pre_key_store,
            profile=profile,
            strict_identity=strict_identity,
        )
        self.identity_key_store = self.builder.identity_key_store
        self.pre_key_store = self.builder.pre_key_store
        self.kyber_pre_key_store = self.builder.kyber_pre_key_store
        self.profile = self.builder.profile

    def encrypt(self, padded_message):
        with SESSION_LOCK:
            record = self.session_store.load_session(self.remote_address)
            record.profile = self.profile
            state = record.session_state
            if not state.has_sender_chain():
                raise NoSessionException(f"No session for: {self.remote_address}")
            self._check_version(state.session_version)
            chain = state.sender_chain_key
            keys = chain.message_keys()
            ciphertext = (
                crypt_ctr(keys.cipher_key, keys.counter, padded_message)
                if state.session_version == 2 and self.profile.whatsapp
                else encrypt_cbc(keys.cipher_key, keys.iv, padded_message)
            )
            message = SignalMessage(
                state.session_version,
                keys.mac_key,
                state.sender_ratchet_key,
                chain.index,
                state.previous_counter,
                ciphertext,
                state.local_identity_key,
                state.remote_identity_key,
                profile=self.profile,
            )
            if state.has_unacknowledged_pre_key_message():
                p = state.unacknowledged_pre_key_message_items
                kem = state.pending_kyber_pre_key
                message = PreKeySignalMessage(
                    state.session_version,
                    state.local_registration_id,
                    p.pre_key_id,
                    p.signed_pre_key_id,
                    p.base_key,
                    state.local_identity_key,
                    message,
                    kyber_pre_key_id=kem[0] if kem is not None else None,
                    kyber_ciphertext=kem[1] if kem is not None else None,
                    profile=self.profile,
                )
            state.sender_chain_key = chain.next_chain_key()
            if self.profile.whatsapp:
                self.builder._validate_identity(state.remote_identity_key)
            else:
                self.builder._trust(state.remote_identity_key, Direction.SENDING)
                self.identity_key_store.save_identity(
                    self.remote_address, state.remote_identity_key
                )
            self.session_store.store_session(self.remote_address, record)
            return message

    def decrypt(self, message, callback=None):
        if not isinstance(message, (SignalMessage, PreKeySignalMessage)):
            raise TypeError("Parse the envelope as SignalMessage or PreKeySignalMessage first")
        with SESSION_LOCK:
            self._check_version(message.message_version)
            is_prekey = isinstance(message, PreKeySignalMessage)
            if not is_prekey and not self.session_store.contains_session(self.remote_address):
                raise NoSessionException(f"No session for: {self.remote_address}")
            record = self.session_store.load_session(self.remote_address)
            record.profile = self.profile
            unsigned_id = None
            kyber_id = message.kyber_pre_key_id if is_prekey else None
            if is_prekey:
                unsigned_id = self.builder.process_message(record, message)
                message = message.message
            plaintext = self._decrypt_record(
                record, message, allow_previous=not (is_prekey and self.profile.whatsapp)
            )
            if not is_prekey and not self.profile.whatsapp:
                self.builder._trust(record.session_state.remote_identity_key, Direction.RECEIVING)
                self.identity_key_store.save_identity(
                    self.remote_address, record.session_state.remote_identity_key
                )
            elif not is_prekey:
                self.builder._validate_identity(record.session_state.remote_identity_key)
            if callback is not None:
                callback(plaintext)
            self.session_store.store_session(self.remote_address, record)
            if unsigned_id is not None:
                self.pre_key_store.remove_pre_key(unsigned_id)
            if self.profile.whatsapp and kyber_id is not None:
                self.kyber_pre_key_store.mark_kyber_pre_key_used(kyber_id)
            return plaintext

    def _check_version(self, version):
        if version not in ((2, 3, 4) if self.profile.whatsapp else (3,)):
            raise InvalidVersionException(f"Unsupported session version: {version}")

    def _decrypt_record(self, record, message, *, allow_previous=True):
        errors = []
        states = [record.session_state] + (record.previous_states if allow_previous else [])
        for index, original in enumerate(states):
            state = SessionState(original)
            try:
                plaintext = self._decrypt_state(state, message)
            except InvalidMessageException as exc:
                errors.append(exc)
                continue
            if index == 0:
                record.session_state = state
            else:
                del record.previous_states[index - 1]
                record.promote_state(state)
            return plaintext
        raise InvalidMessageException("No valid sessions", errors)

    def _decrypt_state(self, state, message):
        if not state.has_sender_chain():
            raise InvalidMessageException("Uninitialized session")
        if message.message_version != state.session_version:
            raise InvalidMessageException("Message/session version mismatch")
        public, counter = message.sender_ratchet_key, message.counter
        chain = self._get_or_create_chain_key(state, public)
        keys = self._get_or_create_message_keys(state, public, chain, counter)
        message.verify_mac(state.remote_identity_key, state.local_identity_key, keys.mac_key)
        plaintext = (
            crypt_ctr(keys.cipher_key, keys.counter, message.body)
            if state.session_version == 2 and self.profile.whatsapp
            else decrypt_cbc(keys.cipher_key, keys.iv, message.body)
        )
        state.clear_unacknowledged_pre_key_message()
        if self.profile.whatsapp:
            state.clear_pending_kyber_pre_key()
        return plaintext

    def _get_or_create_chain_key(self, state, public):
        if state.has_receiver_chain(public):
            return state.get_receiver_chain_key(public)
        try:
            root, receiver = state.root_key.create_chain(
                public, state.sender_ratchet_key_pair, profile=self.profile
            )
            new_ratchet = Curve.generate_key_pair()
            root, sender = root.create_chain(public, new_ratchet, profile=self.profile)
        except InvalidKeyException as exc:
            raise InvalidMessageException(str(exc)) from exc
        state.root_key = root
        state.add_receiver_chain(public, receiver)
        previous = int32(state.sender_chain_key.index - 1)
        state.previous_counter = uint32(max(previous, 0))
        state.set_sender_chain(new_ratchet, sender)
        return receiver

    def _get_or_create_message_keys(self, state, public, chain, counter):
        counter = uint32(counter)
        chain_index = int32(chain.index)
        message_index = int32(counter)
        if chain_index > message_index:
            keys = state.remove_message_keys(public, counter)
            if keys is None:
                raise DuplicateMessageException(f"Old counter: {chain.index}, {counter}")
            return keys
        difference = message_index - chain_index
        checked_difference = int32(difference)
        # Java's signed subtraction can overflow and bypass its fast guard.
        # Keep the real amount of work bounded even for that malformed boundary.
        if checked_difference > 2000 or difference > 2000:
            raise InvalidMessageException("Over 2000 messages into the future")
        while int32(chain.index) < message_index:
            state.set_message_keys(public, chain.message_keys())
            chain = chain.next_chain_key()
        state.set_receiver_chain_key(public, chain.next_chain_key())
        return chain.message_keys()

    def get_remote_registration_id(self):
        with SESSION_LOCK:
            return self.session_store.load_session(
                self.remote_address
            ).session_state.remote_registration_id

    def get_session_version(self):
        with SESSION_LOCK:
            if not self.session_store.contains_session(self.remote_address):
                raise NoSessionException(str(self.remote_address))
            return self.session_store.load_session(
                self.remote_address
            ).session_state.session_version
