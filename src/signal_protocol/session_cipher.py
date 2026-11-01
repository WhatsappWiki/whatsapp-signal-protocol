"""Double-ratchet encryption, authenticated decryption and store commit ordering."""

from signal_protocol._locks import SESSION_LOCK, protocol_operation
from signal_protocol.address import Direction
from signal_protocol.ecc import Curve
from signal_protocol.exceptions import (
    DuplicateMessageException,
    InvalidKeyException,
    InvalidMessageException,
    InvalidVersionException,
    NoSessionException,
)
from signal_protocol.integers import int32, uint32
from signal_protocol.kdf import crypt_ctr, decrypt_cbc, encrypt_cbc
from signal_protocol.profiles import UPSTREAM
from signal_protocol.protocol import PreKeySignalMessage, SignalMessage
from signal_protocol.session_builder import SessionBuilder
from signal_protocol.state import SessionState

__all__ = ["SessionCipher"]


class SessionCipher:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.session"

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
        with protocol_operation(SESSION_LOCK):
            record = self.session_store.load_session(self.remote_address)
            record.profile = self.profile
            state = record.session_state
            if not state.has_sender_chain():
                raise NoSessionException(f"No session for: {self.remote_address}")
            self._check_version(state.session_version)
            message = self._encrypt_state(state, padded_message)
            if self.profile.whatsapp:
                self.builder._validate_identity(state.remote_identity_key)
            else:
                self.builder._trust(state.remote_identity_key, Direction.SENDING)
                self.identity_key_store.save_identity(
                    self.remote_address, state.remote_identity_key
                )
            self.session_store.store_session(self.remote_address, record)
            return message

    def _encrypt_state(self, state, padded_message):
        """Build the envelope and advance the detached state, without storing it."""
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
        return message

    def decrypt(self, message, callback=None):
        if not isinstance(message, (SignalMessage, PreKeySignalMessage)):
            raise TypeError("Parse the envelope as SignalMessage or PreKeySignalMessage first")
        with protocol_operation(SESSION_LOCK):
            self._check_version(message.message_version)
            is_prekey = isinstance(message, PreKeySignalMessage)
            if not is_prekey and not self.session_store.contains_session(self.remote_address):
                raise NoSessionException(f"No session for: {self.remote_address}")
            record = self.session_store.load_session(self.remote_address)
            record.profile = self.profile
            unsigned_id = None
            kyber_id = message.kyber_pre_key_id if is_prekey else None
            if is_prekey:
                unsigned_id = self.builder._process_message(record, message)
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
        with protocol_operation(SESSION_LOCK, read_only=True):
            return self.session_store.load_session(
                self.remote_address
            ).session_state.remote_registration_id

    def get_session_version(self):
        with protocol_operation(SESSION_LOCK, read_only=True):
            if not self.session_store.contains_session(self.remote_address):
                raise NoSessionException(str(self.remote_address))
            return self.session_store.load_session(
                self.remote_address
            ).session_state.session_version
