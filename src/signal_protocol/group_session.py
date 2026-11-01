"""Sender Key distribution and authenticated group encryption over a supplied store."""

from signal_protocol._locks import GROUP_LOCK, protocol_operation
from signal_protocol.exceptions import (
    DuplicateMessageException,
    InvalidKeyException,
    InvalidKeyIdException,
    InvalidMessageException,
    NoSessionException,
)
from signal_protocol.integers import int32, uint32
from signal_protocol.kdf import decrypt_cbc, encrypt_cbc
from signal_protocol.keys import KeyHelper
from signal_protocol.profiles import UPSTREAM, ProtocolProfile
from signal_protocol.protocol import SenderKeyDistributionMessage, SenderKeyMessage

__all__ = ["GroupSessionBuilder", "GroupCipher"]


class GroupSessionBuilder:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.groups"

    def __init__(self, store, *, profile=UPSTREAM):
        self.store = store
        self.profile = ProtocolProfile(profile)

    def process(self, name, message):
        with protocol_operation(GROUP_LOCK):
            record = self.store.load_sender_key(name)
            record.profile = self.profile
            record.add_sender_key_state(
                message.id, message.iteration, message.chain_key, message.signature_key
            )
            self.store.store_sender_key(name, record)

    def create(self, name):
        with protocol_operation(GROUP_LOCK):
            record = self.store.load_sender_key(name)
            record.profile = self.profile
            if record.is_empty():
                record.set_sender_key_state(
                    KeyHelper.generate_sender_key_id(),
                    0,
                    KeyHelper.generate_sender_key(),
                    KeyHelper.generate_sender_signing_key(),
                )
                self.store.store_sender_key(name, record)
            state = record.get_sender_key_state()
            return SenderKeyDistributionMessage(
                state.key_id,
                state.sender_chain_key.iteration,
                state.sender_chain_key.seed,
                state.signing_key_public,
            )


class GroupCipher:
    # Preserve the public type path used by pickle and existing integrations.
    __module__ = "signal_protocol.groups"

    def __init__(self, store, name, *, profile=UPSTREAM):
        self.store, self.name = store, name
        self.profile = ProtocolProfile(profile)

    def encrypt(self, plaintext):
        with protocol_operation(GROUP_LOCK):
            record = self.store.load_sender_key(self.name)
            record.profile = self.profile
            try:
                state = record.get_sender_key_state()
            except InvalidKeyIdException as exc:
                raise NoSessionException(str(exc)) from exc
            key = state.sender_chain_key.sender_message_key()
            ciphertext = encrypt_cbc(key.cipher_key, key.iv, plaintext)
            message = SenderKeyMessage(
                state.key_id, key.iteration, ciphertext, state.signing_key_private
            )
            state.sender_chain_key = state.sender_chain_key.next()
            self.store.store_sender_key(self.name, record)
            return message.serialize()

    def decrypt(self, serialized, callback=None):
        with protocol_operation(GROUP_LOCK):
            record = self.store.load_sender_key(self.name)
            record.profile = self.profile
            if record.is_empty():
                raise NoSessionException(str(self.name))
            message = SenderKeyMessage.from_bytes(serialized, profile=self.profile)
            try:
                state = record.get_sender_key_state(message.key_id)
                message.verify_signature(state.signing_key_public)
            except (InvalidKeyIdException, InvalidKeyException) as exc:
                raise InvalidMessageException(str(exc)) from exc
            key = self._get_sender_key(state, message.iteration)
            plaintext = decrypt_cbc(key.cipher_key, key.iv, message.ciphertext)
            if callback is not None:
                callback(plaintext)
            self.store.store_sender_key(self.name, record)
            return plaintext

    @staticmethod
    def _get_sender_key(state, iteration):
        chain = state.sender_chain_key
        iteration = uint32(iteration)
        current_index, message_index = int32(chain.iteration), int32(iteration)
        if current_index > message_index:
            key = state.remove_sender_message_key(iteration)
            if key is None:
                raise DuplicateMessageException(f"Old counter: {chain.iteration}, {iteration}")
            return key
        difference = message_index - current_index
        if int32(difference) > 2000 or difference > 2000:
            raise InvalidMessageException("Over 2000 messages into the future")
        while int32(chain.iteration) < message_index:
            state.add_sender_message_key(chain.sender_message_key())
            chain = chain.next()
        state.sender_chain_key = chain.next()
        return chain.sender_message_key()
