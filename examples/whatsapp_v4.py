"""Local ML-KEM-1024/X25519 handshake with WhatsApp content padding."""

from signal_protocol import (
    Curve,
    InMemorySignalProtocolStore,
    KeyHelper,
    PreKeyBundle,
    PreKeyRecord,
    SignalProtocolAddress,
    WhatsAppSessionBuilder,
    WhatsAppSessionCipher,
)

alice, bob = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
alice_address, bob_address = SignalProtocolAddress("alice", 1), SignalProtocolAddress("bob", 1)
prekey = PreKeyRecord(7, Curve.generate_key_pair())
signed = KeyHelper.generate_signed_pre_key(bob.identity_key_pair, 8)
kem = KeyHelper.generate_kyber_pre_key(bob.identity_key_pair, 9)
bob.store_pre_key(7, prekey)
bob.store_signed_pre_key(8, signed)
bob.store_kyber_pre_key(9, kem)
bundle = PreKeyBundle(
    bob.registration_id,
    1,
    7,
    prekey.key_pair.public_key,
    8,
    signed.key_pair.public_key,
    signed.signature,
    bob.identity_key_pair.public_key,
    kyber_pre_key_id=9,
    kyber_pre_key=kem.key_pair.public_key,
    kyber_pre_key_signature=kem.signature,
)
WhatsAppSessionBuilder(alice, bob_address).process(bundle)
sender = WhatsAppSessionCipher(alice, bob_address)
receiver = WhatsAppSessionCipher(bob, alice_address)
message = sender.encrypt(b"Hello v4")
assert message.serialize()[0] == 0x44
assert receiver.decrypt(message.serialize(), message_type=message.type) == b"Hello v4"
assert sender.decrypt(receiver.encrypt(b"Hello back")) == b"Hello back"
assert sender.get_session_version() == receiver.get_session_version() == 4
assert not bob.contains_pre_key(7) and not bob.contains_kyber_pre_key(9)
print("WhatsApp v4 ML-KEM-1024/X25519 handshake, business padding and reply passed.")
