"""A completely local two-party exchange; no network service or Java runtime."""

from signal_protocol import (
    InMemorySignalProtocolStore,
    KeyHelper,
    PreKeyBundle,
    PreKeySignalMessage,
    SessionBuilder,
    SessionCipher,
    SignalMessage,
    SignalProtocolAddress,
)

alice_address = SignalProtocolAddress("alice", 1)
bob_address = SignalProtocolAddress("bob", 1)
alice = InMemorySignalProtocolStore()
bob = InMemorySignalProtocolStore()

prekey = KeyHelper.generate_pre_keys(1, 1)[0]
signed = KeyHelper.generate_signed_pre_key(bob.get_identity_key_pair(), 2)
bob.store_pre_key(prekey.id, prekey)
bob.store_signed_pre_key(signed.id, signed)
bundle = PreKeyBundle(
    registration_id=bob.get_local_registration_id(),
    device_id=1,
    pre_key_id=prekey.id,
    pre_key=prekey.key_pair.public_key,
    signed_pre_key_id=signed.id,
    signed_pre_key=signed.key_pair.public_key,
    signed_pre_key_signature=signed.signature,
    identity_key=bob.get_identity_key_pair().public_key,
)
SessionBuilder(alice, bob_address).process(bundle)
alice_cipher = SessionCipher(alice, bob_address)
bob_cipher = SessionCipher(bob, alice_address)

outgoing = alice_cipher.encrypt("你好，Bob".encode())
assert outgoing.type == 3
received = bob_cipher.decrypt(PreKeySignalMessage.from_bytes(outgoing.serialize()))
assert received == "你好，Bob".encode()
assert not bob.contains_pre_key(prekey.id)

reply = bob_cipher.encrypt(b"Hello, Alice")
assert reply.type == 2
assert alice_cipher.decrypt(SignalMessage.from_bytes(reply.serialize())) == b"Hello, Alice"
print("Local prekey handshake and bidirectional message exchange passed.")
