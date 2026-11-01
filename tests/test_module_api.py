"""Public import compatibility and behavior across the separated module boundaries."""

import importlib
import pickle
import pkgutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import signal_protocol
from signal_protocol import KeyHelper, PreKeyBundle, PreKeySignalMessage, SignalMessage
from signal_protocol.adapters import WhatsAppGroupCipher
from signal_protocol.address import SignalProtocolAddress
from signal_protocol.group_session import GroupSessionBuilder
from signal_protocol.memory_store import (
    InMemoryIdentityKeyStore,
    InMemoryKyberPreKeyStore,
    InMemoryPreKeyStore,
    InMemorySenderKeyStore,
    InMemorySessionStore,
    InMemorySignedPreKeyStore,
)
from signal_protocol.profiles import UPSTREAM, WHATSAPP
from signal_protocol.sender_keys import SenderKeyName
from signal_protocol.session_builder import SessionBuilder
from signal_protocol.session_cipher import SessionCipher


@pytest.mark.parametrize(
    "entry,implementation,names",
    [
        ("session", "session_builder", ["SessionBuilder"]),
        ("session", "session_cipher", ["SessionCipher"]),
        ("store", "address", ["SignalProtocolAddress", "Direction"]),
        (
            "store",
            "store_contracts",
            [
                "IdentityKeyStore",
                "PreKeyStore",
                "SignedPreKeyStore",
                "KyberPreKeyStore",
                "SessionStore",
                "SignalProtocolStore",
            ],
        ),
        (
            "store",
            "memory_store",
            [
                "InMemoryIdentityKeyStore",
                "InMemoryPreKeyStore",
                "InMemorySignedPreKeyStore",
                "InMemorySessionStore",
                "InMemoryKyberPreKeyStore",
                "InMemorySignalProtocolStore",
            ],
        ),
        (
            "groups",
            "sender_keys",
            [
                "SenderKeyName",
                "SenderChainKey",
                "SenderMessageKey",
                "SenderKeyState",
                "SenderKeyRecord",
            ],
        ),
        ("groups", "group_session", ["GroupSessionBuilder", "GroupCipher"]),
        ("groups", "store_contracts", ["SenderKeyStore"]),
        ("groups", "memory_store", ["InMemorySenderKeyStore"]),
        ("protobuf_codec", "integers", ["uint32"]),
    ],
)
def test_existing_imports_resolve_to_the_same_objects(entry, implementation, names):
    facade = importlib.import_module(f"signal_protocol.{entry}")
    owner = importlib.import_module(f"signal_protocol.{implementation}")
    for name in names:
        assert name in facade.__all__
        assert getattr(facade, name) is getattr(owner, name)
        if name in signal_protocol.__all__:
            assert getattr(signal_protocol, name) is getattr(owner, name)


def test_handwritten_modules_have_resolvable_explicit_exports():
    for info in pkgutil.iter_modules(signal_protocol.__path__):
        if info.ispkg or info.name.startswith("_"):
            continue
        module = importlib.import_module(f"signal_protocol.{info.name}")
        assert len(module.__all__) == len(set(module.__all__))
        namespace = {}
        exec(f"from {module.__name__} import *", namespace)
        assert set(namespace) - {"__builtins__"} == set(module.__all__)


def test_setup_and_cipher_entry_points_share_the_original_locks():
    from signal_protocol import group_session, groups, session, session_builder, session_cipher

    assert session.SESSION_LOCK is session_builder.SESSION_LOCK
    assert session.SESSION_LOCK is session_cipher.SESSION_LOCK is SessionCipher.SESSION_LOCK
    assert groups.GROUP_LOCK is group_session.GROUP_LOCK
    assert groups.GROUP_LOCK is not session.SESSION_LOCK


def test_group_namespace_is_available_after_only_importing_the_package():
    # A fresh interpreter must not inherit this test module's submodule imports.
    source = Path(signal_protocol.__file__).resolve().parent.parent
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); import signal_protocol; "
            "assert signal_protocol.groups.GroupCipher; "
            "assert signal_protocol.groups.SenderKeyRecord",
            str(source),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("module_name", ["store", "groups", "session"])
def test_relocated_classes_keep_legacy_pickle_paths(module_name):
    module = importlib.import_module(f"signal_protocol.{module_name}")
    for name in module.__all__:
        cls = getattr(module, name)
        if not isinstance(cls, type):
            continue
        # Protocol 0 makes the persisted GLOBAL module/name explicit. A simple
        # round trip would miss a new path that an older installation cannot load.
        serialized = pickle.dumps(cls, protocol=0)
        assert serialized.startswith(f"c{module.__name__}\n{name}\n".encode())
        assert pickle.loads(serialized) is cls


def separate_stores():
    return SimpleNamespace(
        sessions=InMemorySessionStore(),
        identity=InMemoryIdentityKeyStore(),
        prekeys=InMemoryPreKeyStore(),
        signed=InMemorySignedPreKeyStore(),
        kem=InMemoryKyberPreKeyStore(),
    )


def session_arguments(stores, profile):
    return dict(
        pre_key_store=stores.prekeys,
        signed_pre_key_store=stores.signed,
        identity_key_store=stores.identity,
        kyber_pre_key_store=stores.kem,
        profile=profile,
    )


@pytest.mark.parametrize("profile,hybrid", [(UPSTREAM, False), (WHATSAPP, False), (WHATSAPP, True)])
def test_separate_store_dependencies_preserve_commit_and_prekey_consumption(profile, hybrid):
    alice, bob = separate_stores(), separate_stores()
    alice_address = SignalProtocolAddress("alice", 1)
    bob_address = SignalProtocolAddress("bob", 1)
    identity = bob.identity.get_identity_key_pair()
    prekey = KeyHelper.generate_pre_keys(17, 1)[0]
    signed = KeyHelper.generate_signed_pre_key(identity, 23)
    kem = KeyHelper.generate_kyber_pre_key(identity, 31) if hybrid else None
    bob.prekeys.store_pre_key(prekey.id, prekey)
    bob.signed.store_signed_pre_key(signed.id, signed)
    if kem is not None:
        bob.kem.store_kyber_pre_key(kem.id, kem)
    bundle = PreKeyBundle(
        bob.identity.get_local_registration_id(),
        bob_address.device_id,
        prekey.id,
        prekey.key_pair.public_key,
        signed.id,
        signed.key_pair.public_key,
        signed.signature,
        identity.public_key,
        kem.id if kem else None,
        kem.key_pair.public_key if kem else None,
        kem.signature if kem else None,
    )
    SessionBuilder(alice.sessions, bob_address, **session_arguments(alice, profile)).process(bundle)
    sender = SessionCipher(alice.sessions, bob_address, **session_arguments(alice, profile))
    receiver = SessionCipher(bob.sessions, alice_address, **session_arguments(bob, profile))
    message = PreKeySignalMessage.from_bytes(sender.encrypt(b"hello").serialize(), profile=profile)

    def abort(plaintext):
        assert plaintext == b"hello"
        assert not bob.sessions.contains_session(alice_address)
        assert bob.prekeys.contains_pre_key(prekey.id)
        if kem is not None:
            assert bob.kem.contains_kyber_pre_key(kem.id)
        raise RuntimeError("application rejected plaintext")

    with pytest.raises(RuntimeError, match="application rejected"):
        receiver.decrypt(message, abort)
    assert not bob.sessions.contains_session(alice_address)
    assert bob.prekeys.contains_pre_key(prekey.id)
    if kem is not None:
        assert bob.kem.contains_kyber_pre_key(kem.id)
    assert receiver.decrypt(message) == b"hello"
    assert not bob.prekeys.contains_pre_key(prekey.id)
    if kem is not None:
        assert not bob.kem.contains_kyber_pre_key(kem.id)
    assert bob.signed.contains_signed_pre_key(signed.id)
    reply = SignalMessage.from_bytes(receiver.encrypt(b"reply").serialize(), profile=profile)
    assert sender.decrypt(reply) == b"reply"
    assert sender.get_session_version() == (4 if hybrid else 3)


def test_group_content_callback_failure_preserves_state_for_retry():
    name = SenderKeyName("group", SignalProtocolAddress("alice", 1))
    sending, receiving = InMemorySenderKeyStore(), InMemorySenderKeyStore()
    distribution = GroupSessionBuilder(sending, profile=WHATSAPP).create(name)
    GroupSessionBuilder(receiving, profile=WHATSAPP).process(name, distribution)
    sender, receiver = WhatsAppGroupCipher(sending, name), WhatsAppGroupCipher(receiving, name)
    message = sender.encrypt(b"content", padding_length=7)
    before = receiving.load_sender_key(name).serialize()

    def abort(content):
        assert content == b"content"
        assert receiving.load_sender_key(name).serialize() == before
        raise RuntimeError("application rejected content")

    with pytest.raises(RuntimeError, match="application rejected"):
        receiver.decrypt(message, abort)
    assert receiving.load_sender_key(name).serialize() == before
    delivered = []
    assert receiver.decrypt(message, delivered.append) == b"content"
    assert delivered == [b"content"]
    assert receiving.load_sender_key(name).serialize() != before
