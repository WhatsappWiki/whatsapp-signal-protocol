"""All six simultaneous-initiation tests, including delayed archived-session revival."""

from signal_protocol import Curve, InMemorySignalProtocolStore, SessionBuilder, SessionCipher

from .helpers import ALICE, BOB, bundle, decode


class Peers:
    def __init__(self):
        self.a, self.b = InMemorySignalProtocolStore(), InMemorySignalProtocolStore()
        self.ab, self.bb = SessionBuilder(self.a, BOB), SessionBuilder(self.b, ALICE)
        self.ac, self.bc = SessionCipher(self.a, BOB), SessionCipher(self.b, ALICE)
        self.a_signed, self.b_signed = Curve.generate_key_pair(), Curve.generate_key_pair()
        self.next_id = 100

    def a_bundle(self):
        self.next_id += 1
        return bundle(self.a, self.next_id, 20, signed_pair=self.a_signed)

    def b_bundle(self):
        self.next_id += 1
        return bundle(self.b, self.next_id, 21, signed_pair=self.b_signed)

    def same(self):
        return (
            self.a.load_session(BOB).session_state.alice_base_key
            == self.b.load_session(ALICE).session_state.alice_base_key
        )

    def initiate(self, deliver_both=True):
        a_bundle, b_bundle = self.a_bundle(), self.b_bundle()
        self.ab.process(b_bundle)
        self.bb.process(a_bundle)
        to_bob, to_alice = self.ac.encrypt(b"hey there"), self.bc.encrypt(b"sample message")
        assert to_bob.type == to_alice.type == 3
        assert not self.same()
        if deliver_both:
            assert self.ac.decrypt(decode(to_alice)) == b"sample message"
        assert self.bc.decrypt(decode(to_bob)) == b"hey there"
        assert self.b.load_session(ALICE).session_state.session_version == 3
        if deliver_both:
            assert self.a.load_session(BOB).session_state.session_version == 3
            assert not self.same()

    def repeat(self):
        for _ in range(50):
            to_bob, to_alice = self.ac.encrypt(b"hey there"), self.bc.encrypt(b"sample message")
            assert to_bob.type == to_alice.type == 2
            assert not self.same()
            assert self.ac.decrypt(decode(to_alice)) == b"sample message"
            assert self.bc.decrypt(decode(to_bob)) == b"hey there"
            assert not self.same()

    def converge(self, response_type=2, lose_response=False):
        response = self.ac.encrypt(b"second message")
        assert response.type == response_type
        if lose_response:
            assert not self.same()
        else:
            assert self.bc.decrypt(decode(response)) == b"second message"
            assert self.same()
        final = self.bc.encrypt(b"third message")
        assert final.type == 2
        assert self.ac.decrypt(decode(final)) == b"third message"
        assert self.same()


class TestSimultaneousInitiate:
    def testBasicSimultaneousInitiate(self):
        p = Peers()
        p.initiate()
        p.converge()

    def testLostSimultaneousInitiate(self):
        p = Peers()
        p.initiate(deliver_both=False)
        p.converge(response_type=3)

    def testSimultaneousInitiateLostMessage(self):
        p = Peers()
        p.initiate()
        p.converge(lose_response=True)

    def testSimultaneousInitiateRepeatedMessages(self):
        p = Peers()
        p.initiate()
        p.repeat()
        p.converge()

    def testRepeatedSimultaneousInitiateRepeatedMessages(self):
        p = Peers()
        for _ in range(15):
            p.initiate()
        p.repeat()
        p.converge()

    def testRepeatedSimultaneousInitiateLostMessageRepeatedMessages(self):
        p = Peers()
        p.ab.process(p.b_bundle())
        lost = p.ac.encrypt(b"hey there")
        for _ in range(15):
            p.initiate()
        p.repeat()
        p.converge()
        assert p.bc.decrypt(decode(lost)) == b"hey there"
        assert not p.same()
        blast = p.bc.encrypt(b"unexpected!")
        assert p.ac.decrypt(decode(blast)) == b"unexpected!"
        assert p.same()
