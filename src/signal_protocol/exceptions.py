"""Protocol failures, kept distinct so applications can handle retries safely."""


class InvalidKeyException(ValueError):
    pass


class InvalidKeyIdException(Exception):
    pass


class InvalidMessageException(Exception):
    pass


class InvalidVersionException(Exception):
    pass


class LegacyMessageException(Exception):
    pass


class DuplicateMessageException(Exception):
    pass


class NoSessionException(Exception):
    pass


class UntrustedIdentityException(Exception):
    def __init__(self, name, identity_key):
        super().__init__(f"Untrusted identity: {name}")
        self.name = name
        self.identity_key = identity_key


class InvalidMacException(Exception):
    pass


class VrfSignatureVerificationFailedException(Exception):
    pass


class FingerprintParsingException(Exception):
    pass


class FingerprintVersionMismatchException(Exception):
    def __init__(self, their_version, our_version):
        super().__init__(f"Fingerprint version mismatch: {their_version} != {our_version}")
        self.their_version = their_version
        self.our_version = our_version


class FingerprintIdentifierMismatchException(Exception):
    pass
