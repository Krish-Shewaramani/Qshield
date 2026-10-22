"""Errors raised by key and trust management operations."""


class KeyManagementError(Exception):
    """Base class for key-management failures."""


class KeyNotFoundError(KeyManagementError):
    pass


class KeyRecordError(KeyManagementError):
    pass


class KeyUnlockError(KeyManagementError):
    pass


class KeyTypeMismatchError(KeyManagementError):
    pass


class FingerprintMismatchError(KeyManagementError):
    pass


class PublicKeyImportError(KeyManagementError):
    pass


class TrustConfirmationError(KeyManagementError):
    pass
