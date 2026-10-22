"""Errors exposed by the `.qshield` cryptographic core."""


class PackageError(ValueError):
    """Base class for rejected package operations."""


class PackageFormatError(PackageError):
    """The package encoding or encrypted payload is malformed."""


class PackageVerificationError(PackageError):
    """The sender is not trusted or the package signature is invalid."""


class PackageRecipientError(PackageError):
    """The package is not addressed to the selected recipient key."""


class PackageDecryptionError(PackageError):
    """Authentication or recipient decryption failed."""
