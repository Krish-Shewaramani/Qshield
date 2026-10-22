"""Domain errors for cryptographic operations."""


class CryptoConfigurationError(RuntimeError):
    """Raised when an approved cryptographic primitive is unavailable."""


class CryptoInputError(ValueError):
    """Raised when cryptographic input does not meet the API contract."""
