"""Startup checks for the four approved cryptographic operations."""

from backend.app.crypto import (
    kem_service,
    key_derivation,
    signature_service,
    symmetric_encryption,
)
from backend.app.crypto.crypto_errors import CryptoConfigurationError


def run_crypto_self_check() -> tuple[str, ...]:
    """Exercise each approved primitive; raise if any capability is missing."""
    try:
        kem_private, kem_public = kem_service.generate_keypair()
        kem_ciphertext, encapsulated_secret = kem_service.encapsulate(kem_public)
        if kem_service.decapsulate(kem_private, kem_ciphertext) != encapsulated_secret:
            raise RuntimeError("ML-KEM-768 self-check mismatch")

        sig_private, sig_public = signature_service.generate_keypair()
        message = b"QuantumShield startup capability check"
        signature_service.verify(sig_public, signature_service.sign(sig_private, message), message)

        key = key_derivation.derive_key(b"startup input key material", salt=None, info=b"QuantumShield startup check")
        nonce, ciphertext = symmetric_encryption.encrypt(key, message, aad=b"health-check")
        if symmetric_encryption.decrypt(key, nonce, ciphertext, aad=b"health-check") != message:
            raise RuntimeError("AES-256-GCM self-check mismatch")
    except Exception as exc:
        raise CryptoConfigurationError("approved cryptographic self-check failed") from exc
    return ("ML-KEM-768", "ML-DSA-65", "HKDF-SHA-256", "AES-256-GCM")
