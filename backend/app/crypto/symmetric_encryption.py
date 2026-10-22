"""AES-256-GCM authenticated encryption operations."""

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto_errors import CryptoInputError

KEY_LENGTH = 32
NONCE_LENGTH = 12


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    return secrets.token_bytes(NONCE_LENGTH)


def encrypt(key: bytes, plaintext: bytes, *, aad: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    if len(key) != KEY_LENGTH:
        raise CryptoInputError("AES-256-GCM requires a 32-byte key")
    nonce = generate_nonce() if nonce is None else nonce
    if len(nonce) != NONCE_LENGTH:
        raise CryptoInputError("AES-GCM requires a 12-byte nonce")
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, *, aad: bytes) -> bytes:
    if len(key) != KEY_LENGTH:
        raise CryptoInputError("AES-256-GCM requires a 32-byte key")
    if len(nonce) != NONCE_LENGTH:
        raise CryptoInputError("AES-GCM requires a 12-byte nonce")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
