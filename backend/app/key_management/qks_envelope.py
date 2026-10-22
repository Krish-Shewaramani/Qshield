"""QSKS v1 envelope adapter, kept byte-compatible with the Phase 2A PoC.

The fixed header, parameter bounds, scrypt settings, AAD, and ciphertext layout
match experiments/phase2a_serialization/serialization_poc.py exactly.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"QSKS"
FORMAT_VERSION = 1
SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
TAG_LENGTH = 16
SCRYPT_R = 8
SCRYPT_P = 1
MIN_LOG_N = 12
MAX_LOG_N = 17
DEFAULT_LOG_N = 17
SCRYPT_MAXMEM = 160 * 1024 * 1024
_HEADER = struct.Struct(">4sBBII16s12s")


def _passphrase_bytes(passphrase: str) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("passphrase must be a non-empty string")
    return passphrase.encode("utf-8")


def _validate_parameters(log_n: int, r: int, p: int) -> None:
    if not MIN_LOG_N <= log_n <= MAX_LOG_N:
        raise ValueError("unsupported scrypt log_n")
    if r != SCRYPT_R or p != SCRYPT_P:
        raise ValueError("unsupported scrypt r or p")


def _derive_key(passphrase: str, salt: bytes, log_n: int, r: int, p: int) -> bytes:
    _validate_parameters(log_n, r, p)
    return hashlib.scrypt(
        _passphrase_bytes(passphrase),
        salt=salt,
        n=1 << log_n,
        r=r,
        p=p,
        dklen=KEY_LENGTH,
        maxmem=SCRYPT_MAXMEM,
    )


def serialize_unencrypted_pkcs8(private_key: Any) -> bytes:
    """Serialize a supported key as in-memory unencrypted PKCS#8 DER."""
    return private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def seal_pkcs8(
    private_key: Any,
    passphrase: str,
    *,
    log_n: int = DEFAULT_LOG_N,
) -> bytes:
    """Return the Phase 2A QSKS v1 envelope bytes."""
    _validate_parameters(log_n, SCRYPT_R, SCRYPT_P)
    der = serialize_unencrypted_pkcs8(private_key)
    salt = secrets.token_bytes(SALT_LENGTH)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    header = _HEADER.pack(
        MAGIC, FORMAT_VERSION, log_n, SCRYPT_R, SCRYPT_P, salt, nonce
    )
    encrypted = AESGCM(_derive_key(passphrase, salt, log_n, SCRYPT_R, SCRYPT_P)).encrypt(
        nonce, der, header
    )
    return header + encrypted


def open_pkcs8(envelope: bytes, passphrase: str) -> Any:
    """Authenticate and load the DER key in memory; never writes it to disk."""
    if not isinstance(envelope, bytes) or len(envelope) < _HEADER.size + TAG_LENGTH:
        raise ValueError("malformed envelope")
    try:
        magic, version, log_n, r, p, salt, nonce = _HEADER.unpack_from(envelope)
    except struct.error as exc:
        raise ValueError("malformed envelope") from exc
    if magic != MAGIC:
        raise ValueError("invalid envelope magic")
    if version != FORMAT_VERSION:
        raise ValueError("unsupported envelope version")
    _validate_parameters(log_n, r, p)
    header = envelope[:_HEADER.size]
    key = _derive_key(passphrase, salt, log_n, r, p)
    der = AESGCM(key).decrypt(nonce, envelope[_HEADER.size :], header)
    return serialization.load_der_private_key(der, password=None)
