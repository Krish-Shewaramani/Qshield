"""Experimental Windows PKCS#8 and scrypt/AES-GCM storage proof of concept.

This module is intentionally isolated from the planned application packages.
It keeps private-key serialization in memory and never writes plaintext key
bytes to disk. Python does not guarantee that those temporary bytes are erased.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
from dataclasses import dataclass
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
# 128 MiB estimated ROMix allocation at N=131072, r=8, plus 32 MiB headroom.
SCRYPT_MAXMEM = 160 * 1024 * 1024
# magic, version, log_n, r, p, salt, nonce
_HEADER = struct.Struct(">4sBBII16s12s")


@dataclass(frozen=True)
class EnvelopeParameters:
    log_n: int
    r: int = SCRYPT_R
    p: int = SCRYPT_P

    @property
    def estimated_scrypt_memory_bytes(self) -> int:
        # The dominant scrypt ROMix allocation is approximately 128 * N * r.
        return 128 * (1 << self.log_n) * self.r


def _validate_parameters(log_n: int, r: int, p: int) -> EnvelopeParameters:
    if not MIN_LOG_N <= log_n <= MAX_LOG_N:
        raise ValueError("unsupported scrypt log_n")
    if r != SCRYPT_R or p != SCRYPT_P:
        raise ValueError("unsupported scrypt r or p")
    return EnvelopeParameters(log_n=log_n, r=r, p=p)


def _passphrase_bytes(passphrase: str) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("passphrase must be a non-empty string")
    return passphrase.encode("utf-8")


def _derive_key(passphrase: str, salt: bytes, params: EnvelopeParameters) -> bytes:
    return hashlib.scrypt(
        _passphrase_bytes(passphrase),
        salt=salt,
        n=1 << params.log_n,
        r=params.r,
        p=params.p,
        dklen=KEY_LENGTH,
        maxmem=SCRYPT_MAXMEM,
    )


def serialize_unencrypted_pkcs8(private_key: Any) -> bytes:
    """Serialize a supported private key to in-memory unencrypted PKCS#8 DER."""
    return private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def seal_pkcs8(private_key: Any, passphrase: str, *, log_n: int = DEFAULT_LOG_N) -> bytes:
    """Return a versioned binary envelope containing authenticated PKCS#8."""
    params = _validate_parameters(log_n, SCRYPT_R, SCRYPT_P)
    clear_pkcs8 = serialize_unencrypted_pkcs8(private_key)
    salt = secrets.token_bytes(SALT_LENGTH)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    header = _HEADER.pack(MAGIC, FORMAT_VERSION, params.log_n, params.r, params.p, salt, nonce)
    ciphertext_and_tag = AESGCM(_derive_key(passphrase, salt, params)).encrypt(
        nonce, clear_pkcs8, header
    )
    return header + ciphertext_and_tag


def open_pkcs8(envelope: bytes, passphrase: str) -> Any:
    """Authenticate, decrypt, and load an envelope without writing key bytes."""
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
    params = _validate_parameters(log_n, r, p)
    header = envelope[:_HEADER.size]
    ciphertext_and_tag = envelope[_HEADER.size:]
    clear_pkcs8 = AESGCM(_derive_key(passphrase, salt, params)).decrypt(
        nonce, ciphertext_and_tag, header
    )
    return serialization.load_der_private_key(clear_pkcs8, password=None)


# Small DER reader used only to inspect the parameters emitted by the installed
# cryptography backend. It deliberately rejects BER/indefinite and high-tag forms.
def _tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise ValueError("high-tag-number DER is unsupported")
    first_length = data[offset + 1]
    if first_length < 0x80:
        length, content_start = first_length, offset + 2
    else:
        octets = first_length & 0x7F
        if octets == 0 or octets > 4 or offset + 2 + octets > len(data):
            raise ValueError("invalid DER length")
        if data[offset + 2] == 0:
            raise ValueError("non-minimal DER length")
        length = int.from_bytes(data[offset + 2:offset + 2 + octets], "big")
        if length < 0x80:
            raise ValueError("non-minimal DER length")
        content_start = offset + 2 + octets
    content_end = content_start + length
    if content_end > len(data):
        raise ValueError("truncated DER value")
    return tag, content_start, content_end, content_end


def _children(data: bytes, start: int, end: int) -> list[tuple[int, bytes]]:
    result = []
    offset = start
    while offset < end:
        tag, content_start, content_end, next_offset = _tlv(data, offset)
        result.append((tag, data[content_start:content_end]))
        offset = next_offset
    if offset != end:
        raise ValueError("invalid DER container")
    return result


def _decode_oid(encoded: bytes) -> str:
    if not encoded:
        raise ValueError("empty DER OID")
    values = []
    value = 0
    for octet in encoded:
        value = (value << 7) | (octet & 0x7F)
        if not octet & 0x80:
            values.append(value)
            value = 0
    if encoded[-1] & 0x80:
        raise ValueError("truncated DER OID")
    first = values.pop(0)
    arc0 = min(first // 40, 2)
    arcs = [arc0, first - 40 * arc0, *values]
    return ".".join(str(arc) for arc in arcs)


def _sequence(data: bytes) -> list[tuple[int, bytes]]:
    tag, start, end, next_offset = _tlv(data, 0)
    if tag != 0x30 or next_offset != len(data):
        raise ValueError("expected one DER SEQUENCE")
    return _children(data, start, end)


def _sequence_content(content: bytes) -> list[tuple[int, bytes]]:
    return _children(content, 0, len(content))


def _integer(content: bytes) -> int:
    if not content or content[0] & 0x80:
        raise ValueError("unsupported DER INTEGER")
    return int.from_bytes(content, "big")


def inspect_encrypted_pkcs8(der: bytes) -> dict[str, Any]:
    """Report observed PBES2 parameters; fail explicitly on unknown structures."""
    outer = _sequence(der)
    if len(outer) != 2 or outer[0][0] != 0x30 or outer[1][0] != 0x04:
        raise ValueError("not an EncryptedPrivateKeyInfo")
    alg = _sequence_content(outer[0][1])
    if len(alg) != 2 or alg[0][0] != 0x06:
        raise ValueError("unsupported encryption AlgorithmIdentifier")
    pbes2_oid = _decode_oid(alg[0][1])
    if pbes2_oid != "1.2.840.113549.1.5.13":
        raise ValueError(f"unsupported encryption OID: {pbes2_oid}")
    params = _sequence_content(alg[1][1])
    if len(params) != 2 or params[0][0] != 0x30 or params[1][0] != 0x30:
        raise ValueError("unsupported PBES2 parameters")
    kdf = _sequence_content(params[0][1])
    cipher = _sequence_content(params[1][1])
    if len(kdf) != 2 or kdf[0][0] != 0x06 or kdf[1][0] != 0x30:
        raise ValueError("unsupported PBES2 KDF")
    if len(cipher) < 1 or cipher[0][0] != 0x06:
        raise ValueError("unsupported PBES2 cipher")
    kdf_oid = _decode_oid(kdf[0][1])
    cipher_oid = _decode_oid(cipher[0][1])
    if kdf_oid != "1.2.840.113549.1.5.12":
        raise ValueError(f"unsupported PBES2 KDF OID: {kdf_oid}")
    pbkdf2 = _sequence_content(kdf[1][1])
    if len(pbkdf2) < 2 or pbkdf2[0][0] != 0x04 or pbkdf2[1][0] != 0x02:
        raise ValueError("unsupported PBKDF2 parameters")
    prf = "default-hmac-sha1"
    prf_entries = [entry for entry in pbkdf2[2:] if entry[0] == 0x30]
    if prf_entries:
        prf_alg = _sequence_content(prf_entries[0][1])
        if not prf_alg or prf_alg[0][0] != 0x06:
            raise ValueError("unsupported PBKDF2 PRF AlgorithmIdentifier")
        prf = _decode_oid(prf_alg[0][1])
    cipher_names = {
        "2.16.840.1.101.3.4.1.42": "AES-256-CBC",
        "2.16.840.1.101.3.4.1.2": "AES-128-CBC",
    }
    return {
        "encryption_scheme_oid": pbes2_oid,
        "kdf_oid": kdf_oid,
        "kdf": "PBKDF2",
        "kdf_salt_length_bytes": len(pbkdf2[0][1]),
        "kdf_iterations": _integer(pbkdf2[1][1]),
        "prf_oid": prf,
        "cipher_oid": cipher_oid,
        "cipher": cipher_names.get(cipher_oid, "unknown"),
    }


def load_unencrypted_pkcs8(der: bytes) -> Any:
    """Use cryptography's generic PKCS#8 loader for ML-KEM/ML-DSA DER."""
    return serialization.load_der_private_key(der, password=None)


def load_encrypted_pkcs8(der: bytes, passphrase: bytes) -> Any:
    """Use cryptography's generic encrypted-PKCS#8 loader."""
    return serialization.load_der_private_key(der, password=passphrase)


def encrypted_pkcs8(private_key: Any, passphrase: bytes) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )
