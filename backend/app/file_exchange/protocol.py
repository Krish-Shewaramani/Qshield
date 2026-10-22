"""Fixed-width `.qshield` v1 serialization and validation.

This module contains no storage, networking, or cryptographic operations. All
integer fields are unsigned big-endian as specified in CRYPTOGRAPHIC_PROTOCOL.md.
"""

from __future__ import annotations

import struct
import unicodedata
from dataclasses import dataclass

from .errors import PackageFormatError

MAGIC = b"QSHIELD\x00"
VERSION = 1
KEM_ALGORITHM_ID = 1
SIGNATURE_ALGORITHM_ID = 1
AEAD_ALGORITHM_ID = 1
KDF_ALGORITHM_ID = 1
FLAGS = 0

HEADER_SIZE = 1196
SIGNATURE_SIZE = 3309
GCM_TAG_SIZE = 16
FILENAME_LENGTH_SIZE = 2
MIN_FILENAME_SIZE = 1
MAX_FILENAME_SIZE = 255
MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_PACKAGE_SIZE = MAX_FILE_SIZE + 64 * 1024
MIN_AEAD_OUTPUT_SIZE = FILENAME_LENGTH_SIZE + MIN_FILENAME_SIZE + GCM_TAG_SIZE
MAX_AEAD_OUTPUT_SIZE = (
    FILENAME_LENGTH_SIZE + MAX_FILENAME_SIZE + MAX_FILE_SIZE + GCM_TAG_SIZE
)

_HEADER = struct.Struct(">8sHBBBBHQ32s32s1088s12sQ")
if _HEADER.size != HEADER_SIZE:  # Keep the documented constant tied to the layout.
    raise RuntimeError(".qshield v1 header format has an invalid size")


@dataclass(frozen=True)
class PackageHeader:
    version: int
    kem_algorithm_id: int
    signature_algorithm_id: int
    aead_algorithm_id: int
    kdf_algorithm_id: int
    flags: int
    created_at: int
    sender_key_id: bytes
    recipient_key_id: bytes
    kem_ciphertext: bytes
    nonce: bytes
    ciphertext_len: int


@dataclass(frozen=True)
class ParsedPackage:
    header: PackageHeader
    header_bytes: bytes
    aead_output: bytes
    signature: bytes


def _validate_header(header: PackageHeader) -> None:
    if not isinstance(header, PackageHeader):
        raise PackageFormatError("invalid package header")
    for value, field in (
        (header.version, "version"),
        (header.kem_algorithm_id, "KEM algorithm ID"),
        (header.signature_algorithm_id, "signature algorithm ID"),
        (header.aead_algorithm_id, "AEAD algorithm ID"),
        (header.kdf_algorithm_id, "KDF algorithm ID"),
        (header.flags, "flags"),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise PackageFormatError(f"invalid package {field}")
    if header.version != VERSION:
        raise PackageFormatError("unsupported package version")
    if (
        header.kem_algorithm_id != KEM_ALGORITHM_ID
        or header.signature_algorithm_id != SIGNATURE_ALGORITHM_ID
        or header.aead_algorithm_id != AEAD_ALGORITHM_ID
        or header.kdf_algorithm_id != KDF_ALGORITHM_ID
    ):
        raise PackageFormatError("unsupported package algorithm")
    if header.flags != FLAGS:
        raise PackageFormatError("unsupported package flags")
    if not isinstance(header.created_at, int) or isinstance(header.created_at, bool):
        raise PackageFormatError("invalid package timestamp")
    if not 0 <= header.created_at <= 0xFFFFFFFFFFFFFFFF:
        raise PackageFormatError("invalid package timestamp")
    for value, expected_size, field in (
        (header.sender_key_id, 32, "sender key ID"),
        (header.recipient_key_id, 32, "recipient key ID"),
        (header.kem_ciphertext, 1088, "ML-KEM ciphertext"),
        (header.nonce, 12, "AES-GCM nonce"),
    ):
        if not isinstance(value, bytes) or len(value) != expected_size:
            raise PackageFormatError(f"invalid {field} size")
    if not isinstance(header.ciphertext_len, int) or isinstance(header.ciphertext_len, bool):
        raise PackageFormatError("invalid ciphertext length")
    if not MIN_AEAD_OUTPUT_SIZE <= header.ciphertext_len <= MAX_AEAD_OUTPUT_SIZE:
        raise PackageFormatError("ciphertext length is outside the permitted range")


def serialize_header(header: PackageHeader) -> bytes:
    """Serialize a validated header to its unique 1,196-byte representation."""
    _validate_header(header)
    try:
        return _HEADER.pack(
            MAGIC,
            header.version,
            header.kem_algorithm_id,
            header.signature_algorithm_id,
            header.aead_algorithm_id,
            header.kdf_algorithm_id,
            header.flags,
            header.created_at,
            header.sender_key_id,
            header.recipient_key_id,
            header.kem_ciphertext,
            header.nonce,
            header.ciphertext_len,
        )
    except (struct.error, TypeError) as exc:
        raise PackageFormatError("invalid package header") from exc


def parse_header(header_bytes: bytes) -> PackageHeader:
    """Parse and validate exactly one fixed-width header."""
    if not isinstance(header_bytes, bytes) or len(header_bytes) != HEADER_SIZE:
        raise PackageFormatError("malformed package header")
    try:
        (
            magic,
            version,
            kem_id,
            signature_id,
            aead_id,
            kdf_id,
            flags,
            created_at,
            sender_key_id,
            recipient_key_id,
            kem_ciphertext,
            nonce,
            ciphertext_len,
        ) = _HEADER.unpack(header_bytes)
    except struct.error as exc:
        raise PackageFormatError("malformed package header") from exc
    if magic != MAGIC:
        raise PackageFormatError("invalid package magic")
    header = PackageHeader(
        version,
        kem_id,
        signature_id,
        aead_id,
        kdf_id,
        flags,
        created_at,
        sender_key_id,
        recipient_key_id,
        kem_ciphertext,
        nonce,
        ciphertext_len,
    )
    _validate_header(header)
    return header


def assemble_package(header: PackageHeader, aead_output: bytes, signature: bytes) -> bytes:
    """Join validated header, AEAD output, and fixed-size signature."""
    header_bytes = serialize_header(header)
    if not isinstance(aead_output, bytes) or len(aead_output) != header.ciphertext_len:
        raise PackageFormatError("AEAD output length does not match the header")
    if not isinstance(signature, bytes) or len(signature) != SIGNATURE_SIZE:
        raise PackageFormatError("invalid ML-DSA signature size")
    package = header_bytes + aead_output + signature
    if len(package) > MAX_PACKAGE_SIZE:
        raise PackageFormatError("package exceeds the configured size limit")
    return package


def parse_package(package_bytes: bytes) -> ParsedPackage:
    """Validate package bounds and exact lengths before crypto operations."""
    if not isinstance(package_bytes, bytes):
        raise PackageFormatError("package must be bytes")
    if len(package_bytes) > MAX_PACKAGE_SIZE:
        raise PackageFormatError("package exceeds the configured size limit")
    minimum_package_size = HEADER_SIZE + MIN_AEAD_OUTPUT_SIZE + SIGNATURE_SIZE
    if len(package_bytes) < minimum_package_size:
        raise PackageFormatError("package is truncated")
    header_bytes = package_bytes[:HEADER_SIZE]
    header = parse_header(header_bytes)
    expected_size = HEADER_SIZE + header.ciphertext_len + SIGNATURE_SIZE
    if len(package_bytes) != expected_size:
        raise PackageFormatError("package length does not match its header")
    body_start = HEADER_SIZE
    signature_start = body_start + header.ciphertext_len
    return ParsedPackage(
        header,
        header_bytes,
        package_bytes[body_start:signature_start],
        package_bytes[signature_start:],
    )


def build_encrypted_payload(filename: str, file_bytes: bytes) -> bytes:
    """Encode filename and file bytes without changing the filename."""
    filename_bytes = _validated_filename_bytes(filename)
    if not isinstance(file_bytes, bytes):
        raise PackageFormatError("file content must be bytes")
    if len(file_bytes) > MAX_FILE_SIZE:
        raise PackageFormatError("file exceeds the configured size limit")
    return len(filename_bytes).to_bytes(2, "big") + filename_bytes + file_bytes


def parse_decrypted_payload(payload: bytes) -> tuple[str, bytes]:
    """Decode and validate decrypted filename and file bytes."""
    if not isinstance(payload, bytes) or len(payload) < FILENAME_LENGTH_SIZE + 1:
        raise PackageFormatError("decrypted payload is malformed")
    filename_size = int.from_bytes(payload[:FILENAME_LENGTH_SIZE], "big")
    if not 1 <= filename_size <= MAX_FILENAME_SIZE:
        raise PackageFormatError("decrypted filename length is invalid")
    filename_end = FILENAME_LENGTH_SIZE + filename_size
    if len(payload) < filename_end or len(payload) - filename_end > MAX_FILE_SIZE:
        raise PackageFormatError("decrypted payload length is invalid")
    try:
        filename = payload[FILENAME_LENGTH_SIZE:filename_end].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PackageFormatError("decrypted filename is not valid UTF-8") from exc
    _validated_filename_bytes(filename)
    return filename, payload[filename_end:]


def _validated_filename_bytes(filename: str) -> bytes:
    if not isinstance(filename, str):
        raise PackageFormatError("filename must be text")
    try:
        encoded = filename.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise PackageFormatError("filename is not valid UTF-8") from exc
    if not 1 <= len(encoded) <= MAX_FILENAME_SIZE:
        raise PackageFormatError("filename length must be 1 to 255 UTF-8 bytes")
    if (
        filename.rstrip(" .") in {"", ".", ".."}
        or filename.endswith((" ", "."))
        or any(char in filename for char in ("/", "\\", ":"))
    ):
        raise PackageFormatError("filename must be a single safe path component")
    if any(unicodedata.category(char) == "Cc" for char in filename):
        raise PackageFormatError("filename contains a control character")
    return encoded
