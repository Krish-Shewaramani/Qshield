"""Cryptographic orchestration for `.qshield` v1 packages.

This layer composes the existing ML-KEM, ML-DSA, HKDF, and AES-GCM services.
It has no API, disk, upload, or plaintext-temporary-file behavior.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, InvalidTag

from backend.app.crypto import (
    kem_service,
    key_derivation,
    key_serialization,
    signature_service,
    symmetric_encryption,
)
from backend.app.crypto.crypto_errors import CryptoInputError
from backend.app.file_exchange.errors import (
    PackageDecryptionError,
    PackageFormatError,
    PackageRecipientError,
    PackageVerificationError,
)
from backend.app.file_exchange.protocol import (
    AEAD_ALGORITHM_ID,
    FLAGS,
    KDF_ALGORITHM_ID,
    KEM_ALGORITHM_ID,
    SIGNATURE_ALGORITHM_ID,
    VERSION,
    PackageHeader,
    ParsedPackage,
    assemble_package,
    build_encrypted_payload,
    parse_decrypted_payload,
    parse_package,
    serialize_header,
)
from backend.app.key_management.fingerprints import key_id
from backend.app.key_management.models import TrustedKeyRecord

HKDF_INFO_PREFIX = b"QuantumShield/v1/aes-256-gcm-key"
SIGNATURE_CONTEXT = b"QuantumShield/v1/package"
_SHARED_SECRET_SIZE = 32
_VERIFICATION_TOKEN = object()


@dataclass(frozen=True)
class VerifiedPackage:
    """A structurally parsed package whose trusted sender signature passed."""

    package: ParsedPackage
    sender_key_id: str
    _token: object = field(repr=False, compare=False)


def create_package(
    filename: str,
    file_bytes: bytes,
    recipient_public_key: object,
    sender_private_key: object,
    *,
    created_at: int | None = None,
) -> bytes:
    """Encrypt a file payload to an ML-KEM recipient and sign it with ML-DSA."""
    payload = build_encrypted_payload(filename, file_bytes)
    try:
        if key_serialization.algorithm_for_key(recipient_public_key) != key_serialization.MLKEM:
            raise PackageFormatError("recipient key must be ML-KEM-768")
        if key_serialization.algorithm_for_key(sender_private_key) != key_serialization.MLDSA:
            raise PackageFormatError("sender key must be ML-DSA-65")
        sender_public_key = key_serialization.public_key_for(sender_private_key)
        sender_id = bytes.fromhex(key_id(sender_public_key))
        recipient_id = bytes.fromhex(key_id(recipient_public_key))
    except CryptoInputError as exc:
        raise PackageFormatError("unsupported sender or recipient key") from exc
    except (TypeError, ValueError) as exc:
        if isinstance(exc, PackageFormatError):
            raise
        raise PackageFormatError("invalid sender or recipient key") from exc

    timestamp = int(time.time()) if created_at is None else created_at
    nonce = symmetric_encryption.generate_nonce()
    kem_ciphertext, shared_secret = kem_service.encapsulate(recipient_public_key)
    if len(shared_secret) != _SHARED_SECRET_SIZE:
        raise PackageFormatError("ML-KEM-768 returned an invalid shared-secret size")
    ciphertext_len = len(payload) + 16
    header = PackageHeader(
        VERSION,
        KEM_ALGORITHM_ID,
        SIGNATURE_ALGORITHM_ID,
        AEAD_ALGORITHM_ID,
        KDF_ALGORITHM_ID,
        FLAGS,
        timestamp,
        sender_id,
        recipient_id,
        kem_ciphertext,
        nonce,
        ciphertext_len,
    )
    header_bytes = serialize_header(header)
    aes_key = key_derivation.derive_key(
        shared_secret,
        salt=None,
        info=HKDF_INFO_PREFIX + hashlib.sha256(header_bytes).digest(),
        length=32,
    )
    _, aead_output = symmetric_encryption.encrypt(
        aes_key, payload, aad=header_bytes, nonce=nonce
    )
    signature = signature_service.sign(
        sender_private_key,
        header_bytes + aead_output,
        context=SIGNATURE_CONTEXT,
    )
    return assemble_package(header, aead_output, signature)


def verify_package(
    package_bytes: bytes,
    trusted_sender: TrustedKeyRecord,
) -> VerifiedPackage:
    """Parse a package and verify its sender using an explicitly trusted key."""
    package = parse_package(package_bytes)
    return _verify_parsed_package(package, trusted_sender)


def _verify_parsed_package(
    package: ParsedPackage,
    trusted_sender: TrustedKeyRecord,
) -> VerifiedPackage:
    public_key = _trusted_sender_public_key(trusted_sender, package)
    try:
        signature_service.verify(
            public_key,
            package.signature,
            package.header_bytes + package.aead_output,
            context=SIGNATURE_CONTEXT,
        )
    except InvalidSignature as exc:
        raise PackageVerificationError("package signature verification failed") from exc
    return VerifiedPackage(package, trusted_sender.key_id, _VERIFICATION_TOKEN)


def decrypt_package(
    package_bytes: bytes,
    trusted_sender: TrustedKeyRecord,
    recipient_private_key: object,
) -> tuple[str, bytes]:
    """Verify first, then decrypt and return the authenticated original payload."""
    package = parse_package(package_bytes)
    verified = _verify_parsed_package(package, trusted_sender)
    return decrypt_verified_package(verified, recipient_private_key)


def decrypt_verified_package(
    verified: VerifiedPackage,
    recipient_private_key: object,
) -> tuple[str, bytes]:
    """Decrypt a package after trusted sender verification has succeeded."""
    if not isinstance(verified, VerifiedPackage) or verified._token is not _VERIFICATION_TOKEN:
        raise PackageVerificationError("a verified package is required")
    header = verified.package.header
    _validate_recipient_key(header, recipient_private_key)

    try:
        shared_secret = kem_service.decapsulate(
            recipient_private_key, header.kem_ciphertext
        )
        if len(shared_secret) != _SHARED_SECRET_SIZE:
            raise PackageDecryptionError("package decryption failed")
        aes_key = key_derivation.derive_key(
            shared_secret,
            salt=None,
            info=HKDF_INFO_PREFIX + hashlib.sha256(verified.package.header_bytes).digest(),
            length=32,
        )
        payload = symmetric_encryption.decrypt(
            aes_key,
            header.nonce,
            verified.package.aead_output,
            aad=verified.package.header_bytes,
        )
    except (InvalidTag, CryptoInputError, TypeError, ValueError) as exc:
        raise PackageDecryptionError("package authentication or decryption failed") from exc
    return parse_decrypted_payload(payload)


def _validate_recipient_key(header: PackageHeader, recipient_private_key: object) -> None:
    try:
        if key_serialization.algorithm_for_key(recipient_private_key) != key_serialization.MLKEM:
            raise PackageRecipientError("recipient private key must be ML-KEM-768")
        actual_recipient_id = key_id(recipient_private_key.public_key())
    except CryptoInputError as exc:
        raise PackageRecipientError("invalid recipient private key") from exc
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, PackageRecipientError):
            raise
        raise PackageRecipientError("invalid recipient private key") from exc
    if actual_recipient_id != header.recipient_key_id.hex():
        raise PackageRecipientError("package is addressed to a different recipient")


def _trusted_sender_public_key(
    trusted_sender: TrustedKeyRecord,
    package: ParsedPackage,
):
    if not isinstance(trusted_sender, TrustedKeyRecord) or trusted_sender.trusted is not True:
        raise PackageVerificationError("a trusted sender key is required")
    if trusted_sender.algorithm != key_serialization.MLDSA:
        raise PackageVerificationError("trusted sender key must be ML-DSA-65")
    try:
        public_key = key_serialization.import_public_key(
            trusted_sender.public_key_pem.encode("ascii")
        )
        if key_serialization.algorithm_for_key(public_key) != key_serialization.MLDSA:
            raise PackageVerificationError("trusted sender key must be ML-DSA-65")
        actual_id = key_id(public_key)
    except (AttributeError, UnicodeEncodeError, CryptoInputError, ValueError) as exc:
        if isinstance(exc, PackageVerificationError):
            raise
        raise PackageVerificationError("trusted sender key is invalid") from exc
    if actual_id != trusted_sender.key_id or actual_id != package.header.sender_key_id.hex():
        raise PackageVerificationError("package sender is not the selected trusted key")
    return public_key
