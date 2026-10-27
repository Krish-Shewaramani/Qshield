"""Application orchestration for the local `.qshield` API."""

from __future__ import annotations

from backend.app.crypto import key_serialization
from backend.app.crypto.crypto_errors import CryptoInputError
from backend.app.services import package_service
from backend.app.file_exchange.errors import PackageError
from backend.app.key_management.errors import (
    KeyManagementError,
    KeyNotFoundError,
)
from backend.app.key_management.unlock_rate_limiter import UnlockAdmissionError
from backend.app.key_management.contacts import (
    RecipientBlockedError,
    ensure_recipient_not_retired,
)
from backend.app.key_management.fingerprints import key_id
from backend.app.key_management.key_service import KeyService
from backend.app.key_management.models import TrustedKeyRecord
from backend.app.key_management.trust_store import (
    USAGE_FULL,
    USAGE_VERIFY_ONLY,
    TrustStore,
)


class FileExchangeInputError(Exception):
    """A safe-to-report rejected exchange request."""


class FileExchangeMissingRecord(FileExchangeInputError):
    """A selected local key or trusted key does not exist."""


class FileExchangeUntrustedSender(FileExchangeInputError):
    """The selected sender is not an explicitly trusted ML-DSA key."""


class FileExchangePrivateKeyUnavailable(FileExchangeInputError):
    """A private-key record could not be found, parsed, or unlocked."""


class FileExchangeUnlockRateLimited(FileExchangeInputError):
    """Global unlock admission rejected the operation."""


class FileExchangeRecipientBlocked(FileExchangeInputError):
    """A contact retired the recipient key, or contact state could not be checked."""


class FileExchangeService:
    def __init__(self, keys: KeyService, trust: TrustStore):
        self.keys = keys
        self.trust = trust

    def create_package(
        self,
        filename: str,
        file_bytes: bytes,
        recipient_key_id: str,
        signing_key_id: str,
        passphrase: str,
    ) -> bytes:
        recipient = self._trusted_key(recipient_key_id, key_serialization.MLKEM)
        try:
            recipient_public = key_serialization.import_public_key(
                recipient.public_key_pem.encode("ascii")
            )
        except (CryptoInputError, UnicodeEncodeError, ValueError, TypeError) as exc:
            raise FileExchangeInputError from exc
        try:
            signing_private = self.keys.load_private_key(
                signing_key_id, passphrase, key_serialization.MLDSA
            )
        except UnlockAdmissionError as exc:
            raise FileExchangeUnlockRateLimited from exc
        except KeyManagementError as exc:
            raise FileExchangePrivateKeyUnavailable from exc
        try:
            return package_service.create_package(filename, file_bytes, recipient_public, signing_private)
        except (PackageError, ValueError, TypeError) as exc:
            raise FileExchangeInputError from exc

    def verify_package(self, package_bytes: bytes, sender_key_id: str):
        try:
            parsed = package_service.parse_package(package_bytes)
        except PackageError as exc:
            raise FileExchangeInputError from exc
        if parsed.header.sender_key_id.hex() != sender_key_id:
            raise FileExchangeUntrustedSender from None
        try:
            sender = self._trusted_key(sender_key_id, key_serialization.MLDSA)
        except FileExchangeMissingRecord as exc:
            # Absence from the trust store means this signer is untrusted.
            raise FileExchangeUntrustedSender from exc
        try:
            verified = package_service.verify_package(package_bytes, sender)
        except PackageError as exc:
            raise FileExchangeUntrustedSender from exc
        return verified

    def decrypt_package(
        self,
        package_bytes: bytes,
        recipient_key_id: str,
        sender_key_id: str,
        passphrase: str,
    ) -> tuple[str, bytes]:
        # Signature and explicit trust checks happen before unlocking the
        # recipient private key, matching the documented processing order.
        verified = self.verify_package(package_bytes, sender_key_id)
        if verified.package.header.recipient_key_id.hex() != recipient_key_id:
            raise FileExchangeInputError from None
        try:
            recipient_private = self.keys.load_private_key(
                recipient_key_id, passphrase, key_serialization.MLKEM
            )
        except UnlockAdmissionError as exc:
            raise FileExchangeUnlockRateLimited from exc
        except KeyManagementError as exc:
            raise FileExchangePrivateKeyUnavailable from exc
        try:
            return package_service.decrypt_verified_package(verified, recipient_private)
        except PackageError as exc:
            raise FileExchangeInputError from exc

    def _trusted_key(self, identifier: str, expected_algorithm: str) -> TrustedKeyRecord:
        if expected_algorithm == key_serialization.MLKEM:
            # Contact lifecycle is checked before trust: a retired contact key is
            # never a recipient, even if its trust-store entry is stale.
            try:
                # Derived from the trust store, so no construction path skips the guard.
                ensure_recipient_not_retired(self.trust.directory, identifier)
            except RecipientBlockedError as exc:
                raise FileExchangeRecipientBlocked from exc
        try:
            record = self.trust.get(identifier)
        except KeyNotFoundError as exc:
            raise FileExchangeMissingRecord from exc
        except KeyManagementError as exc:
            raise FileExchangeInputError from exc
        if not record.trusted or record.algorithm != expected_algorithm:
            raise FileExchangeUntrustedSender from None
        # Recipients (new encryption) need full trust. Senders may also be
        # verification-only retired contact keys, so older packages still verify.
        allowed_usages = (
            {USAGE_FULL}
            if expected_algorithm == key_serialization.MLKEM
            else {USAGE_FULL, USAGE_VERIFY_ONLY}
        )
        if record.usage not in allowed_usages:
            raise FileExchangeUntrustedSender from None
        try:
            public_key = key_serialization.import_public_key(
                record.public_key_pem.encode("ascii")
            )
            if key_serialization.algorithm_for_key(public_key) != expected_algorithm:
                raise FileExchangeUntrustedSender
            if key_id(public_key) != identifier:
                raise FileExchangeUntrustedSender
        except (CryptoInputError, UnicodeEncodeError, ValueError, TypeError) as exc:
            raise FileExchangeInputError from exc
        return record
