"""Encrypted private-key record persistence using the QSKS v1 envelope."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa

from backend.app.crypto import key_serialization
from backend.app.crypto.crypto_errors import CryptoInputError
from backend.app.core.windows_security import ensure_private_directory
from .errors import (
    FingerprintMismatchError,
    KeyNotFoundError,
    KeyRecordError,
    KeyTypeMismatchError,
    KeyUnlockError,
)
from .fingerprints import key_id as calculate_key_id
from .models import KeyRecord
from .qks_envelope import open_pkcs8, seal_pkcs8
from .unlock_rate_limiter import (
    UnlockRateLimiter,
    shared_unlock_limiter,
)

_KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_KEY_TYPES = (mlkem.MLKEM768PrivateKey, mldsa.MLDSA65PrivateKey)


class KeyStore:
    """Store QSKS envelopes and public, non-secret record metadata."""

    def __init__(
        self,
        directory: Path,
        *,
        unlock_limiter: UnlockRateLimiter | None = None,
    ):
        self.directory = Path(directory)
        self.unlock_limiter = unlock_limiter or shared_unlock_limiter()
        ensure_private_directory(self.directory)

    def save_private_key(self, private_key: object, label: str, passphrase: str) -> KeyRecord:
        if not isinstance(private_key, _PRIVATE_KEY_TYPES):
            raise KeyTypeMismatchError("unsupported private key type")
        label = _validate_label(label)
        algorithm = key_serialization.algorithm_for_key(private_key)
        public_key = private_key.public_key()
        identifier = calculate_key_id(public_key)
        public_pem = key_serialization.export_public_key(public_key).decode("ascii")
        envelope = seal_pkcs8(private_key, passphrase)
        record = KeyRecord(algorithm, identifier, label, public_pem)
        envelope_path, metadata_path = self._paths(identifier)
        if envelope_path.exists() or metadata_path.exists():
            raise FileExistsError("a key record with this fingerprint already exists")
        try:
            _atomic_write(envelope_path, envelope)
            _atomic_write(metadata_path, _record_json(record))
        except Exception:
            envelope_path.unlink(missing_ok=True)
            metadata_path.unlink(missing_ok=True)
            raise
        return record

    def get_record(self, identifier: str) -> KeyRecord:
        envelope_path, metadata_path = self._paths(identifier)
        if not metadata_path.is_file() or not envelope_path.is_file():
            raise KeyNotFoundError("key record not found")
        try:
            data = json.loads(metadata_path.read_text(encoding="utf-8"))
            record = _parse_record(data)
        except (OSError, UnicodeError, json.JSONDecodeError, KeyRecordError) as exc:
            raise KeyRecordError("key record metadata is malformed") from exc
        if record.key_id != identifier:
            raise FingerprintMismatchError("key record fingerprint does not match its selected ID")
        public_key = _import_record_public(record)
        if key_serialization.algorithm_for_key(public_key) != record.algorithm:
            raise KeyTypeMismatchError("key record algorithm does not match its public key")
        if calculate_key_id(public_key) != identifier:
            raise FingerprintMismatchError("stored public key does not match its key ID")
        return record

    def list_records(self) -> list[KeyRecord]:
        records = []
        for metadata_path in sorted(self.directory.glob("*.json")):
            records.append(self.get_record(metadata_path.stem))
        return records

    def export_public_key(self, identifier: str) -> bytes:
        record = self.get_record(identifier)
        return record.public_key_pem.encode("ascii")

    def load_private_key(
        self, identifier: str, passphrase: str, expected_algorithm: str
    ) -> object:
        # Admission precedes record lookup and type validation: malformed or
        # absent IDs still consume global capacity, while only QSKS AEAD
        # authentication failures affect the per-key counter.
        with self.unlock_limiter.admit(identifier) as attempt:
            if expected_algorithm not in key_serialization.SUPPORTED_ALGORITHMS:
                raise KeyTypeMismatchError("unsupported expected key type")
            record = self.get_record(identifier)
            if record.algorithm != expected_algorithm:
                raise KeyTypeMismatchError("selected key record has a different key type")
            envelope_path, _ = self._paths(identifier)
            try:
                private_key = open_pkcs8(envelope_path.read_bytes(), passphrase)
            except InvalidTag as exc:
                attempt.authentication_failed()
                raise KeyUnlockError("could not unlock private key") from exc
            except (OSError, ValueError, TypeError) as exc:
                raise KeyRecordError("private-key envelope is invalid or could not be loaded") from exc
            # QSKS authentication succeeded even if later record consistency
            # checks fail, so this is a successful passphrase attempt.
            attempt.authentication_succeeded()
            try:
                actual_algorithm = key_serialization.algorithm_for_key(private_key)
                actual_public_key = key_serialization.public_key_for(private_key)
            except CryptoInputError as exc:
                raise KeyTypeMismatchError("stored private key is not an approved key type") from exc
            if actual_algorithm != expected_algorithm:
                raise KeyTypeMismatchError("loaded private key has a different key type")
            if calculate_key_id(actual_public_key) != identifier:
                raise FingerprintMismatchError("loaded private key does not match the selected key ID")
            return private_key

    def delete(self, identifier: str) -> None:
        envelope_path, metadata_path = self._paths(identifier)
        if not envelope_path.is_file() or not metadata_path.is_file():
            raise KeyNotFoundError("key record not found")
        envelope_path.unlink()
        metadata_path.unlink()

    def _paths(self, identifier: str) -> tuple[Path, Path]:
        if not isinstance(identifier, str) or not _KEY_ID_RE.fullmatch(identifier):
            raise KeyNotFoundError("invalid key ID")
        return self.directory / f"{identifier}.qks", self.directory / f"{identifier}.json"


def _validate_label(label: str) -> str:
    if not isinstance(label, str) or not label.strip() or len(label) > 128:
        raise ValueError("label must contain 1 to 128 characters")
    return label.strip()


def _record_json(record: KeyRecord) -> bytes:
    data = {
        "algorithm": record.algorithm,
        "key_id": record.key_id,
        "label": record.label,
        "public_key_pem": record.public_key_pem,
    }
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _parse_record(data: object) -> KeyRecord:
    if not isinstance(data, dict):
        raise KeyRecordError("record must be an object")
    try:
        algorithm, identifier, label, public_pem = (
            data["algorithm"], data["key_id"], data["label"], data["public_key_pem"]
        )
    except KeyError as exc:
        raise KeyRecordError("record is missing required fields") from exc
    if algorithm not in key_serialization.SUPPORTED_ALGORITHMS:
        raise KeyRecordError("record has an unsupported algorithm")
    if not isinstance(identifier, str) or not _KEY_ID_RE.fullmatch(identifier):
        raise KeyRecordError("record has an invalid key ID")
    if not isinstance(label, str) or not label.strip() or len(label) > 128:
        raise KeyRecordError("record has an invalid label")
    if not isinstance(public_pem, str):
        raise KeyRecordError("record has an invalid public key")
    return KeyRecord(algorithm, identifier, label, public_pem)


def _import_record_public(record: KeyRecord) -> object:
    try:
        return key_serialization.import_public_key(record.public_key_pem.encode("ascii"))
    except (UnicodeEncodeError, CryptoInputError) as exc:
        raise KeyRecordError("record contains an invalid public key") from exc


def _atomic_write(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as temporary_file:
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
