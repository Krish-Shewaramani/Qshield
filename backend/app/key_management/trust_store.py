"""Persistent local trust store requiring explicit fingerprint confirmation."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import replace
from pathlib import Path

from backend.app.crypto import key_serialization
from backend.app.crypto.crypto_errors import CryptoInputError
from backend.app.core.windows_security import ensure_private_directory

from .errors import (
    FingerprintMismatchError,
    KeyManagementError,
    KeyNotFoundError,
    KeyRecordError,
    PublicKeyImportError,
    TrustConfirmationError,
)
from .fingerprints import key_id as calculate_key_id
from .models import PublicKeyCandidate, TrustedKeyRecord

_KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
USAGE_FULL = "full"
USAGE_VERIFY_ONLY = "verify_only"
USAGE_SUSPENDED = "suspended"
TRUST_USAGES = frozenset({USAGE_FULL, USAGE_VERIFY_ONLY, USAGE_SUSPENDED})


class TrustStore:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        ensure_private_directory(self.directory)

    def preview(self, public_key_pem: bytes) -> PublicKeyCandidate:
        try:
            public_key = key_serialization.import_public_key(public_key_pem)
        except CryptoInputError as exc:
            raise PublicKeyImportError("invalid or unsupported SPKI PEM public key") from exc
        return PublicKeyCandidate(
            key_serialization.algorithm_for_key(public_key),
            calculate_key_id(public_key),
            key_serialization.export_public_key(public_key).decode("ascii"),
        )

    def add(
        self,
        public_key_pem: bytes,
        label: str,
        confirmed_fingerprint: str,
        usage: str = USAGE_FULL,
    ) -> TrustedKeyRecord:
        candidate = self.preview(public_key_pem)
        _validate_usage(candidate.algorithm, usage)
        if not isinstance(label, str) or not label.strip() or len(label) > 128:
            raise ValueError("label must contain 1 to 128 characters")
        if not isinstance(confirmed_fingerprint, str) or confirmed_fingerprint.lower() != candidate.key_id:
            raise TrustConfirmationError("explicit matching fingerprint confirmation is required")
        record = TrustedKeyRecord(
            candidate.algorithm,
            candidate.key_id,
            label.strip(),
            candidate.public_key_pem,
            usage=usage,
        )
        record_path = self._path(record.key_id)
        _atomic_write(record_path, _record_json(record))
        return record

    def set_usage(self, identifier: str, usage: str, label: str | None = None) -> TrustedKeyRecord:
        """Change how an existing trusted key may be used, optionally relabelling it."""
        record = self.get(identifier)
        _validate_usage(record.algorithm, usage)
        if label is not None and (not label.strip() or len(label) > 128):
            raise ValueError("label must contain 1 to 128 characters")
        updated = replace(record, usage=usage, label=label.strip() if label is not None else record.label)
        _atomic_write(self._path(identifier), _record_json(updated))
        return updated

    def suspend_encryption_keys(self) -> tuple[list[str], list[str]]:
        """Suspend every fully trusted ML-KEM key. Used by contact-storage recovery.

        Reading the store fails loudly (raises). Per-key write failures are
        returned, and the store is re-read so any key still fully trusted is
        reported as failed. Already-suspended keys are skipped, so retrying is
        safe. ML-DSA keys are never changed.
        """
        suspended: list[str] = []
        failed: list[str] = []
        for record in self.list_records():
            if record.algorithm != key_serialization.MLKEM or record.usage != USAGE_FULL:
                continue
            try:
                self.set_usage(record.key_id, USAGE_SUSPENDED)
                suspended.append(record.key_id)
            except (KeyManagementError, OSError, ValueError):
                failed.append(record.key_id)
        for record in self.list_records():
            if (
                record.algorithm == key_serialization.MLKEM
                and record.usage == USAGE_FULL
                and record.key_id not in failed
            ):
                failed.append(record.key_id)
        return suspended, failed

    def list_records(self) -> list[TrustedKeyRecord]:
        return [self.get(path.stem) for path in sorted(self.directory.glob("*.json"))]

    def get(self, identifier: str) -> TrustedKeyRecord:
        path = self._path(identifier)
        if not path.is_file():
            raise KeyNotFoundError("trusted key not found")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            record = _parse_record(data)
        except (OSError, UnicodeError, json.JSONDecodeError, KeyRecordError) as exc:
            raise KeyRecordError("trusted-key record is malformed") from exc
        if record.key_id != identifier:
            raise FingerprintMismatchError("trusted-key fingerprint does not match its selected ID")
        try:
            candidate = self.preview(record.public_key_pem.encode("ascii"))
        except (UnicodeEncodeError, PublicKeyImportError) as exc:
            raise KeyRecordError("trusted-key public key is malformed") from exc
        if candidate.algorithm != record.algorithm or candidate.key_id != identifier:
            raise FingerprintMismatchError("trusted public key does not match its key ID")
        return record

    def delete(self, identifier: str) -> None:
        path = self._path(identifier)
        if not path.is_file():
            raise KeyNotFoundError("trusted key not found")
        path.unlink()

    def _path(self, identifier: str) -> Path:
        if not isinstance(identifier, str) or not _KEY_ID_RE.fullmatch(identifier):
            raise KeyNotFoundError("invalid key ID")
        return self.directory / f"{identifier}.json"


def _record_json(record: TrustedKeyRecord) -> bytes:
    data = {
        "algorithm": record.algorithm,
        "key_id": record.key_id,
        "label": record.label,
        "public_key_pem": record.public_key_pem,
        "trusted": True,
    }
    # Omitted for full trust so standalone records stay byte-identical to the legacy format.
    if record.usage != USAGE_FULL:
        data["usage"] = record.usage
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _parse_record(data: object) -> TrustedKeyRecord:
    if not isinstance(data, dict) or data.get("trusted") is not True:
        raise KeyRecordError("trust must be explicitly established")
    try:
        algorithm, identifier, label, public_pem = (
            data["algorithm"], data["key_id"], data["label"], data["public_key_pem"]
        )
    except KeyError as exc:
        raise KeyRecordError("trusted-key record is missing fields") from exc
    if algorithm not in key_serialization.SUPPORTED_ALGORITHMS:
        raise KeyRecordError("trusted-key record has an unsupported algorithm")
    if not isinstance(identifier, str) or not _KEY_ID_RE.fullmatch(identifier):
        raise KeyRecordError("trusted-key record has an invalid ID")
    if not isinstance(label, str) or not label.strip() or len(label) > 128:
        raise KeyRecordError("trusted-key record has an invalid label")
    if not isinstance(public_pem, str):
        raise KeyRecordError("trusted-key record has an invalid public key")
    usage = data.get("usage", USAGE_FULL)
    try:
        _validate_usage(algorithm, usage)
    except TrustConfirmationError as exc:
        raise KeyRecordError("trusted-key record has an invalid usage") from exc
    return TrustedKeyRecord(algorithm, identifier, label, public_pem, usage=usage)


def _validate_usage(algorithm: str, usage: object) -> None:
    if not isinstance(usage, str) or usage not in TRUST_USAGES:
        raise TrustConfirmationError("unsupported trusted-key usage")
    if usage == USAGE_VERIFY_ONLY and algorithm != key_serialization.MLDSA:
        raise TrustConfirmationError("only ML-DSA-65 keys can be verification-only")


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
