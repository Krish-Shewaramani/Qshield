"""Persistent local trust store requiring explicit fingerprint confirmation."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from backend.app.crypto import key_serialization
from backend.app.crypto.crypto_errors import CryptoInputError
from backend.app.core.windows_security import ensure_private_directory

from .errors import (
    FingerprintMismatchError,
    KeyNotFoundError,
    KeyRecordError,
    PublicKeyImportError,
    TrustConfirmationError,
)
from .fingerprints import key_id as calculate_key_id
from .models import PublicKeyCandidate, TrustedKeyRecord

_KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")


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
    ) -> TrustedKeyRecord:
        candidate = self.preview(public_key_pem)
        if not isinstance(label, str) or not label.strip() or len(label) > 128:
            raise ValueError("label must contain 1 to 128 characters")
        if not isinstance(confirmed_fingerprint, str) or confirmed_fingerprint.lower() != candidate.key_id:
            raise TrustConfirmationError("explicit matching fingerprint confirmation is required")
        record = TrustedKeyRecord(
            candidate.algorithm,
            candidate.key_id,
            label.strip(),
            candidate.public_key_pem,
        )
        record_path = self._path(record.key_id)
        _atomic_write(record_path, _record_json(record))
        return record

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
    return TrustedKeyRecord(algorithm, identifier, label, public_pem)


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
