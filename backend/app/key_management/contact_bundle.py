"""Versioned, public-key-only contact bundles.

A contact bundle lets one QuantumShield install hand its public keys to another
install. It never contains private keys, passphrases, or trust decisions. Parsing
a bundle only validates and previews it; nothing is written to any store.

Bundle v1 (UTF-8 JSON object, exact field sets, unknown fields rejected):

    {
      "format": "quantumshield-contact-bundle",
      "version": 1,
      "label": "<display label, 1-128 chars>",
      "keys": [
        {
          "purpose": "encryption" | "signing",
          "algorithm": "ML-KEM-768" | "ML-DSA-65",
          "public_key_pem": "<canonical SPKI PEM>",
          "fingerprint": "<64 lowercase hex: the protocol key ID>"
        }
      ]
    }

`fingerprint` is the full SHA-256 key ID defined in CRYPTOGRAPHIC_PROTOCOL.md,
so a previewed fingerprint can be compared directly with `key_id` values shown
elsewhere in the application and stored in `.qshield` headers.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass

from backend.app.crypto import key_serialization
from backend.app.crypto.crypto_errors import CryptoInputError

from .errors import KeyManagementError
from .fingerprints import key_id as calculate_key_id
from .models import KeyRecord

BUNDLE_FORMAT = "quantumshield-contact-bundle"
BUNDLE_VERSION = 1
MAX_BUNDLE_KEYS = 8
MAX_BUNDLE_TEXT_CHARS = 32 * 1024
MAX_LABEL_CHARS = 128
PURPOSE_FOR_ALGORITHM = {
    key_serialization.MLKEM: "encryption",
    key_serialization.MLDSA: "signing",
}
_BUNDLE_FIELDS = frozenset({"format", "version", "label", "keys"})
_ENTRY_FIELDS = frozenset({"purpose", "algorithm", "public_key_pem", "fingerprint"})
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class ContactBundleError(KeyManagementError):
    """A bundle could not be built or failed validation. Messages are safe to show."""


@dataclass(frozen=True)
class ContactBundleEntry:
    purpose: str
    algorithm: str
    key_id: str
    public_key_pem: str


@dataclass(frozen=True)
class ContactBundlePreview:
    """Validated bundle contents. Always untrusted; never persisted by this module."""

    label: str
    entries: tuple[ContactBundleEntry, ...]
    trusted: bool = False


def build_bundle(label: str, records: list[KeyRecord]) -> dict[str, object]:
    """Build a v1 bundle from local key records, re-deriving every fingerprint."""
    clean_label = _validate_label(label)
    if not 1 <= len(records) <= MAX_BUNDLE_KEYS:
        raise ContactBundleError(f"select 1 to {MAX_BUNDLE_KEYS} keys")
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for record in records:
        entry = _canonical_entry(record.algorithm, record.public_key_pem, record.key_id)
        if entry.key_id in seen:
            raise ContactBundleError("each key may appear only once")
        seen.add(entry.key_id)
        entries.append(
            {
                "purpose": entry.purpose,
                "algorithm": entry.algorithm,
                "public_key_pem": entry.public_key_pem,
                "fingerprint": entry.key_id,
            }
        )
    return {
        "format": BUNDLE_FORMAT,
        "version": BUNDLE_VERSION,
        "label": clean_label,
        "keys": entries,
    }


def parse_bundle(bundle_text: str) -> ContactBundlePreview:
    """Strictly parse and validate bundle JSON text. Does not trust or store keys."""
    if not isinstance(bundle_text, str) or not bundle_text.strip():
        raise ContactBundleError("contact bundle is empty")
    if len(bundle_text) > MAX_BUNDLE_TEXT_CHARS:
        raise ContactBundleError("contact bundle is too large")
    try:
        data = json.loads(
            bundle_text.lstrip("﻿"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_constant,
        )
    except ContactBundleError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ContactBundleError("contact bundle is not valid JSON") from exc

    if not isinstance(data, dict) or set(data) != _BUNDLE_FIELDS:
        raise ContactBundleError("contact bundle has missing or unexpected fields")
    if data["format"] != BUNDLE_FORMAT:
        raise ContactBundleError("not a QuantumShield contact bundle")
    version = data["version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != BUNDLE_VERSION:
        raise ContactBundleError("unsupported contact bundle version")
    label = _validate_label(data["label"])
    keys = data["keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_BUNDLE_KEYS:
        raise ContactBundleError(f"contact bundle must contain 1 to {MAX_BUNDLE_KEYS} keys")

    entries: list[ContactBundleEntry] = []
    seen: set[str] = set()
    for position, raw_entry in enumerate(keys, start=1):
        entry = _parse_entry(raw_entry, position)
        if entry.key_id in seen:
            raise ContactBundleError(f"key {position} duplicates an earlier key")
        seen.add(entry.key_id)
        entries.append(entry)
    return ContactBundlePreview(label, tuple(entries))


def _parse_entry(raw_entry: object, position: int) -> ContactBundleEntry:
    if not isinstance(raw_entry, dict) or set(raw_entry) != _ENTRY_FIELDS:
        raise ContactBundleError(f"key {position} has missing or unexpected fields")
    purpose = raw_entry["purpose"]
    algorithm = raw_entry["algorithm"]
    pem = raw_entry["public_key_pem"]
    fingerprint = raw_entry["fingerprint"]
    if not all(isinstance(value, str) for value in (purpose, algorithm, pem, fingerprint)):
        raise ContactBundleError(f"key {position} has a field of the wrong type")
    if algorithm not in PURPOSE_FOR_ALGORITHM:
        raise ContactBundleError(f"key {position} uses an unsupported algorithm")
    if purpose != PURPOSE_FOR_ALGORITHM[algorithm]:
        raise ContactBundleError(f"key {position} purpose does not match its algorithm")
    if not _FINGERPRINT_RE.fullmatch(fingerprint):
        raise ContactBundleError(f"key {position} fingerprint must be 64 lowercase hexadecimal characters")
    try:
        return _canonical_entry(algorithm, pem, fingerprint)
    except ContactBundleError as exc:
        raise ContactBundleError(f"key {position}: {exc}") from None


def _canonical_entry(algorithm: str, pem: str, expected_fingerprint: str) -> ContactBundleEntry:
    """Import a public key, require it to be canonical, and recompute its fingerprint."""
    try:
        public_key = key_serialization.import_public_key(pem.encode("ascii"))
        actual_algorithm = key_serialization.algorithm_for_key(public_key)
        canonical_pem = key_serialization.export_public_key(public_key).decode("ascii")
    except (CryptoInputError, UnicodeError, AttributeError) as exc:
        raise ContactBundleError("public key is invalid or unsupported") from exc
    # Only a single canonical SPKI PEM block is accepted (CRLF line endings are
    # tolerated). This rejects trailing data or extra PEM blocks that a PEM
    # loader might otherwise silently ignore.
    if pem.replace("\r\n", "\n") != canonical_pem:
        raise ContactBundleError("public key is not a single canonical SPKI PEM block")
    if actual_algorithm != algorithm:
        raise ContactBundleError("public key algorithm does not match the declared algorithm")
    actual_fingerprint = calculate_key_id(public_key)
    if actual_fingerprint != expected_fingerprint:
        raise ContactBundleError("fingerprint does not match the public key")
    return ContactBundleEntry(
        PURPOSE_FOR_ALGORITHM[actual_algorithm],
        actual_algorithm,
        actual_fingerprint,
        canonical_pem,
    )


def _validate_label(label: object) -> str:
    if not isinstance(label, str):
        raise ContactBundleError("contact label must be text")
    clean = label.strip()
    if not 1 <= len(clean) <= MAX_LABEL_CHARS:
        raise ContactBundleError(f"contact label must contain 1 to {MAX_LABEL_CHARS} characters")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in clean):
        raise ContactBundleError("contact label contains control or formatting characters")
    return clean


def _reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ContactBundleError("contact bundle contains duplicate fields")
        result[name] = value
    return result


def _reject_constant(name: str) -> object:
    raise ContactBundleError("contact bundle contains a non-standard JSON number")
