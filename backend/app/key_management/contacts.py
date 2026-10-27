"""Locally stored contacts paired by out-of-band fingerprint comparison.

Trust model
-----------
The existing ``TrustStore`` remains the single trust authority: file exchange
only ever looks keys up there. A contact record groups a person's public keys
and tracks per-key state, version, history, and where each key's trust came
from. Trust-store usage per contact key:

* ``active``: full trust (encryption recipient or signer).
* ``retired`` ML-DSA-65: ``verify_only`` so older package signatures still verify.
* ``retired`` ML-KEM-768: removed when the contact created the trust, or
  ``suspended`` when the user had trusted it independently beforehand. Neither
  is usable for new encryption.

Trust origin
------------
When a key becomes active, the contact records whether a full trust-store
record already existed (``independent``) or was created by the contact
(``contact``). Contact-created trust is revoked when the contact deletes it.
Independent trust is never revoked by the contact: retirement only restricts
it, and deleting the contact returns it to normal standalone trust.
``ambiguous`` marks legacy (version 1) keys whose origin was never recorded.
Retirement restricts them like independent keys; deleting the contact leaves
their trust-store entry exactly as it is, so possibly independent trust is
never silently revoked. The user can remove it afterward in Key Management.

Recipient enforcement
---------------------
``ensure_recipient_not_retired`` is called by file exchange before any
ML-KEM recipient lookup. It blocks a key that any contact record holds as
retired, whatever its trust-store entry says, and fails closed when the
contact records cannot be read and validated.

A durable marker, ``.contacts-initialized`` inside the trust directory, records
that contact storage has been initialized. It is written before any contact
key can become trusted, and it shares the fate of the trust records it
protects. With the marker present, a missing contacts directory fails closed
for ML-KEM recipients; without it (a clean install), standalone ML-KEM
encryption is unaffected. Trust-store listing reads only ``*.json`` files,
so the marker is never mistaken for a trusted key.

Constructing the contact service never recreates a lost contacts directory.
The directory is created only on a clean install (no marker, no directory)
or through the explicit ``reinitialize_storage`` recovery path. While the
marker exists and the directory is missing, contact operations report the
missing state and file exchange keeps refusing ML-KEM recipients.

Ordering and recovery
---------------------
Revocations and restrictions are applied to the trust store before the
contact record changes, so a retired ML-KEM key is never left usable. Grants
are journaled in the contact record first (``trust_sync = "pending"``) and
applied afterwards, so an interrupted confirm can be finished by
reconciliation without re-deciding trust origin. A failed contact deletion
is journaled with ``deletion_pending`` and can be retried.

A bundle's label is self-asserted. It is stored only as ``claimed_label`` and
is never used to match a bundle to an existing contact.

Contact record v2 (one JSON file per contact, ``<contact_id>.json``)::

    {
      "format": "quantumshield-contact",
      "version": 2,
      "contact_id": "<32 lowercase hex>",
      "label": "<local label chosen by the user>",
      "claimed_label": "<label asserted by the first imported bundle>",
      "confirmed": true | false,
      "deletion_pending": true | false,
      "created_at": <unix seconds>,
      "keys": [
        {
          "fingerprint": "<64 lowercase hex protocol key ID>",
          "algorithm": "ML-KEM-768" | "ML-DSA-65",
          "purpose": "encryption" | "signing",
          "public_key_pem": "<canonical SPKI PEM>",
          "state": "pending" | "verified" | "active" | "retired",
          "key_version": null | <int >= 1>,
          "trust_origin": null | "independent" | "contact" | "ambiguous",
          "trust_sync": "synced" | "pending",
          "added_at": <unix seconds>,
          "verified_at": null | <unix seconds>,
          "activated_at": null | <unix seconds>,
          "retired_at": null | <unix seconds>
        }
      ]
    }

Version 1 records (Phase 2) are still read. Phase 2 did not record whether a
key was trusted independently before pairing, and it reused existing
standalone trust records, so their active and retired keys are migrated with
``trust_origin = "ambiguous"``. The record is rewritten as version 2 on its
next change, keeping that origin.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

from backend.app.crypto import key_serialization
from backend.app.core.windows_security import (
    ensure_private_directory,
    reset_private_directory_cache,
)

from .contact_bundle import (
    PURPOSE_FOR_ALGORITHM,
    ContactBundleError,
    _canonical_entry,
    _validate_label,
    parse_bundle,
)
from .errors import KeyManagementError, KeyNotFoundError, TrustConfirmationError
from .models import TrustedKeyRecord
from .trust_store import (
    USAGE_FULL,
    USAGE_SUSPENDED,
    USAGE_VERIFY_ONLY,
    TrustStore,
    _atomic_write,
)

CONTACT_FORMAT = "quantumshield-contact"
CONTACT_RECORD_VERSION = 2
PENDING, VERIFIED, ACTIVE, RETIRED = "pending", "verified", "active", "retired"
KEY_STATES = frozenset({PENDING, VERIFIED, ACTIVE, RETIRED})
_UNTRUSTED_STATES = frozenset({PENDING, VERIFIED})
_LINKED_STATES = frozenset({ACTIVE, RETIRED})
ORIGIN_INDEPENDENT, ORIGIN_CONTACT = "independent", "contact"
ORIGIN_AMBIGUOUS = "ambiguous"  # legacy v1 key: independent or contact-created, unknown
_ORIGINS = (ORIGIN_INDEPENDENT, ORIGIN_CONTACT, ORIGIN_AMBIGUOUS)
CONTACTS_DIRNAME = "contacts"
CONTACTS_MARKER_NAME = ".contacts-initialized"
_MARKER_FORMAT = "quantumshield-contacts-marker"
_MARKER_VERSION = 1
STORAGE_CLEAN = "clean"      # no marker and no directory: never initialized
STORAGE_READY = "ready"      # contacts directory present
STORAGE_MISSING = "missing"  # marker present, directory gone
STORAGE_INVALID = "invalid"  # contacts path unusable (not a folder, unreadable)
STORAGE_MISSING_MESSAGE = (
    "Contact storage is missing or unreadable: contacts were set up on this device, "
    "but the contacts folder is gone. Restore the folder from a backup, or reinitialize "
    "contact storage in Contacts. New encryption to ML-KEM recipients is blocked until then."
)
SYNC_SYNCED, SYNC_PENDING = "synced", "pending"

# Pairing assessment outcomes for each key in an imported bundle.
NEW_KEY = "new_key"
NEW_PURPOSE = "new_purpose"
PENDING_REPLACEMENT = "pending_replacement"
ALREADY_PRESENT = "already_present"
CONFLICT = "conflict"
PREVIOUSLY_RETIRED = "previously_retired"
PENDING_CONFLICT = "pending_conflict"
STAGEABLE = frozenset({NEW_KEY, NEW_PURPOSE, PENDING_REPLACEMENT})
BLOCKING = frozenset({CONFLICT, PREVIOUSLY_RETIRED, PENDING_CONFLICT})

# Effective trust status of a contact key, derived from the trust store.
UNTRUSTED = "untrusted"                      # pending or verified, not trusted by the contact
TRUSTED = "trusted"                          # active and fully trusted
ACTIVATION_PENDING = "activation_pending"    # confirmed, trust grant not yet applied
MISSING = "missing"                          # active, but absent from the trust store
DOWNGRADED = "downgraded"                    # active, but restricted in the trust store
RETIRED_REMOVED = "retired"                  # retired and not usable
VERIFICATION_ONLY = "verification_only"      # retired signing key kept for old packages
SUSPENDED = "suspended"                      # retired independent encryption key, kept but unusable
CLEANUP_PENDING = "cleanup_pending"          # retired, but still more trusted than it should be
HISTORY_UNAVAILABLE = "history_unavailable"  # retired signing key missing from the trust store
NEEDS_RECONCILE = frozenset({ACTIVATION_PENDING, CLEANUP_PENDING, HISTORY_UNAVAILABLE})
NEEDS_RESTORE = frozenset({MISSING, DOWNGRADED})

_CONTACT_FIELDS_V1 = frozenset(
    {"format", "version", "contact_id", "label", "claimed_label", "confirmed", "created_at", "keys"}
)
_CONTACT_FIELDS_V2 = _CONTACT_FIELDS_V1 | {"deletion_pending"}
_KEY_FIELDS_V1 = frozenset(
    {
        "fingerprint", "algorithm", "purpose", "public_key_pem", "state", "key_version",
        "added_at", "verified_at", "activated_at", "retired_at",
    }
)
_KEY_FIELDS_V2 = _KEY_FIELDS_V1 | {"trust_origin", "trust_sync"}
_CONTACT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_WHITESPACE_RE = re.compile(r"\s+")
_TRUST_FAILURES = (KeyManagementError, OSError, ValueError)
# Serializes read-modify-write across the contact store and the trust store,
# including standalone trusted-key changes routed through ContactService.
_PAIRING_LOCK = threading.RLock()


class ContactError(KeyManagementError):
    """A contact operation was rejected. Messages are safe to show."""


class ContactNotFoundError(ContactError):
    pass


class ContactConflictError(ContactError):
    pass


class ContactIncompleteError(ContactError):
    """A multi-step trust change did not finish; the operation can be retried."""


class ContactManagedKeyError(ContactError):
    """A standalone trust change was refused because a contact manages the key."""


class ContactRecordError(ContactError):
    """A stored contact record is malformed or internally inconsistent."""


class ContactStorageMissingError(ContactIncompleteError):
    """Contact storage was initialized but its directory is missing or unusable."""


class RecipientBlockedError(ContactError):
    """An ML-KEM key may not receive new encryption because of contact state."""


def contacts_directory_for(trust_directory: Path) -> Path:
    """Contacts live beside the trust store they manage."""
    return Path(trust_directory).parent / CONTACTS_DIRNAME


def contacts_marker_path(trust_directory: Path) -> Path:
    """Durable proof that contact storage was initialized, kept with the trust data."""
    return Path(trust_directory) / CONTACTS_MARKER_NAME


def mark_contacts_initialized(trust_directory: Path) -> None:
    """Create the marker, or rewrite it if unreadable. Raises OSError on failure.

    The marker only ever makes the recipient check stricter, so it is safe to
    (re)write whenever contact storage is known to exist.
    """
    path = contacts_marker_path(trust_directory)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if (
            isinstance(data, dict)
            and data.get("format") == _MARKER_FORMAT
            and data.get("version") == _MARKER_VERSION
        ):
            return
    except FileNotFoundError:
        pass
    except (UnicodeError, ValueError):
        pass  # Corrupt marker: replace it with a valid one below.
    content = {
        "format": _MARKER_FORMAT,
        "version": _MARKER_VERSION,
        "contacts_directory": CONTACTS_DIRNAME,
        "initialized_at": int(time.time()),
    }
    _atomic_write(path, (json.dumps(content, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))


def _path_exists(path: Path) -> bool:
    """True if anything exists at path; any error other than absence fails closed."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RecipientBlockedError("contact records could not be checked") from exc
    return True


def inspect_contact_storage(trust_directory: Path) -> str:
    """Classify contact storage without creating or changing anything."""
    directory = contacts_directory_for(trust_directory)
    try:
        initialized = _path_exists(contacts_marker_path(trust_directory))
        if not _path_exists(directory):
            return STORAGE_MISSING if initialized else STORAGE_CLEAN
        return STORAGE_READY if directory.is_dir() else STORAGE_INVALID
    except (RecipientBlockedError, OSError):
        return STORAGE_INVALID


def ensure_recipient_not_retired(trust_directory: Path, fingerprint: str) -> None:
    """Block new encryption to an ML-KEM key that any contact has retired.

    Lock-free (records are replaced atomically). It does not depend on the
    key's trust-store usage, so a stale full-trust entry left by an older
    record is still blocked before any list or reconcile request. It fails
    closed when contact records cannot be read and validated, and when the
    initialization marker exists but the contacts directory does not. Its
    only write is creating a missing marker for pre-marker contact storage,
    which can only make later checks stricter.
    """
    directory = contacts_directory_for(trust_directory)
    initialized = _path_exists(contacts_marker_path(trust_directory))
    if not _path_exists(directory):
        if initialized:
            raise RecipientBlockedError("contact records are missing")
        return  # Clean install with no contact history: standalone trust only.
    if not initialized:
        # Contact storage that predates the marker: record it now.
        try:
            mark_contacts_initialized(trust_directory)
        except OSError:
            pass  # The records below are still validated; this only hardens later checks.
    try:
        if not directory.is_dir():
            raise RecipientBlockedError("contact records could not be checked")
        paths = sorted(directory.glob("*.json"))
    except OSError as exc:
        raise RecipientBlockedError("contact records could not be checked") from exc
    for path in paths:
        try:
            record = _parse_contact(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError, KeyManagementError) as exc:
            raise RecipientBlockedError("contact records could not be checked") from exc
        if record.contact_id != path.stem:
            raise RecipientBlockedError("contact records could not be checked")
        for key in record.keys:
            if key.fingerprint == fingerprint and key.state == RETIRED:
                raise RecipientBlockedError("this recipient key was retired by a contact")


@dataclass(frozen=True)
class ContactKey:
    fingerprint: str
    algorithm: str
    purpose: str
    public_key_pem: str
    state: str
    key_version: int | None
    added_at: int
    verified_at: int | None = None
    activated_at: int | None = None
    retired_at: int | None = None
    trust_origin: str | None = None
    trust_sync: str = SYNC_SYNCED


@dataclass(frozen=True)
class ContactRecord:
    contact_id: str
    label: str
    claimed_label: str
    confirmed: bool
    created_at: int
    keys: tuple[ContactKey, ...]
    deletion_pending: bool = False

    def active_key(self, purpose: str) -> ContactKey | None:
        return next((k for k in self.keys if k.state == ACTIVE and k.purpose == purpose), None)

    def find(self, fingerprint: str) -> ContactKey | None:
        return next((k for k in self.keys if k.fingerprint == fingerprint), None)


@dataclass(frozen=True)
class KeyAssessment:
    fingerprint: str
    algorithm: str
    purpose: str
    status: str
    detail: str
    in_trusted_keys: bool
    current_fingerprint: str | None = None
    current_key_version: int | None = None
    conflicting_contact_id: str | None = None
    conflicting_contact_label: str | None = None


@dataclass(frozen=True)
class PairingAnalysis:
    claimed_label: str
    target_contact_id: str | None
    keys: tuple[KeyAssessment, ...]
    matching_contacts: tuple[tuple[str, str], ...]
    can_stage: bool


@dataclass(frozen=True)
class KeyTrustView:
    key: ContactKey
    trust_status: str
    trust_usage: str | None

    @property
    def in_trusted_keys(self) -> bool:
        return self.trust_usage is not None

    @property
    def usable_for_exchange(self) -> bool:
        return self.trust_status == TRUSTED

    @property
    def usable_for_encryption(self) -> bool:
        return self.trust_status == TRUSTED and self.key.algorithm == key_serialization.MLKEM

    @property
    def usable_for_verification(self) -> bool:
        return self.key.algorithm == key_serialization.MLDSA and self.trust_status in {TRUSTED, VERIFICATION_ONLY}


@dataclass(frozen=True)
class ContactView:
    record: ContactRecord
    keys: tuple[KeyTrustView, ...]

    @property
    def needs_reconcile(self) -> bool:
        return self.record.deletion_pending or any(v.trust_status in NEEDS_RECONCILE for v in self.keys)


@dataclass(frozen=True)
class ConfirmResult:
    view: ContactView
    activated: tuple[str, ...]
    retired: tuple[str, ...]
    activation_pending: tuple[str, ...]


@dataclass(frozen=True)
class TrustLink:
    contact_id: str
    contact_label: str
    key_state: str
    trust_origin: str | None


class ContactStore:
    """Persist versioned contact records; performs no trust decisions itself."""

    def __init__(self, directory: Path):
        # Never creates the directory: a lost directory must stay visibly lost.
        self.directory = Path(directory)

    def initialize(self) -> None:
        """Create and secure the directory. Only for clean installs or explicit recovery."""
        if not _path_exists(self.directory):
            reset_private_directory_cache()
        ensure_private_directory(self.directory)
        self._require_present()

    def _require_present(self) -> None:
        try:
            present = self.directory.is_dir()
        except OSError:
            present = False
        if not present:
            raise ContactStorageMissingError(STORAGE_MISSING_MESSAGE)

    def list_records(self) -> list[ContactRecord]:
        self._require_present()
        return [self.get(path.stem) for path in sorted(self.directory.glob("*.json"))]

    def get(self, contact_id: str) -> ContactRecord:
        self._require_present()
        path = self._path(contact_id)
        if not path.is_file():
            raise ContactNotFoundError("contact not found")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            record = _parse_contact(data)
        except (OSError, UnicodeError, json.JSONDecodeError, ContactBundleError, TypeError) as exc:
            raise ContactRecordError("contact record is malformed") from exc
        if record.contact_id != contact_id:
            raise ContactRecordError("contact record ID does not match its file")
        return record

    def save(self, record: ContactRecord) -> None:
        self._require_present()
        _validate_record(record)
        _atomic_write(self._path(record.contact_id), _contact_json(record))

    def delete(self, contact_id: str) -> None:
        self._require_present()
        path = self._path(contact_id)
        if not path.is_file():
            raise ContactNotFoundError("contact not found")
        path.unlink()

    def _path(self, contact_id: str) -> Path:
        if not isinstance(contact_id, str) or not _CONTACT_ID_RE.fullmatch(contact_id):
            raise ContactNotFoundError("invalid contact ID")
        return self.directory / f"{contact_id}.json"


class ContactService:
    """Pairing workflow that writes trust only through the existing TrustStore."""

    def __init__(self, store: ContactStore, trust: TrustStore):
        self.store = store
        self.trust = trust
        self.storage_state = inspect_contact_storage(trust.directory)
        if self.storage_state == STORAGE_CLEAN:
            # Directory first, then marker: an interruption leaves a directory
            # without a marker, which the encryption guard treats as initialized.
            store.initialize()
            mark_contacts_initialized(trust.directory)
            self.storage_state = STORAGE_READY
        elif self.storage_state == STORAGE_READY:
            # No contact operation (and so no contact trust) proceeds without the marker.
            mark_contacts_initialized(trust.directory)
        # MISSING or INVALID: create nothing. Store access reports the missing state.

    def reinitialize_storage(self) -> tuple[str, int]:
        """Explicit recovery: recreate an empty contacts directory after loss.

        Contact history is not recovered, so retired ML-KEM keys can no longer
        be recognized. Before the directory is recreated, every fully trusted
        ML-KEM key is suspended; each must be reauthorized individually after
        the user re-confirms its complete fingerprint. If the trust store cannot
        be read or any key cannot be suspended, contact storage is left missing
        (so file exchange keeps refusing ML-KEM recipients) and recovery can be
        retried safely. ML-DSA keys are not changed.
        """
        with _PAIRING_LOCK:
            state = inspect_contact_storage(self.trust.directory)
            if state == STORAGE_READY:
                raise ContactError("contact storage is present; nothing to reinitialize")
            if state != STORAGE_MISSING:
                raise ContactError("the contacts path exists but is not a usable folder; fix it manually first")
            try:
                suspended, failed = self.trust.suspend_encryption_keys()
            except (KeyManagementError, OSError) as exc:
                raise ContactIncompleteError(
                    "Recovery stopped: your trusted keys could not be read, so contact storage is still "
                    "missing and encryption stays blocked. Fix the trusted-key store and retry recovery."
                ) from exc
            if failed:
                raise ContactIncompleteError(
                    f"Recovery stopped: {len(failed)} encryption key(s) could not be suspended, so contact "
                    "storage is still missing and encryption stays blocked. Retry recovery."
                )
            # Only now, with no ML-KEM key fully trusted, recreate the directory.
            self.store.initialize()
            mark_contacts_initialized(self.trust.directory)
            self.storage_state = STORAGE_READY
            return self.storage_state, len(suspended)

    def reauthorize_suspended_key(self, identifier: str, confirmed_fingerprint: str) -> TrustedKeyRecord:
        """Restore full trust to one suspended ML-KEM key that no contact manages.

        Requires ready contact storage and the user re-typing the complete
        fingerprint. Contact-managed keys must be handled from Contacts.
        """
        with _PAIRING_LOCK:
            link = self.trust_links().get(identifier)  # Refuses while storage is missing.
            if link is not None:
                raise ContactManagedKeyError(
                    f"This key is managed by contact “{link.contact_label}”. Change it from Contacts."
                )
            record = self.trust.get(identifier)
            if record.algorithm != key_serialization.MLKEM or record.usage != USAGE_SUSPENDED:
                raise ContactError("only a suspended ML-KEM key can be reauthorized")
            _require_typed_fingerprint(confirmed_fingerprint, record.key_id)
            return self.trust.set_usage(identifier, USAGE_FULL)

    # Read-only views (plus safe-direction cleanup) -------------------------

    def list_contacts(self) -> list[ContactView]:
        with _PAIRING_LOCK:
            records = self.store.list_records()
            for record in records:
                self._tighten_retired(record)
            return [self._view(record) for record in records]

    def get_contact(self, contact_id: str) -> ContactView:
        with _PAIRING_LOCK:
            record = self.store.get(contact_id)
            self._tighten_retired(record)
            return self._view(record)

    def analyze(self, bundle_text: str, contact_id: str | None) -> PairingAnalysis:
        analysis, _, _ = self._analyze(bundle_text, contact_id)
        return analysis

    def tighten_retired_keys(self) -> None:
        """Remove or restrict leftover trust for retired keys. Never grants trust."""
        with _PAIRING_LOCK:
            for record in self.store.list_records():
                self._tighten_retired(record)

    def trust_links(self) -> dict[str, TrustLink]:
        """Trust-store key IDs that contacts manage (active or retired keys)."""
        links: dict[str, TrustLink] = {}
        for record in self.store.list_records():
            for key in record.keys:
                if key.state in _LINKED_STATES:
                    links[key.fingerprint] = TrustLink(
                        record.contact_id, record.label, key.state, key.trust_origin
                    )
        return links

    # Standalone trusted-key changes, guarded against contact-managed keys --

    def add_standalone_trust(
        self, public_key_pem: bytes, label: str, confirmed_fingerprint: str
    ) -> TrustedKeyRecord:
        with _PAIRING_LOCK:
            candidate = self.trust.preview(public_key_pem)
            link = self.trust_links().get(candidate.key_id)
            if link is not None:
                raise ContactManagedKeyError(
                    f"This key is managed by contact “{link.contact_label}”. Change it from Contacts."
                )
            return self.trust.add(public_key_pem, label, confirmed_fingerprint)

    def remove_standalone_trust(self, identifier: str) -> None:
        with _PAIRING_LOCK:
            try:
                link = self.trust_links().get(identifier)
            except ContactStorageMissingError:
                link = None  # Removing trust only ever reduces it, so allow it during recovery.
            if link is not None:
                if link.trust_origin == ORIGIN_AMBIGUOUS:
                    raise ContactManagedKeyError(
                        f"This key is linked to contact “{link.contact_label}”. Delete that contact first; "
                        "legacy keys whose origin is unknown stay trusted and can then be removed here."
                    )
                if link.trust_origin == ORIGIN_INDEPENDENT:
                    raise ContactManagedKeyError(
                        f"This key is linked to contact “{link.contact_label}”. Delete that contact first; "
                        "keys you trusted independently stay trusted and can then be removed here."
                    )
                raise ContactManagedKeyError(
                    f"This key is managed by contact “{link.contact_label}”. To stop trusting it, "
                    "delete that contact or replace the key from Contacts."
                )
            self.trust.delete(identifier)

    # Pairing state changes --------------------------------------------------

    def stage(
        self, bundle_text: str, contact_id: str | None, label: str | None
    ) -> tuple[PairingAnalysis, ContactView | None, tuple[str, ...]]:
        """Record stageable bundle keys as pending (untrusted). Never trusts anything."""
        with _PAIRING_LOCK:
            analysis, preview_keys, target = self._analyze(bundle_text, contact_id)
            if any(item.status in BLOCKING for item in analysis.keys):
                raise ContactConflictError(
                    "this bundle has conflicting keys; resolve every flagged key before importing"
                )
            stageable = [item for item in analysis.keys if item.status in STAGEABLE]
            if not stageable:
                return analysis, self._view(target) if target else None, ()
            now = int(time.time())
            new_keys = tuple(
                ContactKey(
                    fingerprint=item.fingerprint,
                    algorithm=item.algorithm,
                    purpose=item.purpose,
                    public_key_pem=preview_keys[item.fingerprint],
                    state=PENDING,
                    key_version=None,
                    added_at=now,
                )
                for item in stageable
            )
            if target is None:
                if label is None:
                    raise ContactError("a local contact label is required for a new contact")
                record = ContactRecord(
                    contact_id=secrets.token_hex(16),
                    label=_validate_label(label),
                    claimed_label=analysis.claimed_label,
                    confirmed=False,
                    created_at=now,
                    keys=new_keys,
                )
            else:
                record = replace(target, keys=target.keys + new_keys)
            self.store.save(record)
            return analysis, self._view(record), tuple(key.fingerprint for key in new_keys)

    def verify_key(self, contact_id: str, fingerprint: str, confirmed_fingerprint: str) -> ContactView:
        """Mark one pending key verified after the user types its complete fingerprint."""
        with _PAIRING_LOCK:
            record = self._open_contact(contact_id)
            key = self._find_key(record, fingerprint)
            if key.state == VERIFIED:
                return self._view(record)
            if key.state != PENDING:
                raise ContactError("only a pending key can be verified")
            _require_typed_fingerprint(confirmed_fingerprint, key.fingerprint)
            record = _replace_key(record, replace(key, state=VERIFIED, verified_at=int(time.time())))
            self.store.save(record)
            return self._view(record)

    def confirm(self, contact_id: str) -> ConfirmResult:
        """Activate every verified key, retiring any key it replaces."""
        with _PAIRING_LOCK:
            record = self._open_contact(contact_id)
            verified = [key for key in record.keys if key.state == VERIFIED]
            self._require_marker()
            if not verified:
                raise ContactError("verify the complete fingerprint of at least one key before confirming")
            replaced = [k for k in (record.active_key(v.purpose) for v in verified) if k is not None]

            # 1. Revoke or restrict the keys being replaced before anything else changes.
            #    If this fails, nothing was activated and the old keys stay recorded as active.
            for current in replaced:
                try:
                    self._apply_retired_trust(record.label, current, allow_grant=False)
                except _TRUST_FAILURES as exc:
                    raise ContactIncompleteError(
                        "could not retire the current key; nothing was activated. Retry confirming."
                    ) from exc

            # 2. Journal the new states, including each new key's trust origin.
            now = int(time.time())
            keys = list(record.keys)
            for current in replaced:
                keys[keys.index(current)] = replace(current, state=RETIRED, retired_at=now)
            activated: list[str] = []
            for new_key in verified:
                previous = [k.key_version or 0 for k in record.keys if k.purpose == new_key.purpose]
                existing = self._trust_record(new_key.fingerprint)
                independent = existing is not None and existing.usage == USAGE_FULL
                keys[keys.index(new_key)] = replace(
                    new_key,
                    state=ACTIVE,
                    key_version=max(previous, default=0) + 1,
                    activated_at=now,
                    trust_origin=ORIGIN_INDEPENDENT if independent else ORIGIN_CONTACT,
                    trust_sync=SYNC_SYNCED if independent else SYNC_PENDING,
                )
                activated.append(new_key.fingerprint)
            record = replace(record, confirmed=True, keys=tuple(keys))
            self.store.save(record)

            # 3. Apply journaled grants. Failures stay pending and can be reconciled.
            record, pending = self._apply_pending_grants(record)
            return ConfirmResult(
                self._view(record),
                tuple(activated),
                tuple(k.fingerprint for k in replaced),
                pending,
            )

    def restore_key(self, contact_id: str, fingerprint: str, confirmed_fingerprint: str) -> ContactView:
        """Re-trust an active key that went missing or was restricted, after re-verification."""
        with _PAIRING_LOCK:
            record = self._open_contact(contact_id)
            key = self._find_key(record, fingerprint)
            if key.state != ACTIVE or key.trust_sync != SYNC_SYNCED:
                raise ContactError("only an active key whose trust is missing can be restored")
            existing = self._trust_record(key.fingerprint)
            if _trust_status(key, existing) not in NEEDS_RESTORE:
                raise ContactError("this key is already trusted")
            _require_typed_fingerprint(confirmed_fingerprint, key.fingerprint)
            self._require_marker()
            label = _trust_label(record.label, key.purpose)
            if existing is None:
                # Journal first: the trust about to be created belongs to the contact.
                if key.trust_origin != ORIGIN_CONTACT:
                    record = _replace_key(record, replace(key, trust_origin=ORIGIN_CONTACT))
                    self.store.save(record)
                self.trust.add(key.public_key_pem.encode("ascii"), label, key.fingerprint)
            else:
                self.trust.set_usage(
                    key.fingerprint,
                    USAGE_FULL,
                    label=label if key.trust_origin == ORIGIN_CONTACT else None,
                )
            return self._view(record)

    def reconcile(self, contact_id: str) -> tuple[ContactView, tuple[str, ...]]:
        """Retry unfinished trust changes. Never grants trust the user has not confirmed."""
        with _PAIRING_LOCK:
            record = self.store.get(contact_id)
            if record.deletion_pending:
                raise ContactIncompleteError("this contact's deletion is incomplete; retry deleting it")
            failed: list[str] = []
            self._require_marker()
            for key in record.keys:
                if key.state != RETIRED:
                    continue
                try:
                    updated = self._apply_retired_trust(record.label, key, allow_grant=True)
                except _TRUST_FAILURES:
                    failed.append(key.fingerprint)
                    continue
                if updated != key:
                    record = _replace_key(record, updated)
                    self.store.save(record)
            record, pending = self._apply_pending_grants(record)
            return self._view(record), tuple(failed) + pending

    def discard_key(self, contact_id: str, fingerprint: str) -> ContactView | None:
        """Remove a pending or verified (never active or retired) key."""
        with _PAIRING_LOCK:
            record = self._open_contact(contact_id)
            key = self._find_key(record, fingerprint)
            if key.state not in _UNTRUSTED_STATES:
                raise ContactError("only an unconfirmed key can be discarded")
            remaining = tuple(k for k in record.keys if k.fingerprint != key.fingerprint)
            if not remaining and not record.confirmed:
                self.store.delete(contact_id)
                return None
            record = replace(record, keys=remaining)
            self.store.save(record)
            return self._view(record)

    def delete_contact(self, contact_id: str) -> None:
        """Delete a contact under the documented trust policy.

        * Trust the contact created (active keys and retired signing history)
          is removed from the trust store, so older packages from this contact
          can no longer be verified.
        * Keys the user trusted independently before pairing go back to normal
          standalone trust, including retired ones the contact had restricted.
        * Legacy keys with ambiguous origin are left exactly as they are in the
          trust store (never revoked, never widened) and become standalone
          trusted keys the user can remove in Key Management.
        * Unconfirmed keys never had contact trust and are simply dropped.
        """
        with _PAIRING_LOCK:
            record = self.store.get(contact_id)
            failed = False
            for key in record.keys:
                if key.state not in _LINKED_STATES:
                    continue
                try:
                    existing = self._trust_record(key.fingerprint)
                    if key.trust_origin == ORIGIN_CONTACT:
                        if existing is not None:
                            self.trust.delete(key.fingerprint)
                    elif (
                        key.trust_origin == ORIGIN_INDEPENDENT
                        and existing is not None
                        and existing.usage != USAGE_FULL
                    ):
                        self.trust.set_usage(key.fingerprint, USAGE_FULL)
                except _TRUST_FAILURES:
                    failed = True
            if failed:
                if not record.deletion_pending:
                    self.store.save(replace(record, deletion_pending=True))
                raise ContactIncompleteError(
                    "deletion is incomplete: some keys could not be updated in your trusted keys. "
                    "Retry deleting the contact."
                )
            self.store.delete(contact_id)

    # Internals ----------------------------------------------------------

    def _require_marker(self) -> None:
        try:
            mark_contacts_initialized(self.trust.directory)
        except OSError as exc:
            raise ContactIncompleteError(
                "could not record contact initialization; nothing was trusted. Retry."
            ) from exc

    def _open_contact(self, contact_id: str) -> ContactRecord:
        record = self.store.get(contact_id)
        if record.deletion_pending:
            raise ContactIncompleteError("this contact is being deleted; retry deleting it first")
        return record

    @staticmethod
    def _find_key(record: ContactRecord, fingerprint: str) -> ContactKey:
        key = record.find(fingerprint) if isinstance(fingerprint, str) else None
        if key is None:
            raise ContactNotFoundError("contact key not found")
        return key

    def _apply_retired_trust(self, contact_label: str, key: ContactKey, *, allow_grant: bool) -> ContactKey:
        """Bring a retired key's trust-store entry to its retired usage. Idempotent."""
        existing = self._trust_record(key.fingerprint)
        if key.algorithm == key_serialization.MLKEM:
            if key.trust_origin == ORIGIN_CONTACT:
                if existing is not None:
                    self.trust.delete(key.fingerprint)
            elif existing is not None and existing.usage != USAGE_SUSPENDED:
                # Independent trust is kept but cannot be used for new encryption.
                self.trust.set_usage(key.fingerprint, USAGE_SUSPENDED)
            return key
        if existing is None:
            if not allow_grant:
                return key
            self.trust.add(
                key.public_key_pem.encode("ascii"),
                _retired_label(contact_label),
                key.fingerprint,
                usage=USAGE_VERIFY_ONLY,
            )
            return replace(key, trust_origin=ORIGIN_CONTACT)
        if existing.usage != USAGE_VERIFY_ONLY:
            self.trust.set_usage(
                key.fingerprint,
                USAGE_VERIFY_ONLY,
                label=_retired_label(contact_label) if key.trust_origin == ORIGIN_CONTACT else None,
            )
        return key

    def _tighten_retired(self, record: ContactRecord) -> None:
        """Safe-direction cleanup only: never grants or widens trust."""
        if record.deletion_pending:
            return
        for key in record.keys:
            if key.state == RETIRED:
                try:
                    self._apply_retired_trust(record.label, key, allow_grant=False)
                except _TRUST_FAILURES:
                    pass  # Surfaced as cleanup_pending in the view.

    def _apply_pending_grants(self, record: ContactRecord) -> tuple[ContactRecord, tuple[str, ...]]:
        pending: list[str] = []
        for key in record.keys:
            if key.state != ACTIVE or key.trust_sync != SYNC_PENDING:
                continue
            try:
                existing = self._trust_record(key.fingerprint)
                label = _trust_label(record.label, key.purpose)
                if existing is None:
                    self.trust.add(key.public_key_pem.encode("ascii"), label, key.fingerprint)
                elif existing.usage != USAGE_FULL:
                    self.trust.set_usage(key.fingerprint, USAGE_FULL, label=label)
                record = _replace_key(record, replace(key, trust_sync=SYNC_SYNCED))
                self.store.save(record)
            except _TRUST_FAILURES:
                pending.append(key.fingerprint)
        return record, tuple(pending)

    def _trust_record(self, fingerprint: str) -> TrustedKeyRecord | None:
        try:
            return self.trust.get(fingerprint)
        except KeyNotFoundError:
            return None
        except KeyManagementError as exc:
            raise ContactError("a trusted-key record is malformed") from exc

    def _view(self, record: ContactRecord) -> ContactView:
        views = []
        for key in record.keys:
            try:
                existing = self._trust_record(key.fingerprint)
            except ContactError:
                existing = None
            views.append(KeyTrustView(key, _trust_status(key, existing), existing.usage if existing else None))
        return ContactView(record, tuple(views))

    def _analyze(
        self, bundle_text: str, contact_id: str | None
    ) -> tuple[PairingAnalysis, dict[str, str], ContactRecord | None]:
        preview = parse_bundle(bundle_text)
        purposes = [entry.purpose for entry in preview.entries]
        if len(set(purposes)) != len(purposes):
            raise ContactError("pairing accepts at most one key per purpose in a bundle")
        target = self._open_contact(contact_id) if contact_id is not None else None
        owners: dict[str, tuple[ContactRecord, ContactKey]] = {}
        for record in self.store.list_records():
            for key in record.keys:
                owners.setdefault(key.fingerprint, (record, key))

        assessments: list[KeyAssessment] = []
        matching: dict[str, str] = {}
        for entry in preview.entries:
            fingerprint = entry.key_id
            base = dict(
                fingerprint=fingerprint,
                algorithm=entry.algorithm,
                purpose=entry.purpose,
                in_trusted_keys=self._trust_record_or_none(fingerprint) is not None,
            )
            owner = owners.get(fingerprint)
            if owner is not None:
                matching.setdefault(owner[0].contact_id, owner[0].label)
            if owner is not None and (target is None or owner[0].contact_id != target.contact_id):
                assessments.append(KeyAssessment(
                    **base,
                    status=CONFLICT,
                    detail="this fingerprint already belongs to a different contact; it will not be reassigned",
                    conflicting_contact_id=owner[0].contact_id,
                    conflicting_contact_label=owner[0].label,
                ))
            elif owner is not None:
                existing = owner[1]
                if existing.state == RETIRED:
                    assessments.append(KeyAssessment(
                        **base, status=PREVIOUSLY_RETIRED,
                        detail="this key was retired from this contact and cannot be re-added",
                        current_key_version=existing.key_version,
                    ))
                else:
                    assessments.append(KeyAssessment(
                        **base, status=ALREADY_PRESENT,
                        detail=f"already present on this contact ({existing.state})",
                        current_key_version=existing.key_version,
                    ))
            elif target is None:
                assessments.append(KeyAssessment(
                    **base, status=NEW_KEY,
                    detail="will be added as untrusted until its full fingerprint is verified",
                ))
            else:
                waiting = next(
                    (k for k in target.keys if k.state in _UNTRUSTED_STATES and k.purpose == entry.purpose),
                    None,
                )
                current = target.active_key(entry.purpose)
                if waiting is not None:
                    assessments.append(KeyAssessment(
                        **base, status=PENDING_CONFLICT,
                        detail="another unconfirmed key is already waiting for this purpose; discard it first",
                        current_fingerprint=waiting.fingerprint,
                    ))
                elif current is not None:
                    assessments.append(KeyAssessment(
                        **base, status=PENDING_REPLACEMENT,
                        detail="replaces the current trusted key only after its full fingerprint is verified",
                        current_fingerprint=current.fingerprint,
                        current_key_version=current.key_version,
                    ))
                else:
                    assessments.append(KeyAssessment(
                        **base, status=NEW_PURPOSE,
                        detail="new purpose for this contact; untrusted until its full fingerprint is verified",
                    ))

        keys = tuple(assessments)
        analysis = PairingAnalysis(
            claimed_label=preview.label,
            target_contact_id=target.contact_id if target else None,
            keys=keys,
            matching_contacts=tuple(matching.items()),
            can_stage=not any(k.status in BLOCKING for k in keys) and any(k.status in STAGEABLE for k in keys),
        )
        pems = {entry.key_id: entry.public_key_pem for entry in preview.entries}
        return analysis, pems, target

    def _trust_record_or_none(self, fingerprint: str) -> TrustedKeyRecord | None:
        try:
            return self._trust_record(fingerprint)
        except ContactError:
            return None


def _trust_status(key: ContactKey, existing: TrustedKeyRecord | None) -> str:
    usage = existing.usage if existing is not None else None
    if key.state in _UNTRUSTED_STATES:
        return UNTRUSTED
    if key.state == ACTIVE:
        if key.trust_sync == SYNC_PENDING:
            return ACTIVATION_PENDING
        if usage == USAGE_FULL:
            return TRUSTED
        return MISSING if usage is None else DOWNGRADED
    if key.algorithm == key_serialization.MLKEM:
        if usage is None:
            return RETIRED_REMOVED
        if key.trust_origin in (ORIGIN_INDEPENDENT, ORIGIN_AMBIGUOUS) and usage == USAGE_SUSPENDED:
            return SUSPENDED
        return CLEANUP_PENDING
    if usage == USAGE_VERIFY_ONLY:
        return VERIFICATION_ONLY
    return HISTORY_UNAVAILABLE if usage is None else CLEANUP_PENDING


def _require_typed_fingerprint(confirmed_fingerprint: object, expected: str) -> None:
    typed = _WHITESPACE_RE.sub("", confirmed_fingerprint if isinstance(confirmed_fingerprint, str) else "").lower()
    if not _FINGERPRINT_RE.fullmatch(typed) or not secrets.compare_digest(typed, expected):
        raise TrustConfirmationError("the typed fingerprint does not match this key")


def _replace_key(record: ContactRecord, updated: ContactKey) -> ContactRecord:
    return replace(
        record,
        keys=tuple(updated if k.fingerprint == updated.fingerprint else k for k in record.keys),
    )


def _trust_label(contact_label: str, purpose: str) -> str:
    return f"{contact_label[:115]} · {purpose}"


def _retired_label(contact_label: str) -> str:
    return f"{contact_label[:100]} · signing · retired"


def _contact_json(record: ContactRecord) -> bytes:
    data = {
        "format": CONTACT_FORMAT,
        "version": CONTACT_RECORD_VERSION,
        "contact_id": record.contact_id,
        "label": record.label,
        "claimed_label": record.claimed_label,
        "confirmed": record.confirmed,
        "deletion_pending": record.deletion_pending,
        "created_at": record.created_at,
        "keys": [
            {
                "fingerprint": key.fingerprint,
                "algorithm": key.algorithm,
                "purpose": key.purpose,
                "public_key_pem": key.public_key_pem,
                "state": key.state,
                "key_version": key.key_version,
                "trust_origin": key.trust_origin,
                "trust_sync": key.trust_sync,
                "added_at": key.added_at,
                "verified_at": key.verified_at,
                "activated_at": key.activated_at,
                "retired_at": key.retired_at,
            }
            for key in record.keys
        ],
    }
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _parse_contact(data: object) -> ContactRecord:
    if not isinstance(data, dict) or data.get("format") != CONTACT_FORMAT:
        raise ContactRecordError("not a contact record")
    version = data.get("version")
    if not _is_int(version) or version not in (1, 2):
        raise ContactRecordError("unsupported contact record version")
    if set(data) != (_CONTACT_FIELDS_V1 if version == 1 else _CONTACT_FIELDS_V2):
        raise ContactRecordError("contact record has missing or unexpected fields")
    if not isinstance(data["keys"], list):
        raise ContactRecordError("contact keys must be a list")
    keys = tuple(_parse_key(raw, version) for raw in data["keys"])
    record = ContactRecord(
        contact_id=data["contact_id"],
        label=data["label"],
        claimed_label=data["claimed_label"],
        confirmed=data["confirmed"],
        created_at=data["created_at"],
        keys=keys,
        deletion_pending=data["deletion_pending"] if version == 2 else False,
    )
    _validate_record(record)
    return record


def _parse_key(raw: object, version: int) -> ContactKey:
    if not isinstance(raw, dict) or set(raw) != (_KEY_FIELDS_V1 if version == 1 else _KEY_FIELDS_V2):
        raise ContactRecordError("contact key has missing or unexpected fields")
    if version == 1:
        # Phase 2 reused existing standalone trust without recording it, so the
        # origin of a confirmed v1 key is unknown.
        linked = raw.get("state") in (ACTIVE, RETIRED)
        return ContactKey(**raw, trust_origin=ORIGIN_AMBIGUOUS if linked else None, trust_sync=SYNC_SYNCED)
    return ContactKey(**raw)


def _validate_record(record: ContactRecord) -> None:
    if not isinstance(record.contact_id, str) or not _CONTACT_ID_RE.fullmatch(record.contact_id):
        raise ContactRecordError("contact record has an invalid ID")
    if _validate_label(record.label) != record.label or _validate_label(record.claimed_label) != record.claimed_label:
        raise ContactRecordError("contact record has an invalid label")
    if (
        not isinstance(record.confirmed, bool)
        or not isinstance(record.deletion_pending, bool)
        or not _is_timestamp(record.created_at)
    ):
        raise ContactRecordError("contact record has invalid metadata")
    seen: set[str] = set()
    active_purposes: set[str] = set()
    waiting_purposes: set[str] = set()
    versions: set[tuple[str, int]] = set()
    for key in record.keys:
        _validate_key(key)
        if key.fingerprint in seen:
            raise ContactRecordError("contact record repeats a key")
        seen.add(key.fingerprint)
        if key.state == ACTIVE:
            if key.purpose in active_purposes:
                raise ContactRecordError("contact record has two active keys for one purpose")
            active_purposes.add(key.purpose)
        if key.state in _UNTRUSTED_STATES:
            if key.purpose in waiting_purposes:
                raise ContactRecordError("contact record has two unconfirmed keys for one purpose")
            waiting_purposes.add(key.purpose)
        if key.key_version is not None:
            if (key.purpose, key.key_version) in versions:
                raise ContactRecordError("contact record repeats a key version")
            versions.add((key.purpose, key.key_version))
        if key.state in _LINKED_STATES and not record.confirmed:
            raise ContactRecordError("an unconfirmed contact cannot have trusted keys")


def _validate_key(key: ContactKey) -> None:
    text_fields = (key.fingerprint, key.algorithm, key.purpose, key.public_key_pem, key.state, key.trust_sync)
    if not all(isinstance(v, str) for v in text_fields):
        raise ContactRecordError("contact key has a field of the wrong type")
    if key.state not in KEY_STATES:
        raise ContactRecordError("contact key has an invalid state")
    if not _FINGERPRINT_RE.fullmatch(key.fingerprint):
        raise ContactRecordError("contact key has an invalid fingerprint")
    if PURPOSE_FOR_ALGORITHM.get(key.algorithm) != key.purpose:
        raise ContactRecordError("contact key purpose does not match its algorithm")
    # Recompute the fingerprint from the stored public key on every load and save.
    _canonical_entry(key.algorithm, key.public_key_pem, key.fingerprint)
    linked = key.state in _LINKED_STATES
    if linked != (key.key_version is not None):
        raise ContactRecordError("only active or retired keys carry a key version")
    if key.key_version is not None and (not _is_int(key.key_version) or key.key_version < 1):
        raise ContactRecordError("contact key has an invalid key version")
    if linked != (key.trust_origin in _ORIGINS) or (
        not linked and key.trust_origin is not None
    ):
        raise ContactRecordError("contact key trust origin does not match its state")
    if key.trust_sync not in (SYNC_SYNCED, SYNC_PENDING):
        raise ContactRecordError("contact key has an invalid trust sync state")
    if key.trust_sync == SYNC_PENDING and not (key.state == ACTIVE and key.trust_origin == ORIGIN_CONTACT):
        raise ContactRecordError("only a contact-created active key can have a pending trust grant")
    expectations = (
        (key.added_at, True),
        (key.verified_at, key.state != PENDING),
        (key.activated_at, linked),
        (key.retired_at, key.state == RETIRED),
    )
    for value, required in expectations:
        if required != (value is not None) or (value is not None and not _is_timestamp(value)):
            raise ContactRecordError("contact key timestamps do not match its state")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_timestamp(value: object) -> bool:
    return _is_int(value) and 0 <= value <= 0xFFFFFFFFFFFFFFFF
