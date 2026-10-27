"""Schemas for contact pairing and locally stored contacts."""

from pydantic import BaseModel, Field


class PairingRequest(BaseModel):
    bundle_json: str = Field(min_length=1, max_length=32 * 1024)
    # None means "create a new contact". Matching is never inferred from labels.
    contact_id: str | None = Field(default=None, min_length=32, max_length=32)


class StageRequest(PairingRequest):
    # Local label chosen by the user; required only when creating a new contact.
    label: str | None = Field(default=None, min_length=1, max_length=128)


class ContactStorageResponse(BaseModel):
    # "ready", "missing" (initialized but folder gone) or "invalid".
    state: str
    message: str | None
    # Encryption keys suspended by this recovery; each needs re-confirmation in Key Management.
    suspended_encryption_keys: int = 0


class ReinitializeStorageRequest(BaseModel):
    # Must be true: contact history and retired-key records are not recovered.
    acknowledge_lost_history: bool


class VerifyKeyRequest(BaseModel):
    # Whitespace is ignored; the complete 64-character fingerprint is required.
    confirmed_fingerprint: str = Field(min_length=64, max_length=256)


class KeyAssessmentResponse(BaseModel):
    fingerprint: str
    algorithm: str
    purpose: str
    status: str
    detail: str
    in_trusted_keys: bool
    current_fingerprint: str | None
    current_key_version: int | None
    conflicting_contact_id: str | None
    conflicting_contact_label: str | None


class MatchingContactResponse(BaseModel):
    contact_id: str
    label: str


class PairingAnalysisResponse(BaseModel):
    claimed_label: str
    target_contact_id: str | None
    keys: list[KeyAssessmentResponse]
    matching_contacts: list[MatchingContactResponse]
    can_stage: bool


class ContactKeyResponse(BaseModel):
    fingerprint: str
    algorithm: str
    purpose: str
    public_key_pem: str
    state: str
    key_version: int | None
    trust_origin: str | None
    trust_status: str
    trust_usage: str | None
    added_at: int
    verified_at: int | None
    activated_at: int | None
    retired_at: int | None
    in_trusted_keys: bool
    usable_for_exchange: bool
    usable_for_encryption: bool
    usable_for_verification: bool


class ContactResponse(BaseModel):
    contact_id: str
    label: str
    claimed_label: str
    confirmed: bool
    deletion_pending: bool
    needs_reconcile: bool
    created_at: int
    keys: list[ContactKeyResponse]


class StageResponse(BaseModel):
    analysis: PairingAnalysisResponse
    contact: ContactResponse | None
    staged_fingerprints: list[str]


class ConfirmResponse(BaseModel):
    contact: ContactResponse
    activated: list[str]
    retired: list[str]
    # Confirmed keys whose trust grant has not been applied yet; reconcile to finish.
    activation_pending: list[str]


class ReconcileResponse(BaseModel):
    contact: ContactResponse
    failed: list[str]
