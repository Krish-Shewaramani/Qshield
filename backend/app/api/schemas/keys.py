"""Schemas for local keys and explicitly trusted public keys."""

from pydantic import BaseModel, Field


class GenerateKeyRequest(BaseModel):
    label: str = Field(min_length=1, max_length=128)
    # The cap permits long user-selected passphrases while bounding API input.
    passphrase: str = Field(min_length=1, max_length=1024)


class KeyRecordResponse(BaseModel):
    algorithm: str
    key_id: str
    label: str
    public_key_pem: str


class PublicKeyPreviewRequest(BaseModel):
    public_key_pem: str = Field(min_length=1, max_length=10000)


class PublicKeyPreviewResponse(BaseModel):
    algorithm: str
    key_id: str
    public_key_pem: str


class TrustedKeyImportRequest(PublicKeyPreviewRequest):
    label: str = Field(min_length=1, max_length=128)
    confirmed_fingerprint: str = Field(min_length=64, max_length=64)


class TrustedKeyReauthorizeRequest(BaseModel):
    # Whitespace is ignored; the complete 64-character fingerprint is required.
    confirmed_fingerprint: str = Field(min_length=64, max_length=256)


class TrustedKeyRecordResponse(KeyRecordResponse):
    trusted: bool
    usage: str = "full"
    # Present when a contact manages this trusted key.
    contact_id: str | None = None
    contact_label: str | None = None
    contact_key_state: str | None = None
    trust_origin: str | None = None


class ContactBundleExportRequest(BaseModel):
    label: str = Field(min_length=1, max_length=128)
    key_ids: list[str] = Field(min_length=1, max_length=8)


class ContactBundlePreviewRequest(BaseModel):
    # Raw bundle text so the backend can reject duplicate JSON fields itself.
    bundle_json: str = Field(min_length=1, max_length=32 * 1024)


class ContactBundleKeyPreview(BaseModel):
    purpose: str
    algorithm: str
    key_id: str
    public_key_pem: str


class ContactBundlePreviewResponse(BaseModel):
    label: str
    keys: list[ContactBundleKeyPreview]
    trusted: bool
