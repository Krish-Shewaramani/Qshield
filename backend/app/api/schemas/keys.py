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


class TrustedKeyRecordResponse(KeyRecordResponse):
    trusted: bool
