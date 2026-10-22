"""Non-secret key-management record models."""

from dataclasses import dataclass


@dataclass(frozen=True)
class KeyRecord:
    algorithm: str
    key_id: str
    label: str
    public_key_pem: str


@dataclass(frozen=True)
class PublicKeyCandidate:
    algorithm: str
    key_id: str
    public_key_pem: str


@dataclass(frozen=True)
class TrustedKeyRecord:
    algorithm: str
    key_id: str
    label: str
    public_key_pem: str
    trusted: bool = True
