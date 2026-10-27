"""Application service for supported key generation and record operations."""

from backend.app.crypto import kem_service, signature_service

from .key_storage import KeyStore
from .models import KeyRecord, PublicKeyCandidate
from .public_key_service import inspect_public_key


class KeyService:
    def __init__(self, store: KeyStore):
        self.store = store

    def generate_kem_key(self, label: str, passphrase: str) -> KeyRecord:
        private_key, _ = kem_service.generate_keypair()
        return self.store.save_private_key(private_key, label, passphrase)

    def generate_signature_key(self, label: str, passphrase: str) -> KeyRecord:
        private_key, _ = signature_service.generate_keypair()
        return self.store.save_private_key(private_key, label, passphrase)

    def list_keys(self) -> list[KeyRecord]:
        return self.store.list_records()

    def get_public_record(self, identifier: str) -> KeyRecord:
        """Return a verified local key record's public, non-secret metadata."""
        return self.store.get_record(identifier)

    def export_public_key(self, identifier: str) -> bytes:
        return self.store.export_public_key(identifier)

    def load_private_key(self, identifier: str, passphrase: str, expected_algorithm: str) -> object:
        return self.store.load_private_key(identifier, passphrase, expected_algorithm)

    def delete_key(self, identifier: str) -> None:
        self.store.delete(identifier)

    @staticmethod
    def inspect_public_key(pem: bytes) -> PublicKeyCandidate:
        return inspect_public_key(pem)

