"""API dependencies for per-user key and trust stores."""

from backend.app.core.config import key_data_dir, trust_data_dir
from fastapi import Depends
from backend.app.key_management.contacts import ContactService, ContactStore, contacts_directory_for
from backend.app.key_management.key_service import KeyService
from backend.app.key_management.key_storage import KeyStore
from backend.app.key_management.trust_store import TrustStore
from backend.app.services.file_exchange_service import FileExchangeService


def get_key_service() -> KeyService:
    return KeyService(KeyStore(key_data_dir()))


def get_trust_store() -> TrustStore:
    return TrustStore(trust_data_dir())


def get_file_exchange_service(
    keys: KeyService = Depends(get_key_service),
    trust: TrustStore = Depends(get_trust_store),
) -> FileExchangeService:
    return FileExchangeService(keys, trust)


def get_contact_service(trust: TrustStore = Depends(get_trust_store)) -> ContactService:
    # Contacts write trust only through the same TrustStore that file exchange reads,
    # and live beside it so a test or override of the trust store moves both together.
    return ContactService(ContactStore(contacts_directory_for(trust.directory)), trust)
