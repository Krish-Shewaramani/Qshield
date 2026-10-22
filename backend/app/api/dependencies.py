"""API dependencies for per-user key and trust stores."""

from backend.app.core.config import key_data_dir, trust_data_dir
from fastapi import Depends
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
