"""Import and inspect supported SPKI PEM public keys."""

from backend.app.crypto import key_serialization
from backend.app.crypto.crypto_errors import CryptoInputError

from .errors import PublicKeyImportError
from .fingerprints import key_id
from .models import PublicKeyCandidate


def inspect_public_key(pem: bytes) -> PublicKeyCandidate:
    try:
        public_key = key_serialization.import_public_key(pem)
        algorithm = key_serialization.algorithm_for_key(public_key)
        canonical_pem = key_serialization.export_public_key(public_key).decode("ascii")
    except (CryptoInputError, UnicodeDecodeError) as exc:
        raise PublicKeyImportError("invalid or unsupported SPKI PEM public key") from exc
    return PublicKeyCandidate(algorithm, key_id(public_key), canonical_pem)
