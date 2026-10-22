"""SPKI PEM public-key serialization for the approved PQC key types."""

from typing import TypeAlias

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa

from .crypto_errors import CryptoInputError

Algorithm: TypeAlias = str
MLKEM = "ML-KEM-768"
MLDSA = "ML-DSA-65"
SUPPORTED_ALGORITHMS = (MLKEM, MLDSA)


def algorithm_for_key(key: object) -> str:
    if isinstance(key, (mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey)):
        return MLKEM
    if isinstance(key, (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey)):
        return MLDSA
    raise CryptoInputError("unsupported key type")


def public_key_for(key: object) -> mlkem.MLKEM768PublicKey | mldsa.MLDSA65PublicKey:
    if isinstance(key, (mlkem.MLKEM768PrivateKey, mldsa.MLDSA65PrivateKey)):
        return key.public_key()
    if isinstance(key, (mlkem.MLKEM768PublicKey, mldsa.MLDSA65PublicKey)):
        return key
    raise CryptoInputError("unsupported key type")


def raw_public_bytes(public_key: object) -> bytes:
    algorithm_for_key(public_key)
    return public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def export_public_key(public_key: object) -> bytes:
    algorithm_for_key(public_key)
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def import_public_key(pem: bytes) -> mlkem.MLKEM768PublicKey | mldsa.MLDSA65PublicKey:
    if not isinstance(pem, bytes):
        raise CryptoInputError("public key must be PEM bytes")
    try:
        public_key = serialization.load_pem_public_key(pem)
        algorithm_for_key(public_key)
    except (TypeError, ValueError, CryptoInputError) as exc:
        raise CryptoInputError("invalid or unsupported public key PEM") from exc
    return public_key
