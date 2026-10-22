"""HKDF-SHA-256 key derivation."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto_errors import CryptoInputError


def derive_key(
    input_key_material: bytes,
    *,
    salt: bytes | None,
    info: bytes,
    length: int = 32,
) -> bytes:
    if not input_key_material:
        raise CryptoInputError("HKDF input key material must not be empty")
    if not 1 <= length <= 255 * hashes.SHA256.digest_size:
        raise CryptoInputError("HKDF output length is outside the SHA-256 limit")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(input_key_material)
