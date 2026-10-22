"""ML-DSA-65 key generation, signing, and verification operations."""

from cryptography.hazmat.primitives.asymmetric import mldsa


def generate_keypair() -> tuple[mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey]:
    private_key = mldsa.MLDSA65PrivateKey.generate()
    return private_key, private_key.public_key()


def sign(
    private_key: mldsa.MLDSA65PrivateKey,
    message: bytes,
    *,
    context: bytes = b"",
) -> bytes:
    return private_key.sign(message, context=context)


def verify(
    public_key: mldsa.MLDSA65PublicKey,
    signature: bytes,
    message: bytes,
    *,
    context: bytes = b"",
) -> None:
    """Verify a signature; invalid signatures raise ``InvalidSignature``."""
    public_key.verify(signature, message, context=context)
