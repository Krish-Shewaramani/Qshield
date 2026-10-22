"""ML-KEM-768 key generation and encapsulation operations."""

from cryptography.hazmat.primitives.asymmetric import mlkem


def generate_keypair() -> tuple[mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey]:
    private_key = mlkem.MLKEM768PrivateKey.generate()
    return private_key, private_key.public_key()


def encapsulate(public_key: mlkem.MLKEM768PublicKey) -> tuple[bytes, bytes]:
    """Return ``(ciphertext, shared_secret)`` for an ML-KEM-768 public key."""
    shared_secret, ciphertext = public_key.encapsulate()
    return ciphertext, shared_secret


def decapsulate(
    private_key: mlkem.MLKEM768PrivateKey, ciphertext: bytes
) -> bytes:
    """Return the shared secret. ML-KEM implicit rejection is preserved."""
    return private_key.decapsulate(ciphertext)
