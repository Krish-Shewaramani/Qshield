import unittest
from cryptography.exceptions import InvalidTag

from backend.app.crypto import symmetric_encryption
from backend.app.crypto.crypto_errors import CryptoInputError


class EncryptionTests(unittest.TestCase):
    def test_aes_256_gcm_round_trip(self) -> None:
        key = symmetric_encryption.generate_key()
        plaintext, aad = b"in-memory plaintext only", b"authenticated header"
        nonce, ciphertext = symmetric_encryption.encrypt(key, plaintext, aad=aad)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(symmetric_encryption.decrypt(key, nonce, ciphertext, aad=aad), plaintext)

    def test_aes_256_gcm_rejects_tampering_and_wrong_aad(self) -> None:
        key = symmetric_encryption.generate_key()
        nonce, ciphertext = symmetric_encryption.encrypt(key, b"message", aad=b"header")
        changed = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            symmetric_encryption.decrypt(key, nonce, changed, aad=b"header")
        with self.assertRaises(InvalidTag):
            symmetric_encryption.decrypt(key, nonce, ciphertext, aad=b"other header")

    def test_aes_256_gcm_rejects_invalid_key_and_nonce_sizes(self) -> None:
        with self.assertRaises(CryptoInputError):
            symmetric_encryption.encrypt(b"small", b"message", aad=b"")
        with self.assertRaises(CryptoInputError):
            symmetric_encryption.encrypt(bytes(32), b"message", aad=b"", nonce=bytes(8))
