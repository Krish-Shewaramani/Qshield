import unittest

from backend.app.crypto import key_derivation
from backend.app.crypto.crypto_errors import CryptoInputError


class KeyDerivationTests(unittest.TestCase):
    def test_hkdf_sha256_derives_requested_key(self) -> None:
        key = key_derivation.derive_key(b"shared secret", salt=b"salt", info=b"context")
        self.assertEqual(len(key), 32)
        self.assertNotEqual(key, key_derivation.derive_key(b"shared secret", salt=b"salt", info=b"other context"))

    def test_hkdf_sha256_rejects_invalid_input(self) -> None:
        with self.assertRaises(CryptoInputError):
            key_derivation.derive_key(b"", salt=None, info=b"context")
        with self.assertRaises(CryptoInputError):
            key_derivation.derive_key(b"secret", salt=None, info=b"context", length=0)
