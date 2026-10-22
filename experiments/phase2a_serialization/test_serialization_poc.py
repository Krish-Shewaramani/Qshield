import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa

from serialization_poc import (
    encrypted_pkcs8,
    inspect_encrypted_pkcs8,
    load_encrypted_pkcs8,
    load_unencrypted_pkcs8,
    open_pkcs8,
    seal_pkcs8,
    serialize_unencrypted_pkcs8,
)


PASSPHRASE = "phase2a-only test passphrase"
WRONG_PASSPHRASE = "incorrect phase2a passphrase"
MESSAGE = b"QuantumShield Phase 2A serialization proof"


def assert_functional(test: unittest.TestCase, key: object) -> None:
    if isinstance(key, mlkem.MLKEM768PrivateKey):
        sender_secret, ciphertext = key.public_key().encapsulate()
        recipient_secret = key.decapsulate(ciphertext)
        test.assertEqual(sender_secret, recipient_secret)
    elif isinstance(key, mldsa.MLDSA65PrivateKey):
        signature = key.sign(MESSAGE)
        key.public_key().verify(signature, MESSAGE)
        with test.assertRaises(InvalidSignature):
            key.public_key().verify(signature, MESSAGE + b" altered")
    else:
        test.fail("loader returned an unexpected private-key type")


class SerializationProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.keys = (
            ("ML-KEM-768", mlkem.MLKEM768PrivateKey.generate()),
            ("ML-DSA-65", mldsa.MLDSA65PrivateKey.generate()),
        )

    def test_unencrypted_pkcs8_loaders_reconstruct_working_keys(self) -> None:
        for name, key in self.keys:
            with self.subTest(algorithm=name):
                encoded = serialize_unencrypted_pkcs8(key)
                reconstructed = load_unencrypted_pkcs8(encoded)
                self.assertIsInstance(reconstructed, type(key))
                assert_functional(self, reconstructed)

    def test_native_encrypted_pkcs8_loads_and_rejects_wrong_passphrase(self) -> None:
        for name, key in self.keys:
            with self.subTest(algorithm=name):
                encrypted = encrypted_pkcs8(key, PASSPHRASE.encode("utf-8"))
                reconstructed = load_encrypted_pkcs8(encrypted, PASSPHRASE.encode("utf-8"))
                self.assertIsInstance(reconstructed, type(key))
                assert_functional(self, reconstructed)
                with self.assertRaises((ValueError, TypeError)):
                    load_encrypted_pkcs8(encrypted, WRONG_PASSPHRASE.encode("utf-8"))
                observed = inspect_encrypted_pkcs8(encrypted)
                self.assertGreater(observed["kdf_iterations"], 0)
                print(f"Observed native {name} encryption parameters: {observed}")

    def test_scrypt_aes_gcm_envelope_round_trip(self) -> None:
        for name, key in self.keys:
            with self.subTest(algorithm=name):
                envelope = seal_pkcs8(key, PASSPHRASE, log_n=12)
                reconstructed = open_pkcs8(envelope, PASSPHRASE)
                self.assertIsInstance(reconstructed, type(key))
                assert_functional(self, reconstructed)

    def test_scrypt_aes_gcm_envelope_default_round_trip(self) -> None:
        for name, key in self.keys:
            with self.subTest(algorithm=name):
                envelope = seal_pkcs8(key, PASSPHRASE)
                self.assertEqual(envelope[5], 17)
                reconstructed = open_pkcs8(envelope, PASSPHRASE)
                self.assertIsInstance(reconstructed, type(key))
                assert_functional(self, reconstructed)

    def test_scrypt_aes_gcm_envelope_rejects_wrong_passphrase(self) -> None:
        envelope = seal_pkcs8(self.keys[0][1], PASSPHRASE, log_n=12)
        with self.assertRaises(InvalidTag):
            open_pkcs8(envelope, WRONG_PASSPHRASE)

    def test_scrypt_aes_gcm_envelope_rejects_tampering(self) -> None:
        envelope = seal_pkcs8(self.keys[0][1], PASSPHRASE, log_n=12)
        for offset in (0, 4, 8):
            with self.subTest(offset=offset):
                tampered = bytearray(envelope)
                tampered[offset] ^= 1
                with self.assertRaises(ValueError):
                    open_pkcs8(bytes(tampered), PASSPHRASE)
        for offset in (20, len(envelope) - 1):
            with self.subTest(offset=offset):
                tampered = bytearray(envelope)
                tampered[offset] ^= 1
                with self.assertRaises(InvalidTag):
                    open_pkcs8(bytes(tampered), PASSPHRASE)

    def test_scrypt_aes_gcm_envelope_rejects_malformed_inputs(self) -> None:
        envelope = seal_pkcs8(self.keys[0][1], PASSPHRASE, log_n=12)
        malformed = (
            b"",
            envelope[:10],
            envelope[:57],
            b"BAD!" + envelope[4:],
            envelope[:4] + bytes([2]) + envelope[5:],
            envelope[:5] + bytes([18]) + envelope[6:],
            envelope[:6] + (9).to_bytes(4, "big") + envelope[10:],
        )
        for candidate in malformed:
            with self.subTest(length=len(candidate)):
                with self.assertRaises(ValueError):
                    open_pkcs8(candidate, PASSPHRASE)

    def test_envelope_parameter_bounds_are_checked_before_scrypt(self) -> None:
        envelope = seal_pkcs8(self.keys[0][1], PASSPHRASE, log_n=12)
        invalid_headers = {
            "log_n above maximum": envelope[:5] + bytes([18]) + envelope[6:],
            "unsupported r": envelope[:6] + (7).to_bytes(4, "big") + envelope[10:],
            "unsupported p": envelope[:10] + (2).to_bytes(4, "big") + envelope[14:],
        }
        for label, candidate in invalid_headers.items():
            with self.subTest(parameter=label):
                with patch("serialization_poc.hashlib.scrypt") as scrypt:
                    with self.assertRaises(ValueError):
                        open_pkcs8(candidate, PASSPHRASE)
                    scrypt.assert_not_called()

    def test_unsupported_version_is_rejected_before_scrypt(self) -> None:
        envelope = seal_pkcs8(self.keys[0][1], PASSPHRASE, log_n=12)
        unsupported = envelope[:4] + bytes([2]) + envelope[5:]
        with patch("serialization_poc.hashlib.scrypt") as scrypt:
            with self.assertRaisesRegex(ValueError, "unsupported envelope version"):
                open_pkcs8(unsupported, PASSPHRASE)
            scrypt.assert_not_called()

    def test_pkcs8_uses_der_and_envelope_has_version_and_scrypt_fields(self) -> None:
        der = serialize_unencrypted_pkcs8(self.keys[0][1])
        self.assertEqual(der[0], 0x30)
        envelope = seal_pkcs8(self.keys[0][1], PASSPHRASE, log_n=12)
        self.assertEqual(envelope[:4], b"QSKS")
        self.assertEqual(envelope[4], 1)
        self.assertEqual(envelope[5], 12)
        self.assertEqual(int.from_bytes(envelope[6:10], "big"), 8)
        self.assertEqual(int.from_bytes(envelope[10:14], "big"), 1)
        self.assertGreaterEqual(len(envelope), 38 + 16)


if __name__ == "__main__":
    unittest.main(verbosity=2)
