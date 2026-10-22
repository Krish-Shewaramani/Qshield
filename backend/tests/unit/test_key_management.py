import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa

from backend.app.crypto import key_serialization, kem_service, signature_service
from backend.app.key_management.errors import (
    FingerprintMismatchError,
    KeyTypeMismatchError,
    KeyUnlockError,
    KeyRecordError,
    PublicKeyImportError,
    TrustConfirmationError,
)
from backend.app.key_management.fingerprints import key_id
from backend.app.key_management.key_storage import KeyStore
from backend.app.key_management.public_key_service import inspect_public_key
from backend.app.key_management.trust_store import TrustStore
from backend.app.key_management.unlock_rate_limiter import (
    UnlockCooldownError,
    UnlockRateLimiter,
)
from backend.app.key_management.qks_envelope import seal_pkcs8, serialize_unencrypted_pkcs8

PASSPHRASE = "key-management test passphrase"


class KeyStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.directory = Path(self.temp_directory.name)
        self.store = KeyStore(self.directory, unlock_limiter=UnlockRateLimiter())

    def test_ml_kem_key_storage_load_and_public_key_export(self) -> None:
        private_key, _ = kem_service.generate_keypair()
        record = self.store.save_private_key(private_key, "Recipient", PASSPHRASE)
        loaded = self.store.load_private_key(record.key_id, PASSPHRASE, "ML-KEM-768")
        ciphertext, sender_secret = kem_service.encapsulate(loaded.public_key())
        self.assertEqual(sender_secret, kem_service.decapsulate(loaded, ciphertext))
        exported = self.store.export_public_key(record.key_id)
        imported = key_serialization.import_public_key(exported)
        self.assertIsInstance(imported, mlkem.MLKEM768PublicKey)
        self.assertEqual(key_id(imported), record.key_id)
        self.assertEqual(record.algorithm, "ML-KEM-768")

    def test_ml_dsa_key_storage_load_and_public_key_export(self) -> None:
        private_key, _ = signature_service.generate_keypair()
        record = self.store.save_private_key(private_key, "Signer", PASSPHRASE)
        loaded = self.store.load_private_key(record.key_id, PASSPHRASE, "ML-DSA-65")
        message = b"key storage round trip"
        signature = signature_service.sign(loaded, message)
        signature_service.verify(loaded.public_key(), signature, message)
        with self.assertRaises(InvalidSignature):
            signature_service.verify(loaded.public_key(), signature, message + b" changed")
        imported = key_serialization.import_public_key(self.store.export_public_key(record.key_id))
        self.assertIsInstance(imported, mldsa.MLDSA65PublicKey)
        self.assertEqual(key_id(imported), record.key_id)

    def test_private_key_storage_contains_qsks_ciphertext_not_pkcs8_plaintext(self) -> None:
        private_key, _ = kem_service.generate_keypair()
        record = self.store.save_private_key(private_key, "Encrypted", PASSPHRASE)
        envelope = (self.directory / f"{record.key_id}.qks").read_bytes()
        metadata = (self.directory / f"{record.key_id}.json").read_bytes()
        clear_der = serialize_unencrypted_pkcs8(private_key)
        self.assertEqual(envelope[:4], b"QSKS")
        self.assertNotIn(clear_der, envelope)
        self.assertNotIn(clear_der, metadata)

    def test_wrong_passphrase_and_tampered_envelope_are_rejected(self) -> None:
        private_key, _ = kem_service.generate_keypair()
        record = self.store.save_private_key(private_key, "Unlock", PASSPHRASE)
        with self.assertRaises(KeyUnlockError):
            self.store.load_private_key(record.key_id, "incorrect passphrase", "ML-KEM-768")
        self.assertEqual(self.store.unlock_limiter.tracked_key_count, 1)

        envelope_path = self.directory / f"{record.key_id}.qks"
        tampered = bytearray(envelope_path.read_bytes())
        tampered[-1] ^= 1
        envelope_path.write_bytes(tampered)
        with self.assertRaises(KeyUnlockError):
            self.store.load_private_key(record.key_id, PASSPHRASE, "ML-KEM-768")

    def test_expected_key_type_mismatch_is_rejected_before_decryption(self) -> None:
        private_key, _ = kem_service.generate_keypair()
        record = self.store.save_private_key(private_key, "Typed", PASSPHRASE)
        with self.assertRaises(KeyTypeMismatchError):
            self.store.load_private_key(record.key_id, PASSPHRASE, "ML-DSA-65")
        self.assertEqual(self.store.unlock_limiter.tracked_key_count, 0)

    def test_loaded_key_fingerprint_must_match_selected_record(self) -> None:
        selected_key, _ = kem_service.generate_keypair()
        other_key, _ = kem_service.generate_keypair()
        record = self.store.save_private_key(selected_key, "Selected", PASSPHRASE)
        other_envelope = seal_pkcs8(other_key, PASSPHRASE, log_n=12)
        (self.directory / f"{record.key_id}.qks").write_bytes(other_envelope)
        with self.assertRaises(FingerprintMismatchError):
            self.store.load_private_key(record.key_id, PASSPHRASE, "ML-KEM-768")

    def test_record_metadata_fingerprint_mismatch_is_rejected(self) -> None:
        private_key, _ = kem_service.generate_keypair()
        record = self.store.save_private_key(private_key, "Metadata", PASSPHRASE)
        metadata_path = self.directory / f"{record.key_id}.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["key_id"] = "0" * 64
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        with self.assertRaises(FingerprintMismatchError):
            self.store.load_private_key(record.key_id, PASSPHRASE, "ML-KEM-768")

    def test_corrupt_metadata_and_invalid_envelope_are_rejected_generically(self) -> None:
        private_key, _ = kem_service.generate_keypair()
        record = self.store.save_private_key(private_key, "Corrupt", PASSPHRASE)
        metadata_path = self.directory / f"{record.key_id}.json"
        metadata_path.write_text("{", encoding="utf-8")
        with self.assertRaises(KeyRecordError):
            self.store.get_record(record.key_id)

        # Restore metadata from the generated record and make the envelope malformed.
        metadata_path.write_text(
            json.dumps({
                "algorithm": record.algorithm,
                "key_id": record.key_id,
                "label": record.label,
                "public_key_pem": record.public_key_pem,
            }),
            encoding="utf-8",
        )
        (self.directory / f"{record.key_id}.qks").write_bytes(b"malformed envelope")
        with self.assertRaises(KeyRecordError):
            self.store.load_private_key(record.key_id, PASSPHRASE, "ML-KEM-768")
        self.assertEqual(self.store.unlock_limiter.tracked_key_count, 0)

    def test_failed_metadata_atomic_write_removes_partial_private_record(self) -> None:
        private_key, _ = kem_service.generate_keypair()
        with patch(
            "backend.app.key_management.key_storage._atomic_write",
            side_effect=[None, OSError("simulated metadata write failure")],
        ):
            with self.assertRaises(OSError):
                self.store.save_private_key(private_key, "Cleanup", PASSPHRASE)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_cooldown_rejects_before_record_read_or_qsks_open(self) -> None:
        private_key, _ = kem_service.generate_keypair()
        record = self.store.save_private_key(private_key, "Cooling", PASSPHRASE)
        limiter = UnlockRateLimiter(clock=lambda: 0.0, global_capacity=100)
        for _ in range(5):
            with limiter.admit(record.key_id) as attempt:
                attempt.authentication_failed()
        self.store.unlock_limiter = limiter
        with patch.object(self.store, "get_record") as get_record, patch(
            "backend.app.key_management.key_storage.open_pkcs8"
        ) as open_key:
            with self.assertRaises(UnlockCooldownError):
                self.store.load_private_key(record.key_id, PASSPHRASE, "ML-KEM-768")
        get_record.assert_not_called()
        open_key.assert_not_called()


class PublicKeyImportTests(unittest.TestCase):
    def test_both_approved_public_key_types_import_from_spki_pem(self) -> None:
        for private_key in (mlkem.MLKEM768PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()):
            with self.subTest(algorithm=key_serialization.algorithm_for_key(private_key)):
                pem = key_serialization.export_public_key(private_key.public_key())
                candidate = inspect_public_key(pem)
                self.assertEqual(candidate.key_id, key_id(private_key.public_key()))
                self.assertEqual(candidate.public_key_pem.encode("ascii"), pem)

    def test_invalid_or_unsupported_public_key_import_is_rejected(self) -> None:
        with self.assertRaises(PublicKeyImportError):
            inspect_public_key(b"not an SPKI PEM")


class TrustStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.store = TrustStore(Path(self.temp_directory.name))
        _, public_key = signature_service.generate_keypair()
        self.pem = key_serialization.export_public_key(public_key)

    def test_preview_does_not_trust_and_explicit_matching_confirmation_does(self) -> None:
        candidate = self.store.preview(self.pem)
        self.assertEqual(self.store.list_records(), [])
        with self.assertRaises(TrustConfirmationError):
            self.store.add(self.pem, "Sender", "")
        self.assertEqual(self.store.list_records(), [])

        trusted = self.store.add(self.pem, "Sender", candidate.key_id)
        self.assertTrue(trusted.trusted)
        self.assertEqual(self.store.get(candidate.key_id), trusted)
        self.assertEqual(self.store.list_records(), [trusted])
        self.store.delete(candidate.key_id)
        self.assertEqual(self.store.list_records(), [])

    def test_wrong_fingerprint_confirmation_does_not_trust_key(self) -> None:
        candidate = self.store.preview(self.pem)
        with self.assertRaises(TrustConfirmationError):
            self.store.add(self.pem, "Sender", "f" * 64)
        self.assertNotIn(candidate.key_id, [record.key_id for record in self.store.list_records()])

    def test_invalid_public_key_is_not_trusted(self) -> None:
        with self.assertRaises(PublicKeyImportError):
            self.store.preview(b"invalid pem")
        self.assertEqual(self.store.list_records(), [])
