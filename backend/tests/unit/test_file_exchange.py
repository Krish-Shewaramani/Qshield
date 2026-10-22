import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import mlkem

from backend.app.crypto import key_serialization, signature_service
from backend.app.file_exchange.errors import (
    PackageDecryptionError,
    PackageFormatError,
    PackageRecipientError,
    PackageVerificationError,
)
from backend.app.file_exchange.protocol import (
    HEADER_SIZE,
    MAX_FILE_SIZE,
    MAX_PACKAGE_SIZE,
    SIGNATURE_SIZE,
    build_encrypted_payload,
    parse_decrypted_payload,
    parse_header,
    parse_package,
    serialize_header,
)
from backend.app.key_management.fingerprints import key_id
from backend.app.key_management.models import TrustedKeyRecord
from backend.app.key_management.trust_store import TrustStore
from backend.app.services import package_service


class QShieldPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.trust_store = TrustStore(Path(self.temp_directory.name) / "trust")
        self.sender_private, sender_public = signature_service.generate_keypair()
        candidate_pem = key_serialization.export_public_key(sender_public)
        candidate = self.trust_store.preview(candidate_pem)
        self.trusted_sender = self.trust_store.add(
            candidate_pem, "Known sender", candidate.key_id
        )
        self.recipient_private = mlkem.MLKEM768PrivateKey.generate()
        self.package = package_service.create_package(
            "report.txt",
            b"sample confidential file bytes",
            self.recipient_private.public_key(),
            self.sender_private,
            created_at=1_800_000_000,
        )

    def test_nonempty_and_empty_file_round_trips_with_unicode_filename(self) -> None:
        cases = (
            ("notes.txt", b"file data"),
            ("résumé_日本語.txt", b""),
        )
        for filename, content in cases:
            with self.subTest(filename=filename):
                package = package_service.create_package(
                    filename,
                    content,
                    self.recipient_private.public_key(),
                    self.sender_private,
                    created_at=7,
                )
                self.assertEqual(
                    package_service.decrypt_package(
                        package, self.trusted_sender, self.recipient_private
                    ),
                    (filename, content),
                )

    def test_wrong_recipient_is_rejected_before_decapsulation(self) -> None:
        wrong_private = mlkem.MLKEM768PrivateKey.generate()
        with patch.object(
            package_service.kem_service, "decapsulate", wraps=package_service.kem_service.decapsulate
        ) as decapsulate:
            with self.assertRaises(PackageRecipientError):
                package_service.decrypt_package(
                    self.package, self.trusted_sender, wrong_private
                )
        decapsulate.assert_not_called()

    def test_wrong_or_untrusted_sender_is_rejected_before_decapsulation(self) -> None:
        _, other_public = signature_service.generate_keypair()
        other_pem = key_serialization.export_public_key(other_public)
        other_id = key_id(other_public)
        wrong_sender = TrustedKeyRecord(
            key_serialization.MLDSA,
            other_id,
            "Other sender",
            other_pem.decode("ascii"),
            True,
        )
        untrusted_sender = replace(self.trusted_sender, trusted=False)
        for record in (wrong_sender, untrusted_sender):
            with self.subTest(key_id=record.key_id, trusted=record.trusted):
                with patch.object(
                    package_service.kem_service,
                    "decapsulate",
                    wraps=package_service.kem_service.decapsulate,
                ) as decapsulate:
                    with self.assertRaises(PackageVerificationError):
                        package_service.decrypt_package(
                            self.package, record, self.recipient_private
                        )
                decapsulate.assert_not_called()

    def test_invalid_signature_and_tampered_header_or_ciphertext_are_rejected(self) -> None:
        changed_signature = bytearray(self.package)
        changed_signature[-1] ^= 1
        with patch.object(
            package_service.kem_service, "decapsulate", wraps=package_service.kem_service.decapsulate
        ) as decapsulate:
            with self.assertRaises(PackageVerificationError):
                package_service.decrypt_package(
                    bytes(changed_signature), self.trusted_sender, self.recipient_private
                )
        decapsulate.assert_not_called()
        with self.assertRaises(PackageVerificationError):
            package_service.verify_package(bytes(changed_signature), self.trusted_sender)

        changed_header = bytearray(self.package)
        changed_header[16] ^= 1  # created_at is signed
        with self.assertRaises(PackageVerificationError):
            package_service.verify_package(bytes(changed_header), self.trusted_sender)

        changed_body = bytearray(self.package)
        changed_body[HEADER_SIZE] ^= 1
        with self.assertRaises(PackageVerificationError):
            package_service.verify_package(bytes(changed_body), self.trusted_sender)

    def test_authenticated_header_tampering_fails_gcm_after_valid_signature(self) -> None:
        parsed = parse_package(self.package)
        changed_nonce = bytes([parsed.header.nonce[0] ^ 1]) + parsed.header.nonce[1:]
        changed_header = replace(parsed.header, nonce=changed_nonce)
        changed_header_bytes = serialize_header(changed_header)
        signature = signature_service.sign(
            self.sender_private,
            changed_header_bytes + parsed.aead_output,
            context=package_service.SIGNATURE_CONTEXT,
        )
        resigned_package = (
            changed_header_bytes + parsed.aead_output + signature
        )
        # Sender signature succeeds, but changing the nonce/AAD must not release plaintext.
        verified = package_service.verify_package(resigned_package, self.trusted_sender)
        with self.assertRaises(PackageDecryptionError):
            package_service.decrypt_verified_package(verified, self.recipient_private)

    def test_truncated_malformed_inconsistent_and_trailing_packages_are_rejected(self) -> None:
        wrong_magic = bytearray(self.package)
        wrong_magic[0] ^= 1
        for malformed in (
            b"",
            b"QSHIELD",
            bytes(wrong_magic),
            self.package[:-1],
            self.package + b"x",
        ):
            with self.subTest(size=len(malformed)):
                with self.assertRaises(PackageFormatError):
                    parse_package(malformed)

        wrong_length = bytearray(self.package)
        original_length = int.from_bytes(wrong_length[1188:1196], "big")
        wrong_length[1188:1196] = (original_length + 1).to_bytes(8, "big")
        with self.assertRaises(PackageFormatError):
            parse_package(bytes(wrong_length))

    def test_unsupported_version_algorithm_and_flags_are_rejected(self) -> None:
        cases = ((8, b"\x00\x02"), (10, b"\x02"), (14, b"\x00\x01"))
        for offset, value in cases:
            with self.subTest(offset=offset):
                malformed = bytearray(self.package)
                malformed[offset : offset + len(value)] = value
                with self.assertRaises(PackageFormatError):
                    parse_package(bytes(malformed))

    def test_oversized_package_is_rejected_before_header_processing(self) -> None:
        with self.assertRaises(PackageFormatError):
            parse_package(bytes(MAX_PACKAGE_SIZE + 1))

    def test_missing_or_wrong_algorithm_keys_are_rejected(self) -> None:
        with self.assertRaises(PackageFormatError):
            package_service.create_package("x", b"", None, self.sender_private)
        with self.assertRaises(PackageFormatError):
            package_service.create_package(
                "x", b"", self.recipient_private.public_key(), self.recipient_private
            )
        with self.assertRaises(PackageVerificationError):
            package_service.verify_package(self.package, None)
        with self.assertRaises(PackageRecipientError):
            package_service.decrypt_package(self.package, self.trusted_sender, None)

    def test_filename_path_traversal_and_unsafe_names_are_rejected(self) -> None:
        for filename in (
            "../secret.txt",
            "..\\secret.txt",
            ".",
            "..",
            ".. ",
            "...",
            "trailing.",
            "C:secret.txt",
            "bad\nname",
        ):
            with self.subTest(filename=filename):
                with self.assertRaises(PackageFormatError):
                    build_encrypted_payload(filename, b"data")

        for name_bytes in (b"../x", b"..\\x", b"x\x00y", b"\xff", b"x" * 256):
            payload = len(name_bytes).to_bytes(2, "big") + name_bytes
            with self.subTest(name_bytes=name_bytes):
                with self.assertRaises(PackageFormatError):
                    parse_decrypted_payload(payload)

        with self.assertRaises(PackageFormatError):
            build_encrypted_payload("é" * 128, b"data")  # 256 encoded bytes

    def test_exact_header_signature_and_total_overhead(self) -> None:
        parsed = parse_package(self.package)
        header_bytes = parsed.header_bytes
        self.assertEqual(len(parsed.header_bytes), HEADER_SIZE)
        self.assertEqual(len(parsed.signature), SIGNATURE_SIZE)
        self.assertEqual(len(self.package), HEADER_SIZE + parsed.header.ciphertext_len + SIGNATURE_SIZE)
        self.assertEqual(header_bytes[0:8], b"QSHIELD\x00")
        self.assertEqual(header_bytes[8:10], b"\x00\x01")
        self.assertEqual(header_bytes[10:16], b"\x01\x01\x01\x01\x00\x00")
        self.assertEqual(
            package_service.SIGNATURE_CONTEXT,
            b"QuantumShield/v1/package",
        )
        self.assertEqual(
            package_service.HKDF_INFO_PREFIX,
            b"QuantumShield/v1/aes-256-gcm-key",
        )
        self.assertEqual(int.from_bytes(header_bytes[16:24], "big"), 1_800_000_000)
        self.assertEqual(header_bytes[24:56].hex(), self.trusted_sender.key_id)
        self.assertEqual(header_bytes[56:88].hex(), key_id(self.recipient_private.public_key()))
        self.assertEqual(len(header_bytes[88:1176]), 1088)
        self.assertEqual(len(header_bytes[1176:1188]), 12)
        self.assertEqual(
            int.from_bytes(header_bytes[1188:1196], "big"),
            parsed.header.ciphertext_len,
        )
        filename = "report.txt"
        file_data = b"sample confidential file bytes"
        self.assertEqual(
            len(self.package) - len(file_data),
            4523 + len(filename.encode("utf-8")),
        )
        self.assertEqual(
            len(self.package),
            HEADER_SIZE + len(file_data) + 2 + len(filename.encode("utf-8")) + 16 + SIGNATURE_SIZE,
        )
        self.assertEqual(parse_header(parsed.header_bytes), parsed.header)

    def test_payload_and_header_bounds(self) -> None:
        with self.assertRaises(PackageFormatError):
            build_encrypted_payload("x", bytes(MAX_FILE_SIZE + 1))
        header = parse_package(self.package).header
        with self.assertRaises(PackageFormatError):
            serialize_header(replace(header, ciphertext_len=18))


if __name__ == "__main__":
    unittest.main()
