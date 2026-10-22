import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.api.dependencies import get_file_exchange_service, get_key_service, get_trust_store
from backend.app.crypto import key_serialization, signature_service
from backend.app.core import request_security
from backend.app.file_exchange.protocol import (
    MAX_FILE_SIZE,
    MAX_PACKAGE_SIZE,
    assemble_package,
    parse_package,
)
from backend.app.key_management.key_service import KeyService
from backend.app.key_management.key_storage import KeyStore
from backend.app.key_management.models import TrustedKeyRecord
from backend.app.key_management.trust_store import TrustStore
from backend.app.key_management.unlock_rate_limiter import UnlockRateLimiter
from backend.app.main import app
from backend.app.services import package_service
from backend.app.services.file_exchange_service import FileExchangeService


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FileExchangeAPITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        root = Path(self.temp_directory.name)
        self.clock = FakeClock()
        self.limiter = UnlockRateLimiter(clock=self.clock, global_capacity=100)
        self.keys = KeyService(KeyStore(root / "keys", unlock_limiter=self.limiter))
        self.trust = TrustStore(root / "trust")
        self.sender = self.keys.generate_signature_key("sender", "sender API passphrase")
        self.recipient = self.keys.generate_kem_key("recipient", "recipient API passphrase")
        self._trust_record(self.sender.public_key_pem, "sender")
        self._trust_record(self.recipient.public_key_pem, "recipient")
        self.untrusted_sender = self.keys.generate_signature_key("untrusted", "other passphrase")
        app.dependency_overrides[get_key_service] = lambda: self.keys
        app.dependency_overrides[get_trust_store] = lambda: self.trust
        app.dependency_overrides[get_file_exchange_service] = lambda: FileExchangeService(
            self.keys, self.trust
        )
        self.addCleanup(app.dependency_overrides.clear)
        self.client = TestClient(app, base_url="http://127.0.0.1:8000")
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def _trust_record(self, pem: str, label: str) -> None:
        candidate = self.trust.preview(pem.encode("ascii"))
        self.trust.add(pem.encode("ascii"), label, candidate.key_id)

    def _encrypt(self, filename: str, content: bytes, *, passphrase: str = "sender API passphrase"):
        return self.client.post(
            "/api/encrypt",
            data={
                "recipient_key_id": self.recipient.key_id,
                "signing_key_id": self.sender.key_id,
                "passphrase": passphrase,
            },
            files={"file": (filename, content, "application/octet-stream")},
        )

    def _decrypt(self, package: bytes, *, passphrase: str = "recipient API passphrase", recipient_id=None, sender_id=None):
        return self.client.post(
            "/api/decrypt",
            data={
                "recipient_key_id": recipient_id or self.recipient.key_id,
                "sender_key_id": sender_id or self.sender.key_id,
                "passphrase": passphrase,
            },
            files={"file": ("package.qshield", package, "application/octet-stream")},
        )

    def test_complete_sender_to_recipient_exchange_and_unicode_filename(self) -> None:
        source = "résumé_日本語.txt"
        content = b"encrypted file contents"
        created = self._encrypt(source, content)
        self.assertEqual(created.status_code, 200, created.text[:200])
        verified = self.client.post(
            "/api/verify",
            data={"sender_key_id": self.sender.key_id},
            files={"file": ("package.qshield", created.content, "application/octet-stream")},
        )
        self.assertEqual(verified.status_code, 200, verified.text)
        self.assertTrue(verified.json()["verified"])
        opened = self._decrypt(created.content)
        self.assertEqual(opened.status_code, 200, opened.text[:200])
        self.assertEqual(opened.content, content)
        self.assertIn("filename*=UTF-8''r%C3%A9sum%C3%A9_%E6%97%A5%E6%9C%AC%E8%AA%9E.txt", opened.headers["content-disposition"])

    def test_empty_file_round_trip(self) -> None:
        created = self._encrypt("empty.bin", b"")
        self.assertEqual(created.status_code, 200, created.text[:200])
        opened = self._decrypt(created.content)
        self.assertEqual(opened.status_code, 200, opened.text[:200])
        self.assertEqual(opened.content, b"")

    def test_wrong_passphrases_and_missing_keys_are_rejected(self) -> None:
        wrong_signing_passphrase = self._encrypt("a.txt", b"x", passphrase="wrong passphrase")
        self.assertEqual(wrong_signing_passphrase.status_code, 400)
        self.assertEqual(wrong_signing_passphrase.json(), {"detail": "selected private key is unavailable"})
        self.assertNotIn("wrong passphrase", wrong_signing_passphrase.text)
        created = self._encrypt("a.txt", b"x")
        self.assertEqual(created.status_code, 200, created.text[:200])
        wrong_recipient_passphrase = self._decrypt(created.content, passphrase="wrong passphrase")
        self.assertEqual(wrong_recipient_passphrase.status_code, 400)
        self.assertEqual(wrong_recipient_passphrase.json(), {"detail": "selected private key is unavailable"})
        self.assertNotIn("wrong passphrase", wrong_recipient_passphrase.text)
        wrong_recipient = self._decrypt(created.content, recipient_id="f" * 64)
        self.assertEqual(wrong_recipient.status_code, 400)
        signer_envelope = self.keys.store.directory / f"{self.sender.key_id}.qks"
        original_envelope = signer_envelope.read_bytes()
        signer_envelope.write_bytes(b"malformed QSKS envelope")
        malformed_signing_record = self._encrypt("a.txt", b"x")
        self.assertEqual(malformed_signing_record.status_code, 400)
        self.assertEqual(malformed_signing_record.json(), wrong_signing_passphrase.json())
        signer_envelope.write_bytes(original_envelope)
        missing_signing_key = self.client.post(
            "/api/encrypt",
            data={
                "recipient_key_id": self.recipient.key_id,
                "signing_key_id": "f" * 64,
                "passphrase": "sender API passphrase",
            },
            files={"file": ("a.txt", b"x")},
        )
        self.assertEqual(missing_signing_key.status_code, 400)
        self.assertEqual(missing_signing_key.json(), wrong_signing_passphrase.json())
        missing_sender = self.client.post(
            "/api/verify",
            data={"sender_key_id": "f" * 64},
            files={"file": ("package.qshield", created.content)},
        )
        self.assertEqual(missing_sender.status_code, 403)

    def test_signing_and_recipient_routes_share_cooldown_and_global_admission(self) -> None:
        package_response = self._encrypt("shared.txt", b"contents")
        self.assertEqual(package_response.status_code, 200, package_response.text[:200])

        # Exercise the exact production global capacity through both routes.
        self.keys.store.unlock_limiter = UnlockRateLimiter(clock=self.clock)
        self.limiter = self.keys.store.unlock_limiter
        for _ in range(4):
            failed = self._encrypt("shared.txt", b"contents", passphrase="wrong")
            self.assertEqual(failed.status_code, 400)
            self.assertEqual(failed.json(), {"detail": "selected private key is unavailable"})
        globally_rejected = self._decrypt(package_response.content)
        self.assertEqual(globally_rejected.status_code, 429)
        self.assertEqual(
            globally_rejected.json(),
            {"detail": "private-key operation is temporarily unavailable"},
        )
        self.clock.advance(2.0)
        recovered = self._decrypt(package_response.content)
        self.assertEqual(recovered.status_code, 200, recovered.text[:200])

    def test_five_failures_cool_down_then_correct_passphrase_succeeds(self) -> None:
        for _ in range(5):
            failed = self._encrypt("cooldown.txt", b"x", passphrase="wrong")
            self.assertEqual(failed.status_code, 400)
            self.assertEqual(failed.json(), {"detail": "selected private key is unavailable"})
        during = self._encrypt("cooldown.txt", b"x")
        self.assertEqual(during.status_code, 400)
        self.assertEqual(during.json(), {"detail": "selected private key is unavailable"})
        self.clock.advance(30.0)
        after = self._encrypt("cooldown.txt", b"x")
        self.assertEqual(after.status_code, 200, after.text[:200])

    def test_untrusted_sender_and_tampering_are_rejected(self) -> None:
        untrusted_private = self.keys.load_private_key(
            self.untrusted_sender.key_id, "other passphrase", "ML-DSA-65"
        )
        recipient_public = key_serialization.import_public_key(self.recipient.public_key_pem.encode("ascii"))
        untrusted_package = package_service.create_package(
            "untrusted.txt", b"hidden", recipient_public, untrusted_private
        )
        rejected_untrusted = self._decrypt(
            untrusted_package, sender_id=self.untrusted_sender.key_id
        )
        self.assertEqual(rejected_untrusted.status_code, 403)

        created = self._encrypt("signed.txt", b"hidden")
        self.assertEqual(created.status_code, 200, created.text[:200])
        wrong_sender = self.client.post(
            "/api/verify",
            data={"sender_key_id": self.recipient.key_id},
            files={"file": ("package.qshield", created.content)},
        )
        self.assertEqual(wrong_sender.status_code, 403)
        tampered = bytearray(created.content)
        tampered[1200] ^= 0x01
        rejected_tampered = self._decrypt(bytes(tampered))
        self.assertEqual(rejected_tampered.status_code, 403)
        verify_tampered = self.client.post(
            "/api/verify",
            data={"sender_key_id": self.sender.key_id},
            files={"file": ("package.qshield", bytes(tampered))},
        )
        self.assertEqual(verify_tampered.status_code, 403)

    def test_authenticated_encryption_failure_never_returns_plaintext(self) -> None:
        plaintext = b"must remain withheld"
        created = self._encrypt("auth-failure.txt", plaintext)
        self.assertEqual(created.status_code, 200, created.text[:200])
        parsed = parse_package(created.content)
        changed_aead = bytearray(parsed.aead_output)
        changed_aead[0] ^= 0x01
        sender_private = self.keys.load_private_key(
            self.sender.key_id, "sender API passphrase", "ML-DSA-65"
        )
        changed_aead_bytes = bytes(changed_aead)
        new_signature = signature_service.sign(
            sender_private,
            parsed.header_bytes + changed_aead_bytes,
            context=package_service.SIGNATURE_CONTEXT,
        )
        authenticated_but_invalid = assemble_package(
            parsed.header, changed_aead_bytes, new_signature
        )
        response = self._decrypt(authenticated_but_invalid)
        self.assertEqual(response.status_code, 400)
        self.assertNotEqual(response.content, plaintext)
        self.assertNotIn(plaintext, response.content)

    def test_malformed_packages_are_rejected(self) -> None:
        for package in (b"", b"not a qshield package"):
            response = self._decrypt(package)
            self.assertEqual(response.status_code, 400)

    def test_malformed_trust_records_are_sanitized(self) -> None:
        created = self._encrypt("signed.txt", b"hidden")
        self.assertEqual(created.status_code, 200, created.text[:200])

        # Exercise FileExchangeService's direct public-key import guard. A
        # TrustStore normally validates this first; the injected record covers
        # corruption between store validation and use.
        malformed_record = TrustedKeyRecord(
            "ML-DSA-65", self.sender.key_id, "sender", "not a valid PEM"
        )
        with patch.object(self.trust, "get", return_value=malformed_record):
            direct_import = self.client.post(
                "/api/verify",
                data={"sender_key_id": self.sender.key_id},
                files={"file": ("package.qshield", created.content)},
            )
        self.assertEqual(direct_import.status_code, 400)
        self.assertEqual(direct_import.json(), {"detail": "package is invalid"})
        self.assertNotIn("not a valid PEM", direct_import.text)

        # Exercise malformed serialized data in the temporary trust store,
        # including a non-ASCII value that cannot be encoded as PEM.
        corrupted = {
            "algorithm": "ML-DSA-65",
            "key_id": self.sender.key_id,
            "label": "sender",
            "public_key_pem": "invalid PEM Ω",
            "trusted": True,
        }
        (self.trust.directory / f"{self.sender.key_id}.json").write_text(
            json.dumps(corrupted), encoding="utf-8"
        )
        stored_record = self.client.post(
            "/api/verify",
            data={"sender_key_id": self.sender.key_id},
            files={"file": ("package.qshield", created.content)},
        )
        self.assertEqual(stored_record.status_code, 400)
        self.assertEqual(stored_record.json(), {"detail": "package is invalid"})
        self.assertNotIn("invalid PEM", stored_record.text)
        self.assertNotIn(str(self.trust.directory), stored_record.text)

    def test_multipart_duplicates_unexpected_fields_and_invalid_filename_are_rejected(self) -> None:
        boundary = "QShieldAuditBoundary"
        fields = [
            ("file", b"x", "safe.txt"),
            ("recipient_key_id", self.recipient.key_id.encode(), None),
            ("signing_key_id", self.sender.key_id.encode(), None),
            ("passphrase", b"sender API passphrase", None),
        ]

        def encode(parts):
            body = bytearray()
            for name, value, filename in parts:
                body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"".encode())
                if filename is not None:
                    body.extend(f"; filename=\"{filename}\"".encode())
                body.extend(b"\r\n\r\n" + value + b"\r\n")
            body.extend(f"--{boundary}--\r\n".encode())
            return bytes(body)

        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        duplicate = self.client.post(
            "/api/encrypt",
            content=encode(fields + [("recipient_key_id", self.recipient.key_id.encode(), None)]),
            headers=headers,
        )
        self.assertEqual(duplicate.status_code, 400)
        unexpected = self.client.post(
            "/api/encrypt",
            content=encode(fields + [("unexpected", b"value", None)]),
            headers=headers,
        )
        self.assertEqual(unexpected.status_code, 400)
        truncated = self.client.post(
            "/api/encrypt",
            content=encode(fields).replace(f"--{boundary}--\r\n".encode(), b"", 1),
            headers=headers,
        )
        self.assertEqual(truncated.status_code, 400)
        invalid_filename = self._encrypt("../outside.txt", b"x")
        self.assertEqual(invalid_filename.status_code, 400)

    def test_multipart_missing_and_transfer_encoded_fields_are_rejected(self) -> None:
        boundary = "QShieldFieldValidation"
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}

        missing = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="package.qshield"\r\n'
            "\r\ninvalid\r\n"
            f"--{boundary}--\r\n"
        ).encode("ascii")
        missing_response = self.client.post("/api/verify", content=missing, headers=headers)
        self.assertEqual(missing_response.status_code, 400)
        self.assertEqual(missing_response.json(), {"detail": "required multipart fields are missing"})

        transfer_encoded = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="sender_key_id"\r\n\r\n'
            f"{self.sender.key_id}\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="package.qshield"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\nYWJj\r\n"
            f"--{boundary}--\r\n"
        ).encode("ascii")
        encoded_response = self.client.post(
            "/api/verify", content=transfer_encoded, headers=headers
        )
        self.assertEqual(encoded_response.status_code, 400)
        self.assertEqual(encoded_response.json(), {"detail": "malformed multipart field"})

        malformed_response = self.client.post(
            "/api/verify", content=transfer_encoded, headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(malformed_response.status_code, 400)
        self.assertEqual(malformed_response.json(), {"detail": "malformed multipart request"})

    def test_mime_parameters_reject_duplicates_and_defects_at_header_validation(self) -> None:
        boundary = b"QShieldStrictMime"

        def verify_body(file_disposition: bytes) -> bytes:
            return b"".join(
                (
                    b"--" + boundary + b"\r\n",
                    b'Content-Disposition: form-data; name="sender_key_id"\r\n\r\n',
                    self.sender.key_id.encode("ascii"),
                    b"\r\n--" + boundary + b"\r\n",
                    file_disposition,
                    b"\r\n\r\nnot a package\r\n--" + boundary + b"--\r\n",
                )
            )

        headers = {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"}
        malformed_parts = (
            b'Content-Disposition: form-data; name="file"; name="sender_key_id"; filename="p.qshield"',
            b'Content-Disposition: form-data; name="file"; filename="p.qshield"; filename="other.qshield"',
            b'Content-Disposition: form-data; name="file"; filename="unterminated',
            b'Content-Disposition: form-data; name="file"; filename="p.qshield"; broken',
        )
        for disposition in malformed_parts:
            with self.subTest(disposition=disposition):
                response = self.client.post(
                    "/api/verify", content=verify_body(disposition), headers=headers
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json(), {"detail": "malformed multipart field"})

        body = verify_body(
            b'Content-Disposition: form-data; name="file"; filename="p.qshield"'
        )
        duplicate_boundary = self.client.post(
            "/api/verify",
            content=body,
            headers={
                "Content-Type": (
                    f"multipart/form-data; boundary={boundary.decode()}; "
                    f"boundary={boundary.decode()}"
                )
            },
        )
        self.assertEqual(duplicate_boundary.status_code, 400)
        self.assertEqual(
            duplicate_boundary.json(), {"detail": "malformed multipart request"}
        )
        for content_type in (
            "multipart/form-data",
            'multipart/form-data; boundary="unclosed',
        ):
            with self.subTest(content_type=content_type):
                invalid_boundary = self.client.post(
                    "/api/verify", content=body, headers={"Content-Type": content_type}
                )
                self.assertEqual(invalid_boundary.status_code, 400)
                self.assertEqual(
                    invalid_boundary.json(), {"detail": "malformed multipart request"}
                )

        missing_filename = self.client.post(
            "/api/verify",
            content=verify_body(
                b'Content-Disposition: form-data; name="file"'
            ),
            headers=headers,
        )
        self.assertEqual(missing_filename.status_code, 400)
        self.assertEqual(missing_filename.json(), {"detail": "file name is required"})

    def test_valid_rfc2231_filename_is_preserved(self) -> None:
        boundary = b"QShieldRFC2231"
        parts = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename*=UTF-8\'\'caf%C3%A9.txt\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            b"rfc2231 payload\r\n"
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="recipient_key_id"\r\n\r\n'
            + self.recipient.key_id.encode("ascii")
            + b"\r\n--" + boundary + b"\r\n"
            + b'Content-Disposition: form-data; name="signing_key_id"\r\n\r\n'
            + self.sender.key_id.encode("ascii")
            + b"\r\n--" + boundary + b"\r\n"
            + b'Content-Disposition: form-data; name="passphrase"\r\n\r\nsender API passphrase\r\n'
            + b"--" + boundary + b"--\r\n"
        )
        created = self.client.post(
            "/api/encrypt",
            content=parts,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(created.status_code, 200, created.text[:200])
        opened = self._decrypt(created.content)
        self.assertEqual(opened.status_code, 200, opened.text[:200])
        self.assertEqual(opened.content, b"rfc2231 payload")
        self.assertIn("filename*=UTF-8''caf%C3%A9.txt", opened.headers["content-disposition"])

    def test_closing_boundary_requires_line_ending_and_allows_epilogue(self) -> None:
        boundary = b"QShieldClosingPolicy"
        prefix = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="sender_key_id"\r\n\r\n'
            + self.sender.key_id.encode("ascii")
            + b"\r\n--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="p.qshield"\r\n\r\n'
            b"not a package\r\n--" + boundary + b"--"
        )
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"}

        for suffix in (b"\r\n", b"\r\nlegal MIME epilogue"):
            with self.subTest(suffix=suffix):
                response = self.client.post(
                    "/api/verify", content=prefix + suffix, headers=headers
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json(), {"detail": "package is invalid"})

        malformed = self.client.post(
            "/api/verify", content=prefix + b"X\r\n", headers=headers
        )
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(malformed.json(), {"detail": "malformed multipart request"})

        for truncated_body in (prefix[:-3], prefix[:-1]):
            with self.subTest(truncated_body=truncated_body[-8:]):
                truncated = self.client.post(
                    "/api/verify", content=truncated_body, headers=headers
                )
                self.assertEqual(truncated.status_code, 400)
                self.assertEqual(
                    truncated.json(), {"detail": "malformed multipart request"}
                )

    def test_chunked_file_exchange_limit_and_early_multipart_error_still_enforce_413(self) -> None:
        boundary = "QShieldChunkedLimit"
        prefix = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="sender_key_id"\r\n\r\n'
            f"{self.sender.key_id}\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="package.qshield"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("ascii")
        suffix = f"\r\n--{boundary}--\r\n".encode("ascii")

        def body_chunks(total_size: int):
            content_size = total_size - len(prefix) - len(suffix)
            self.assertGreaterEqual(content_size, 0)
            yield prefix
            block = b"x" * 4096
            remaining = content_size
            while remaining:
                size = min(remaining, len(block))
                yield block[:size]
                remaining -= size
            yield suffix

        # Keep the test small while exercising the verify route's package-body
        # limit calculation. The same middleware code handles its production cap.
        with patch.object(request_security, "MAX_PACKAGE_SIZE", 1024):
            body_limit = 1024 + request_security.FILE_EXCHANGE_MULTIPART_OVERHEAD_BYTES
            headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
            at_limit = self.client.post(
                "/api/verify", content=body_chunks(body_limit), headers=headers
            )
            self.assertEqual(at_limit.status_code, 400, at_limit.text[:200])
            self.assertEqual(at_limit.json(), {"detail": "package is invalid"})

            one_over = self.client.post(
                "/api/verify", content=body_chunks(body_limit + 1), headers=headers
            )
            self.assertEqual(one_over.status_code, 413, one_over.text[:200])

            # Even an invalid content type must drain through the middleware's
            # counter; an over-limit chunked body still takes the 413 path.
            malformed_over = self.client.post(
                "/api/verify",
                content=body_chunks(body_limit + 1),
                headers={"Content-Type": "application/octet-stream"},
            )
            self.assertEqual(malformed_over.status_code, 413, malformed_over.text[:200])

            transfer_prefix = prefix.replace(
                b"Content-Type: application/octet-stream\r\n",
                b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n",
            )

            def parser_error_then_over_limit():
                content_size = body_limit + 1 - len(transfer_prefix) - len(suffix)
                yield transfer_prefix
                block = b"x" * 4096
                while content_size:
                    size = min(content_size, len(block))
                    yield block[:size]
                    content_size -= size
                yield suffix

            parser_error_over = self.client.post(
                "/api/verify", content=parser_error_then_over_limit(), headers=headers
            )
            self.assertEqual(parser_error_over.status_code, 413, parser_error_over.text[:200])

    def test_oversized_file_and_package_requests_are_rejected(self) -> None:
        too_large_file = self._encrypt("large.bin", b"x" * (MAX_FILE_SIZE + 1))
        self.assertEqual(too_large_file.status_code, 413)
        too_large_package = self.client.post(
            "/api/verify",
            data={"sender_key_id": self.sender.key_id},
            files={"file": ("package.qshield", b"x" * (MAX_PACKAGE_SIZE + 1))},
        )
        self.assertEqual(too_large_package.status_code, 413)

    def test_uploads_and_decrypted_content_do_not_use_plaintext_temp_files(self) -> None:
        before = {path.relative_to(self.temp_directory.name) for path in Path(self.temp_directory.name).rglob("*") if path.is_file()}
        # Starlette's multipart form parser uses this spool; raw Request parsing
        # must not invoke it for upload or decrypted file content.
        with patch("starlette.formparsers.SpooledTemporaryFile", side_effect=AssertionError("spooling used")):
            created = self._encrypt("private.txt", b"plaintext sentinel").content
            opened = self._decrypt(created)
        self.assertEqual(opened.status_code, 200, opened.text[:200])
        after = {path.relative_to(self.temp_directory.name) for path in Path(self.temp_directory.name).rglob("*") if path.is_file()}
        self.assertEqual(after, before)

    def test_streaming_parser_handles_every_delimiter_split_and_boundary_like_content(self) -> None:
        boundary = b"QShieldSplitBoundary"
        filename = "café-日本.txt"
        file_data = b"prefix\r\n--QShieldSplitBoundaryX-is-content\x00suffix"
        pieces = [
            b"--" + boundary + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="' + filename.encode("utf-8") + b'"\r\n',
            b"Content-Type: application/octet-stream\r\n\r\n",
            file_data,
            b"\r\n--" + boundary + b"\r\n",
            b'Content-Disposition: form-data; name="recipient_key_id"\r\n\r\n',
            self.recipient.key_id.encode("ascii"),
            b"\r\n--" + boundary + b"\r\n",
            b'Content-Disposition: form-data; name="signing_key_id"\r\n\r\n',
            self.sender.key_id.encode("ascii"),
            b"\r\n--" + boundary + b"\r\n",
            b'Content-Disposition: form-data; name="passphrase"\r\n\r\n',
            b"sender API passphrase",
            b"\r\n--" + boundary + b"--\r\n",
        ]
        body = b"".join(pieces)

        # One-byte chunks split every opening/inter-part/closing delimiter and
        # each CRLF pair across reads, while also testing false boundary text.
        response = self.client.post(
            "/api/encrypt",
            content=(body[index : index + 1] for index in range(len(body))),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary.decode('ascii')}"},
        )
        self.assertEqual(response.status_code, 200, response.text[:200])
        opened = self._decrypt(response.content)
        self.assertEqual(opened.status_code, 200, opened.text[:200])
        self.assertEqual(opened.content, file_data)
        self.assertIn(
            "caf%C3%A9-%E6%97%A5%E6%9C%AC.txt",
            opened.headers["content-disposition"],
        )

    def test_streaming_parser_enforces_exact_file_package_and_text_field_limits(self) -> None:
        with patch("backend.app.api.routes.file_exchange.MAX_FILE_SIZE", 128):
            with patch.object(FileExchangeService, "create_package", return_value=b"test package"):
                exact_file = self._encrypt("exact.bin", b"f" * 128)
                over_file = self._encrypt("over.bin", b"f" * 129)
        self.assertEqual(exact_file.status_code, 200, exact_file.text[:200])
        self.assertEqual(over_file.status_code, 413, over_file.text[:200])

        verified_result = SimpleNamespace(
            sender_key_id=self.sender.key_id,
            package=SimpleNamespace(
                header=SimpleNamespace(
                    recipient_key_id=bytes.fromhex(self.recipient.key_id), created_at=1
                )
            ),
        )
        with patch("backend.app.api.routes.file_exchange.MAX_PACKAGE_SIZE", 128):
            with patch.object(FileExchangeService, "verify_package", return_value=verified_result):
                exact_package = self.client.post(
                    "/api/verify",
                    data={"sender_key_id": self.sender.key_id},
                    files={"file": ("package.qshield", b"p" * 128)},
                )
                over_package = self.client.post(
                    "/api/verify",
                    data={"sender_key_id": self.sender.key_id},
                    files={"file": ("package.qshield", b"p" * 129)},
                )
        self.assertEqual(exact_package.status_code, 200, exact_package.text[:200])
        self.assertEqual(over_package.status_code, 413, over_package.text[:200])

        with patch("backend.app.api.routes.file_exchange._MAX_PASSPHRASE_BYTES", 8):
            with patch.object(FileExchangeService, "create_package", return_value=b"test package"):
                exact_text = self._encrypt("text.bin", b"", passphrase="p" * 8)
                over_text = self._encrypt("text.bin", b"", passphrase="p" * 9)
        self.assertEqual(exact_text.status_code, 200, exact_text.text[:200])
        self.assertEqual(over_text.status_code, 400, over_text.text[:200])

    def test_streaming_parser_rejects_nested_parts_and_bounded_header_violations(self) -> None:
        boundary = "QShieldHeaderBounds"
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        prefix = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="sender_key_id"\r\n'
        )
        value = f"\r\n{self.sender.key_id}\r\n--{boundary}--\r\n"
        too_many_headers = prefix + "".join(f"X-Header-{index}: x\r\n" for index in range(8)) + value
        response = self.client.post("/api/verify", content=too_many_headers, headers=headers)
        self.assertEqual(response.status_code, 400)

        too_large_header = prefix + "X-Large: " + ("x" * 9000) + value
        response = self.client.post("/api/verify", content=too_large_header, headers=headers)
        self.assertEqual(response.status_code, 400)

        aggregate_headers = prefix + "".join(
            f"X-Padding-{index}: " + ("x" * 2300) + "\r\n" for index in range(7)
        ) + value
        response = self.client.post("/api/verify", content=aggregate_headers, headers=headers)
        self.assertEqual(response.status_code, 400)

        nested = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="sender_key_id"\r\n'
            "Content-Type: multipart/mixed; boundary=inner\r\n\r\n"
            f"--inner--\r\n\r\n{self.sender.key_id}\r\n"
            f"--{boundary}--\r\n"
        ).encode("ascii")
        response = self.client.post("/api/verify", content=nested, headers=headers)
        self.assertEqual(response.status_code, 400)

