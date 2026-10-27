"""End-to-end `.qshield` exchange between two independent installations.

Each installation has its own key store, trust store, and contact store in a
separate directory. Only public contact bundles and the `.qshield` package move
between them, as they would between two laptops.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.api.dependencies import get_key_service, get_trust_store
from backend.app.file_exchange.protocol import parse_package
from backend.app.key_management.key_service import KeyService
from backend.app.key_management.key_storage import KeyStore
from backend.app.key_management.trust_store import TrustStore
from backend.app.key_management.unlock_rate_limiter import UnlockRateLimiter
from backend.app.main import app


class Installation:
    """One independent QuantumShield install with its own local data directory."""

    def __init__(self, root: Path):
        self.root = root
        self.keys = KeyService(KeyStore(root / "keys", unlock_limiter=UnlockRateLimiter(global_capacity=100)))
        self.trust = TrustStore(root / "trust")

    @contextmanager
    def client(self):
        # File exchange and contacts derive from these two dependencies, so
        # overriding them switches every route to this installation's data.
        app.dependency_overrides[get_key_service] = lambda: self.keys
        app.dependency_overrides[get_trust_store] = lambda: self.trust
        try:
            with TestClient(app, base_url="http://127.0.0.1:8000") as client:
                yield client
        finally:
            app.dependency_overrides.clear()


def _grouped(fingerprint: str) -> str:
    """How a user would type a fingerprint read aloud in groups of four."""
    return " ".join(fingerprint[i:i + 4] for i in range(0, len(fingerprint), 4))


class TwoInstallationExchangeTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.addCleanup(app.dependency_overrides.clear)
        root = Path(directory.name)
        self.alice = Installation(root / "alice-laptop")
        self.bob = Installation(root / "bob-laptop")

    def _generate(self, install: Installation, route: str, label: str, passphrase: str) -> dict:
        with install.client() as client:
            response = client.post(f"/api/keys/{route}", json={"label": label, "passphrase": passphrase})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def _export_bundle(self, install: Installation, label: str, key_ids: list[str]) -> str:
        with install.client() as client:
            response = client.post("/api/contact-bundles/export", json={"label": label, "key_ids": key_ids})
        self.assertEqual(response.status_code, 200, response.text)
        # Transported as a file written on Windows: CRLF line endings.
        return json.dumps(response.json(), indent=2).replace("\n", "\r\n")

    def _pair(self, install: Installation, bundle_text: str, local_label: str) -> dict:
        """Import a bundle as a new contact, verify every full fingerprint, then confirm."""
        with install.client() as client:
            analysis = client.post(
                "/api/contacts/pairing/analyze", json={"bundle_json": bundle_text, "contact_id": None}
            )
            self.assertEqual(analysis.status_code, 200, analysis.text)
            self.assertTrue(analysis.json()["can_stage"])
            self.assertEqual({k["status"] for k in analysis.json()["keys"]}, {"new_key"})

            staged = client.post(
                "/api/contacts/pairing/stage",
                json={"bundle_json": bundle_text, "contact_id": None, "label": local_label},
            )
            self.assertEqual(staged.status_code, 200, staged.text)
            contact = staged.json()["contact"]
            self.assertFalse(contact["confirmed"])
            self.assertTrue(all(k["state"] == "pending" and not k["in_trusted_keys"] for k in contact["keys"]))

            for key in contact["keys"]:
                verified = client.post(
                    f"/api/contacts/{contact['contact_id']}/keys/{key['fingerprint']}/verify",
                    json={"confirmed_fingerprint": _grouped(key["fingerprint"])},
                )
                self.assertEqual(verified.status_code, 200, verified.text)

            confirmed = client.post(f"/api/contacts/{contact['contact_id']}/confirm")
            self.assertEqual(confirmed.status_code, 200, confirmed.text)
            self.assertEqual(confirmed.json()["activation_pending"], [])
            return confirmed.json()["contact"]

    def test_paired_contacts_exchange_a_package_between_independent_installations(self) -> None:
        bob_kem = self._generate(self.bob, "kem", "bob encryption", "bob passphrase")
        bob_sig = self._generate(self.bob, "sig", "bob signing", "bob signing passphrase")
        alice_sig = self._generate(self.alice, "sig", "alice signing", "alice passphrase")
        alice_kem = self._generate(self.alice, "kem", "alice encryption", "alice kem passphrase")

        bob_bundle = self._export_bundle(self.bob, "Bob", [bob_kem["key_id"], bob_sig["key_id"]])
        alice_bundle = self._export_bundle(self.alice, "Alice", [alice_sig["key_id"], alice_kem["key_id"]])
        for bundle in (bob_bundle, alice_bundle):
            self.assertNotIn("PRIVATE KEY", bundle)
            self.assertNotIn("passphrase", bundle)
            self.assertNotIn("QSKS", bundle)

        # Before pairing, Alice cannot encrypt to Bob: his key is not trusted on her install.
        with self.alice.client() as client:
            early = client.post(
                "/api/encrypt",
                data={"recipient_key_id": bob_kem["key_id"], "signing_key_id": alice_sig["key_id"], "passphrase": "alice passphrase"},
                files={"file": ("report.txt", b"too early", "text/plain")},
            )
        self.assertEqual(early.status_code, 404, early.text)

        bob_on_alice = self._pair(self.alice, bob_bundle, "Bob (verified by phone)")
        alice_on_bob = self._pair(self.bob, alice_bundle, "Alice (verified in person)")

        # Fingerprints computed independently on each install are identical.
        self.assertEqual(
            {k["fingerprint"] for k in bob_on_alice["keys"]}, {bob_kem["key_id"], bob_sig["key_id"]}
        )
        self.assertEqual(
            {k["fingerprint"] for k in alice_on_bob["keys"]}, {alice_sig["key_id"], alice_kem["key_id"]}
        )
        with self.alice.client() as client:
            trusted = {r["key_id"]: r for r in client.get("/api/trusted-keys").json()}
        self.assertEqual(trusted[bob_kem["key_id"]]["usage"], "full")
        self.assertEqual(trusted[bob_kem["key_id"]]["contact_label"], "Bob (verified by phone)")

        content = "quarterly résumé\n".encode("utf-8") * 50
        with self.alice.client() as client:
            created = client.post(
                "/api/encrypt",
                data={"recipient_key_id": bob_kem["key_id"], "signing_key_id": alice_sig["key_id"], "passphrase": "alice passphrase"},
                files={"file": ("résumé.txt", content, "text/plain")},
            )
        self.assertEqual(created.status_code, 200, created.text[:200])
        package = created.content
        header = parse_package(package).header
        self.assertEqual(header.sender_key_id.hex(), alice_sig["key_id"])
        self.assertEqual(header.recipient_key_id.hex(), bob_kem["key_id"])

        with self.bob.client() as client:
            verified = client.post(
                "/api/verify",
                data={"sender_key_id": alice_sig["key_id"]},
                files={"file": ("package.qshield", package, "application/octet-stream")},
            )
            self.assertEqual(verified.status_code, 200, verified.text)
            self.assertTrue(verified.json()["verified"])
            self.assertEqual(verified.json()["recipient_key_id"], bob_kem["key_id"])

            opened = client.post(
                "/api/decrypt",
                data={"recipient_key_id": bob_kem["key_id"], "sender_key_id": alice_sig["key_id"], "passphrase": "bob passphrase"},
                files={"file": ("package.qshield", package, "application/octet-stream")},
            )
        self.assertEqual(opened.status_code, 200, opened.text[:200])
        self.assertEqual(opened.content, content)
        self.assertIn("filename*=UTF-8''r%C3%A9sum%C3%A9.txt", opened.headers["content-disposition"])

        # Private keys never leave their installation.
        self.assertEqual(
            {p.stem for p in (self.alice.root / "keys").glob("*.qks")}, {alice_sig["key_id"], alice_kem["key_id"]}
        )
        self.assertEqual(
            {p.stem for p in (self.bob.root / "keys").glob("*.qks")}, {bob_kem["key_id"], bob_sig["key_id"]}
        )
        self.assertEqual(list((self.alice.root / "trust").glob("*.qks")), [])
        self.assertEqual(list((self.bob.root / "trust").glob("*.qks")), [])

    def test_receiver_rejects_wrong_sender_and_sender_cannot_decrypt(self) -> None:
        bob_kem = self._generate(self.bob, "kem", "bob encryption", "bob passphrase")
        bob_sig = self._generate(self.bob, "sig", "bob signing", "bob signing passphrase")
        alice_sig = self._generate(self.alice, "sig", "alice signing", "alice passphrase")
        alice_kem = self._generate(self.alice, "kem", "alice encryption", "alice kem passphrase")
        self._pair(self.alice, self._export_bundle(self.bob, "Bob", [bob_kem["key_id"], bob_sig["key_id"]]), "Bob")
        self._pair(self.bob, self._export_bundle(self.alice, "Alice", [alice_sig["key_id"], alice_kem["key_id"]]), "Alice")

        with self.alice.client() as client:
            package = client.post(
                "/api/encrypt",
                data={"recipient_key_id": bob_kem["key_id"], "signing_key_id": alice_sig["key_id"], "passphrase": "alice passphrase"},
                files={"file": ("note.txt", b"for bob only", "text/plain")},
            ).content

            # Let the sender installation verify its own signature, so the decrypt
            # attempt below gets past verification and the recipient-ID check.
            preview = client.post(
                "/api/trusted-keys/preview", json={"public_key_pem": alice_sig["public_key_pem"]}
            ).json()
            self_trust = client.post(
                "/api/trusted-keys",
                json={"public_key_pem": preview["public_key_pem"], "label": "Alice (self)", "confirmed_fingerprint": preview["key_id"]},
            )
            self.assertEqual(self_trust.status_code, 201, self_trust.text)
            own_verify = client.post(
                "/api/verify",
                data={"sender_key_id": alice_sig["key_id"]},
                files={"file": ("package.qshield", package, "application/octet-stream")},
            )
            self.assertEqual(own_verify.status_code, 200, own_verify.text)
            self.assertEqual(own_verify.json()["recipient_key_id"], bob_kem["key_id"])

            # Real sender ID and the package's real recipient ID, which exists only on Bob's installation.
            own = client.post(
                "/api/decrypt",
                data={"recipient_key_id": bob_kem["key_id"], "sender_key_id": alice_sig["key_id"], "passphrase": "bob passphrase"},
                files={"file": ("package.qshield", package, "application/octet-stream")},
            )
        self.assertEqual(own.status_code, 400, own.text)
        self.assertEqual(own.json(), {"detail": "selected private key is unavailable"})
        self.assertFalse((self.alice.root / "keys" / f"{bob_kem['key_id']}.qks").exists())

        with self.bob.client() as client:
            # A trusted key that did not sign this package (here an encryption key) fails verification.
            wrong_sender = client.post(
                "/api/verify",
                data={"sender_key_id": alice_kem["key_id"]},
                files={"file": ("package.qshield", package, "application/octet-stream")},
            )
            self.assertEqual(wrong_sender.status_code, 403, wrong_sender.text)
            # Decrypting with a local key the package is not addressed to is refused.
            wrong_recipient = client.post(
                "/api/decrypt",
                data={"recipient_key_id": bob_sig["key_id"], "sender_key_id": alice_sig["key_id"], "passphrase": "bob signing passphrase"},
                files={"file": ("package.qshield", package, "application/octet-stream")},
            )
            self.assertEqual(wrong_recipient.status_code, 400, wrong_recipient.text)

    def test_standalone_pem_trust_interoperates_across_installations(self) -> None:
        bob_kem = self._generate(self.bob, "kem", "bob encryption", "bob passphrase")
        alice_sig = self._generate(self.alice, "sig", "alice signing", "alice passphrase")

        def trust_pem(install: Installation, pem: str, label: str) -> str:
            with install.client() as client:
                preview = client.post(
                    "/api/trusted-keys/preview", json={"public_key_pem": pem.replace("\n", "\r\n")}
                ).json()
                added = client.post(
                    "/api/trusted-keys",
                    json={"public_key_pem": preview["public_key_pem"], "label": label, "confirmed_fingerprint": preview["key_id"]},
                )
            self.assertEqual(added.status_code, 201, added.text)
            return preview["key_id"]

        self.assertEqual(trust_pem(self.alice, bob_kem["public_key_pem"], "Bob"), bob_kem["key_id"])
        self.assertEqual(trust_pem(self.bob, alice_sig["public_key_pem"], "Alice"), alice_sig["key_id"])

        with self.alice.client() as client:
            package = client.post(
                "/api/encrypt",
                data={"recipient_key_id": bob_kem["key_id"], "signing_key_id": alice_sig["key_id"], "passphrase": "alice passphrase"},
                files={"file": ("plain.bin", b"\x00\x01binary", "application/octet-stream")},
            )
        self.assertEqual(package.status_code, 200, package.text[:200])
        with self.bob.client() as client:
            opened = client.post(
                "/api/decrypt",
                data={"recipient_key_id": bob_kem["key_id"], "sender_key_id": alice_sig["key_id"], "passphrase": "bob passphrase"},
                files={"file": ("package.qshield", package.content, "application/octet-stream")},
            )
        self.assertEqual(opened.status_code, 200, opened.text[:200])
        self.assertEqual(opened.content, b"\x00\x01binary")


if __name__ == "__main__":
    unittest.main()
