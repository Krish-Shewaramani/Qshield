import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.api.dependencies import get_key_service, get_trust_store
from backend.app.crypto import key_serialization, signature_service
from backend.app.key_management.key_service import KeyService
from backend.app.key_management.key_storage import KeyStore
from backend.app.key_management.trust_store import TrustStore
from backend.app.main import app


class KeyManagementAPITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        root = Path(self.temp_directory.name)
        key_service = KeyService(KeyStore(root / "keys"))
        trust_store = TrustStore(root / "trust")
        app.dependency_overrides[get_key_service] = lambda: key_service
        app.dependency_overrides[get_trust_store] = lambda: trust_store
        self.addCleanup(app.dependency_overrides.clear)
        self.client = TestClient(app, base_url="http://127.0.0.1:8000")
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def test_key_generation_listing_and_spki_export(self) -> None:
        response = self.client.post(
            "/api/keys/kem",
            json={"label": "Recipient", "passphrase": "key API test passphrase"},
        )
        self.assertEqual(response.status_code, 201)
        record = response.json()
        self.assertEqual(record["algorithm"], "ML-KEM-768")
        self.assertTrue(record["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----"))
        listed = self.client.get("/api/keys")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()[0]["key_id"], record["key_id"])
        exported = self.client.get(f"/api/keys/{record['key_id']}/public")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.content, record["public_key_pem"].encode("ascii"))

    def test_public_key_must_be_previewed_and_explicitly_confirmed_to_trust(self) -> None:
        _, public_key = signature_service.generate_keypair()
        pem = key_serialization.export_public_key(public_key).decode("ascii")
        preview = self.client.post("/api/trusted-keys/preview", json={"public_key_pem": pem})
        self.assertEqual(preview.status_code, 200)
        candidate = preview.json()
        self.assertEqual(candidate["algorithm"], "ML-DSA-65")
        self.assertEqual(self.client.get("/api/trusted-keys").json(), [])

        missing_confirmation = self.client.post(
            "/api/trusted-keys", json={"public_key_pem": pem, "label": "Sender"}
        )
        self.assertEqual(missing_confirmation.status_code, 422)
        wrong_confirmation = self.client.post(
            "/api/trusted-keys",
            json={
                "public_key_pem": pem,
                "label": "Sender",
                "confirmed_fingerprint": "0" * 64,
            },
        )
        self.assertEqual(wrong_confirmation.status_code, 400)
        self.assertEqual(self.client.get("/api/trusted-keys").json(), [])

        trusted = self.client.post(
            "/api/trusted-keys",
            json={
                "public_key_pem": pem,
                "label": "Sender",
                "confirmed_fingerprint": candidate["key_id"],
            },
        )
        self.assertEqual(trusted.status_code, 201)
        self.assertTrue(trusted.json()["trusted"])
        self.assertEqual(len(self.client.get("/api/trusted-keys").json()), 1)
