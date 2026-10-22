import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.crypto.crypto_errors import CryptoConfigurationError
from backend.app.crypto import kem_service


class APITests(unittest.TestCase):
    def test_health_endpoint_runs_crypto_self_check(self) -> None:
        with TestClient(app, base_url="http://127.0.0.1:8000") as client:
            response = client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "status": "ok",
            "cryptography": "ready",
            "algorithms": ["ML-KEM-768", "ML-DSA-65", "HKDF-SHA-256", "AES-256-GCM"],
        })

    def test_startup_fails_closed_when_crypto_self_check_fails(self) -> None:
        with patch.object(kem_service, "generate_keypair", side_effect=RuntimeError("provider unavailable")):
            with self.assertRaises(CryptoConfigurationError):
                with TestClient(app, base_url="http://127.0.0.1:8000"):
                    pass
