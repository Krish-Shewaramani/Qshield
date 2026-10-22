import unittest

from backend.app.crypto import kem_service


class KEMTests(unittest.TestCase):
    def test_ml_kem_768_encapsulate_decapsulate_round_trip(self) -> None:
        private, public = kem_service.generate_keypair()
        ciphertext, sender_secret = kem_service.encapsulate(public)
        recipient_secret = kem_service.decapsulate(private, ciphertext)
        self.assertEqual(len(ciphertext), 1088)
        self.assertEqual(sender_secret, recipient_secret)

    def test_ml_kem_768_rejects_malformed_ciphertext(self) -> None:
        private, _ = kem_service.generate_keypair()
        with self.assertRaises((ValueError, TypeError)):
            kem_service.decapsulate(private, b"short")
