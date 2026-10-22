import unittest
from cryptography.exceptions import InvalidSignature

from backend.app.crypto import signature_service


class SignatureTests(unittest.TestCase):
    def test_ml_dsa_65_signature_round_trip(self) -> None:
        private, public = signature_service.generate_keypair()
        message = b"QuantumShield signature test"
        signature = signature_service.sign(private, message)
        self.assertEqual(len(signature), 3309)
        self.assertIsNone(signature_service.verify(public, signature, message))

    def test_ml_dsa_65_rejects_modified_message_and_signature(self) -> None:
        private, public = signature_service.generate_keypair()
        message = b"original message"
        signature = signature_service.sign(private, message)
        with self.assertRaises(InvalidSignature):
            signature_service.verify(public, signature, message + b" altered")
        with self.assertRaises(InvalidSignature):
            signature_service.verify(public, signature[:-1] + bytes([signature[-1] ^ 1]), message)
