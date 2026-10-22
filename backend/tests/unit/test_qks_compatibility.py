import importlib.util
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa

from backend.app.key_management.fingerprints import key_id
from backend.app.key_management.qks_envelope import open_pkcs8, seal_pkcs8

EXPERIMENT_PATH = Path(__file__).resolve().parents[3] / "experiments" / "phase2a_serialization" / "serialization_poc.py"
SPEC = importlib.util.spec_from_file_location("phase2a_serialization_poc", EXPERIMENT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Phase 2A serialization experiment")
EXPERIMENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EXPERIMENT
SPEC.loader.exec_module(EXPERIMENT)


class QKSEnvelopeCompatibilityTests(unittest.TestCase):
    def test_production_and_experiment_envelopes_are_interoperable(self) -> None:
        passphrase = "QSKS compatibility test"
        for private_key in (
            mlkem.MLKEM768PrivateKey.generate(),
            mldsa.MLDSA65PrivateKey.generate(),
        ):
            with self.subTest(key_type=type(private_key).__name__):
                experiment_envelope = EXPERIMENT.seal_pkcs8(private_key, passphrase, log_n=12)
                self.assertEqual(
                    key_id(open_pkcs8(experiment_envelope, passphrase).public_key()),
                    key_id(private_key.public_key()),
                )
                production_envelope = seal_pkcs8(private_key, passphrase, log_n=12)
                self.assertEqual(
                    key_id(EXPERIMENT.open_pkcs8(production_envelope, passphrase).public_key()),
                    key_id(private_key.public_key()),
                )

    def test_v1_header_retains_the_experiment_layout_and_bounds(self) -> None:
        private_key = mlkem.MLKEM768PrivateKey.generate()
        envelope = seal_pkcs8(private_key, "format test", log_n=12)
        self.assertEqual(len(envelope[:42]), 42)
        self.assertEqual(envelope[:5], b"QSKS\x01")
        self.assertEqual(envelope[5], 12)
        self.assertEqual(int.from_bytes(envelope[6:10], "big"), 8)
        self.assertEqual(int.from_bytes(envelope[10:14], "big"), 1)
