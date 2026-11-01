import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.validate import ValidationError, validate_evidence_pointer


class EvidencePointerTests(unittest.TestCase):
    def valid_pointer(self) -> dict:
        return {
            'hash_algorithm': 'sha256',
            'digest': 'a' * 64,
            'issuer': 'did:example:issuer',
            'signature_ref': 'urn:example:signature:1',
        }

    def test_valid_pointer(self) -> None:
        validate_evidence_pointer(self.valid_pointer())

    def test_prefixed_digest(self) -> None:
        pointer = self.valid_pointer()
        pointer['digest'] = 'sha256:' + 'b' * 64
        validate_evidence_pointer(pointer)

    def test_unknown_algorithm(self) -> None:
        pointer = self.valid_pointer()
        pointer['hash_algorithm'] = 'md5'
        with self.assertRaises(ValidationError):
            validate_evidence_pointer(pointer)

    def test_malformed_digest(self) -> None:
        pointer = self.valid_pointer()
        pointer['digest'] = 'not-hex'
        with self.assertRaises(ValidationError):
            validate_evidence_pointer(pointer)

    def test_incomplete_pointer(self) -> None:
        pointer = self.valid_pointer()
        del pointer['issuer']
        with self.assertRaises(ValidationError):
            validate_evidence_pointer(pointer)

    def test_embedded_content_rejected(self) -> None:
        pointer = self.valid_pointer()
        pointer['content'] = 'secret record'
        with self.assertRaises(ValidationError):
            validate_evidence_pointer(pointer)

    def test_demo_runs(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / 'examples' / 'verifiable-evidence' / 'verify.py')],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('OK: synthetic evidence pointer verified', result.stdout)


if __name__ == '__main__':
    unittest.main()
