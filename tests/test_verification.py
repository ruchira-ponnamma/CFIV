
import hashlib
import tempfile
import unittest
from pathlib import Path

from backend.hashing import calculate_file_hashes
from backend.signatures import generate_key_pair, sign_hash
from backend.verification import verify_file_integrity


class TestFileVerification(unittest.TestCase):

    def setUp(self):

        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

        self.key_directory = self.base_path / "keys"

        self.password = b"test_password_123"

        self.private_key, self.public_key = generate_key_pair(
            self.key_directory,
            self.password
        )

        self.file_path = self.base_path / "sample.txt"

        self.original_content = b"Original CFIV document"

        self.file_path.write_bytes(self.original_content)

        # Store original hashes
        self.original_hashes = calculate_file_hashes(
            self.file_path
        )

        # Generate the original digital signature
        self.signature = sign_hash(
            self.original_hashes["sha256"],
            self.private_key,
            self.password
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_original_file_verification(self):

        result = verify_file_integrity(
            self.file_path,
            self.original_hashes,
            self.signature,
            self.public_key
        )

        self.assertTrue(result["sha256_match"])
        self.assertTrue(result["sha3_256_match"])
        self.assertTrue(result["signature_valid"])
        self.assertTrue(result["integrity_verified"])

    def test_modified_file_detection(self):

        # Modify the original file
        self.file_path.write_bytes(
            b"Modified CFIV document"
        )

        result = verify_file_integrity(
            self.file_path,
            self.original_hashes,
            self.signature,
            self.public_key
        )

        self.assertFalse(result["sha256_match"])
        self.assertFalse(result["sha3_256_match"])
        self.assertFalse(result["signature_valid"])
        self.assertFalse(result["integrity_verified"])


if __name__ == "__main__":
    unittest.main()
