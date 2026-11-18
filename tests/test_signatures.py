
import hashlib
import tempfile
import unittest
from pathlib import Path

from backend.signatures import (
    combined_sha256_sha3_digest,
    generate_key_pair,
    sign_hash,
    verify_signature
)


class TestDigitalSignatures(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.key_directory = Path(self.temp_dir.name)

        self.password = b"test_password_123"

        self.private_key, self.public_key = generate_key_pair(
            self.key_directory,
            self.password
        )

        self.original_content = b"Hello CFIV!"
        self.original_hash = hashlib.sha256(
            self.original_content
        ).hexdigest()

        self.signature = sign_hash(
            self.original_hash,
            self.private_key,
            self.password
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_valid_signature(self):

        result = verify_signature(
            self.original_hash,
            self.signature,
            self.public_key
        )

        self.assertTrue(result)

    def test_modified_hash(self):

        modified_content = b"Hello CFIV! Modified"

        modified_hash = hashlib.sha256(
            modified_content
        ).hexdigest()

        result = verify_signature(
            modified_hash,
            self.signature,
            self.public_key
        )

        self.assertFalse(result)

    def test_wrong_public_key(self):

        with tempfile.TemporaryDirectory() as other_dir:

            _, other_public_key = generate_key_pair(
                other_dir,
                self.password
            )

            result = verify_signature(
                self.original_hash,
                self.signature,
                other_public_key
            )

            self.assertFalse(result)

    def test_invalid_digest_length(self):

        with self.assertRaises(ValueError):
            sign_hash(
                "abcd",
                self.private_key,
                self.password
            )

    def test_combined_v2_signature_verifies_and_detects_either_hash_change(self):
        sha256_hex = hashlib.sha256(self.original_content).hexdigest()
        sha3_256_hex = hashlib.sha3_256(self.original_content).hexdigest()
        combined_digest = combined_sha256_sha3_digest(sha256_hex, sha3_256_hex)
        signature = sign_hash(combined_digest, self.private_key, self.password)

        self.assertTrue(verify_signature(combined_digest, signature, self.public_key))

        changed_sha256_digest = combined_sha256_sha3_digest("0" * 64, sha3_256_hex)
        changed_sha3_digest = combined_sha256_sha3_digest(sha256_hex, "0" * 64)
        self.assertFalse(
            verify_signature(changed_sha256_digest, signature, self.public_key)
        )
        self.assertFalse(
            verify_signature(changed_sha3_digest, signature, self.public_key)
        )

    def test_combined_digest_rejects_invalid_inputs(self):
        with self.assertRaises(ValueError):
            combined_sha256_sha3_digest("not-a-digest", "0" * 64)
        with self.assertRaises(ValueError):
            combined_sha256_sha3_digest("0" * 62, "0" * 64)


if __name__ == "__main__":
    unittest.main()
