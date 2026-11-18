
import hashlib
import tempfile
import unittest
from pathlib import Path

from backend.hashing import calculate_file_hashes


class TestFileHashing(unittest.TestCase):

    def test_hash_calculation(self):

        content = b"Hello CFIV!"

        with tempfile.TemporaryDirectory() as temp_dir:

            file_path = Path(temp_dir) / "sample.txt"

            file_path.write_bytes(content)

            result = calculate_file_hashes(file_path)

        expected_sha256 = hashlib.sha256(content).hexdigest()
        expected_sha3 = hashlib.sha3_256(content).hexdigest()

        self.assertEqual(result["sha256"], expected_sha256)
        self.assertEqual(result["sha3_256"], expected_sha3)

    def test_empty_file(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            file_path = Path(temp_dir) / "empty.txt"

            file_path.write_bytes(b"")

            result = calculate_file_hashes(file_path)

        self.assertEqual(
            result["sha256"],
            hashlib.sha256(b"").hexdigest()
        )

        self.assertEqual(
            result["sha3_256"],
            hashlib.sha3_256(b"").hexdigest()
        )


if __name__ == "__main__":
    unittest.main()
