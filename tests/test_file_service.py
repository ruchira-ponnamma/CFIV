"""Tests for CFIV file registration using temporary files and a database."""

import base64
import hashlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from werkzeug.datastructures import FileStorage

from backend import database
from backend.cloud_storage import CloudStorageConfigurationError, CloudStorageError
from backend.file_service import register_uploaded_file
from backend.key_registry import register_public_key
from backend.signatures import generate_key_pair
from config import Config


class OversizedStream:
    """Generate upload bytes in small pieces without holding them all in memory."""

    def __init__(self, total_size):
        self.remaining = total_size

    def read(self, size=-1):
        if self.remaining <= 0:
            return b""
        chunk_size = min(size, self.remaining) if size >= 0 else self.remaining
        self.remaining -= chunk_size
        return b"x" * chunk_size


class FileServiceTests(unittest.TestCase):
    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)

        database_patch = patch.object(database, "DATABASE_PATH", self.root / "test.db")
        database_patch.start()
        self.addCleanup(database_patch.stop)

        database.init_db()
        self.upload_folder = self.root / "uploads"
        self.key_folder = self.root / "keys"
        self.password = b"test-only-password"
        self.private_key_path, self.public_key_path = generate_key_pair(
            self.key_folder,
            self.password,
        )
        self.key_id = register_public_key(self.public_key_path)
        cloud_upload_patch = patch(
            "backend.file_service.upload_file_and_signature",
            side_effect=self.mock_cloud_upload,
        )
        self.cloud_upload_mock = cloud_upload_patch.start()
        self.addCleanup(cloud_upload_patch.stop)
        cloud_delete_patch = patch("backend.file_service.delete_resource")
        self.cloud_delete_mock = cloud_delete_patch.start()
        self.addCleanup(cloud_delete_patch.stop)
        self.uploaded_artifacts = []
        self.uploaded_ids = []
        self.uploaded_staged_files = []

    def mock_cloud_upload(self, source_path, signature_artifact, *, correlation_id=None):
        """Capture the staged artifact and return generated-looking IDs."""
        self.uploaded_artifacts.append(signature_artifact)
        source_path = Path(source_path)
        self.uploaded_staged_files.append(
            (source_path.name, source_path.read_bytes())
        )
        identifier = uuid4().hex
        public_ids = (
            f"cfiv/files/{identifier}{source_path.suffix}",
            f"cfiv/signatures/{uuid4().hex}.txt",
        )
        self.uploaded_ids.append(public_ids)
        return public_ids

    def register(self, uploaded_file, *, password=None, key_id=None, private_key_path=None):
        """Register an upload using this test's temporary resources."""
        return register_uploaded_file(
            uploaded_file,
            private_key_path=private_key_path or self.private_key_path,
            private_key_password=self.password if password is None else password,
            key_id=self.key_id if key_id is None else key_id,
            upload_folder=self.upload_folder,
        )

    def get_file_records(self):
        """Return all test database file records and close the connection."""
        connection = database.get_db_connection()
        try:
            return connection.execute(
                "SELECT * FROM file_records ORDER BY file_id"
            ).fetchall()
        finally:
            connection.close()

    def test_successful_registration_saves_metadata_and_signature(self):
        content = b"CFIV test document\n"
        upload = FileStorage(
            stream=io.BytesIO(content),
            filename="sample.txt",
        )

        result = self.register(upload)

        self.assertEqual(result["original_name"], "sample.txt")
        self.assertEqual(result["size_bytes"], len(content))
        self.assertEqual(result["key_id"], self.key_id)
        self.assertTrue(result["file_id"])
        self.assertTrue(result["created_at"].endswith("Z"))

        records = self.get_file_records()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["file_id"], result["file_id"])
        self.assertEqual(record["original_name"], "sample.txt")
        self.assertEqual(record["size_bytes"], len(content))
        self.assertEqual(record["sha256"], result["sha256"])
        self.assertEqual(record["sha3_256"], result["sha3_256"])
        self.assertEqual(record["signature_scheme"], "combined-sha256-sha3-v2")
        self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(result["sha3_256"], hashlib.sha3_256(content).hexdigest())
        staged_name, staged_bytes = self.uploaded_staged_files[-1]
        self.assertRegex(staged_name, r"^[0-9a-f]{32}\.txt$")
        self.assertEqual(staged_bytes, content)
        self.assertIsInstance(record["signature"], bytes)
        self.assertGreater(len(record["signature"]), 0)
        self.assertEqual(record["storage_backend"], "cloudinary")
        self.assertIsNone(record["stored_name"])
        self.assertEqual(
            (
                record["cloudinary_file_public_id"],
                record["cloudinary_signature_public_id"],
            ),
            self.uploaded_ids[-1],
        )
        self.assertEqual(
            self.uploaded_artifacts,
            [
                b"CFIV-SIGNATURE-V1\n"
                b"scheme=combined-sha256-sha3-v2\n"
                + b"signature="
                + base64.b64encode(record["signature"])
                + b"\n"
            ],
        )
        self.assertEqual(list(self.upload_folder.iterdir()), [])

    def test_original_path_is_not_used_for_staging_or_cloud_public_id(self):
        original_name = r"C:\private\course files\Report.TXT"
        result = self.register(
            FileStorage(stream=io.BytesIO(b"exact bytes"), filename=original_name)
        )

        record = self.get_file_records()[0]
        staged_name, staged_bytes = self.uploaded_staged_files[-1]
        self.assertEqual(record["original_name"], original_name)
        self.assertRegex(staged_name, r"^[0-9a-f]{32}\.txt$")
        self.assertEqual(staged_bytes, b"exact bytes")
        self.assertNotIn("private", record["cloudinary_file_public_id"])
        self.assertNotIn("Report", record["cloudinary_file_public_id"])
        self.assertEqual(result["original_name"], original_name)

    def test_original_extension_is_normalized_to_lowercase(self):
        self.register(
            FileStorage(stream=io.BytesIO(b"content"), filename="report.CsV")
        )

        record = self.get_file_records()[0]
        staged_name, _ = self.uploaded_staged_files[-1]
        self.assertTrue(staged_name.endswith(".csv"))
        self.assertRegex(
            record["cloudinary_file_public_id"],
            r"^cfiv/files/[0-9a-f]{32}\.csv$",
        )

    def test_missing_malformed_and_unsupported_extensions_are_rejected_before_upload(self):
        invalid_names = ("no-extension", "trailing.", "report.bad!", "program.exe")
        for filename in invalid_names:
            with self.subTest(filename=filename):
                with self.assertRaisesRegex(ValueError, "supported extension"):
                    self.register(
                        FileStorage(stream=io.BytesIO(b"content"), filename=filename)
                    )
                self.cloud_upload_mock.assert_not_called()
                self.assertEqual(self.get_file_records(), [])
                self.assertFalse(self.upload_folder.exists())

    def test_string_password_is_accepted(self):
        upload = FileStorage(
            stream=io.BytesIO(b"String password upload"),
            filename="string-password.txt",
        )

        result = self.register(upload, password=self.password.decode("utf-8"))

        self.assertTrue(result["file_id"])
        records = self.get_file_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["file_id"], result["file_id"])
        self.assertIsNone(records[0]["stored_name"])
        self.assertEqual(records[0]["storage_backend"], "cloudinary")

    def test_same_original_filename_creates_independent_uploads(self):
        first = self.register(
            FileStorage(stream=io.BytesIO(b"first"), filename="repeat.txt")
        )
        second = self.register(
            FileStorage(stream=io.BytesIO(b"second"), filename="repeat.txt")
        )

        self.assertNotEqual(first["file_id"], second["file_id"])
        records = self.get_file_records()
        self.assertEqual(len(records), 2)
        self.assertEqual(
            {record["original_name"] for record in records},
            {"repeat.txt"},
        )
        file_public_ids = {record["cloudinary_file_public_id"] for record in records}
        self.assertEqual(len(file_public_ids), 2)
        self.assertEqual(list(self.upload_folder.iterdir()), [])

    def test_missing_filename_is_rejected(self):
        upload = FileStorage(stream=io.BytesIO(b"content"), filename="")

        with self.assertRaises(ValueError):
            self.register(upload)

        if self.upload_folder.exists():
            self.assertEqual(list(self.upload_folder.iterdir()), [])
        self.assertEqual(self.get_file_records(), [])

    def test_unknown_key_id_fails_and_removes_upload(self):
        upload = FileStorage(stream=io.BytesIO(b"content"), filename="unknown.txt")

        with self.assertRaisesRegex(ValueError, "not registered"):
            self.register(upload, key_id="0" * 64)

        self.assertEqual(list(self.upload_folder.iterdir()), [])
        self.assertEqual(self.get_file_records(), [])

    def test_incorrect_private_key_password_fails_and_removes_upload(self):
        upload = FileStorage(stream=io.BytesIO(b"content"), filename="password.txt")

        with self.assertRaises(ValueError):
            self.register(upload, password=b"incorrect-password")

        self.assertEqual(list(self.upload_folder.iterdir()), [])
        self.assertEqual(self.get_file_records(), [])

    def test_mismatched_private_key_fails_and_removes_upload(self):
        other_private_key, _ = generate_key_pair(
            self.root / "other-keys",
            self.password,
        )
        upload = FileStorage(stream=io.BytesIO(b"content"), filename="mismatch.txt")

        with self.assertRaisesRegex(ValueError, "does not match"):
            self.register(upload, private_key_path=other_private_key)

        self.assertEqual(list(self.upload_folder.iterdir()), [])
        self.assertEqual(self.get_file_records(), [])

    def test_oversized_upload_fails_and_removes_partial_file(self):
        upload = FileStorage(
            stream=OversizedStream(Config.MAX_FILE_SIZE + 1),
            filename="too-large.txt",
        )

        with self.assertRaisesRegex(ValueError, "16 MB limit"):
            self.register(upload)

        self.assertEqual(list(self.upload_folder.iterdir()), [])
        self.assertEqual(self.get_file_records(), [])

    def test_non_bytes_stream_chunk_fails_and_removes_upload(self):
        upload = FileStorage(
            stream=io.StringIO("not binary data"),
            filename="invalid-stream.txt",
        )

        with self.assertRaisesRegex(ValueError, "must return bytes"):
            self.register(upload)

        self.assertEqual(list(self.upload_folder.iterdir()), [])
        self.assertEqual(self.get_file_records(), [])

    def test_original_cloud_upload_failure_leaves_no_local_or_database_record(self):
        self.cloud_upload_mock.side_effect = CloudStorageError(
            "Cloudinary upload failed."
        )

        with self.assertRaises(CloudStorageError):
            self.register(FileStorage(stream=io.BytesIO(b"content"), filename="x.txt"))

        self.assertEqual(self.get_file_records(), [])
        self.assertEqual(list(self.upload_folder.iterdir()), [])
        self.cloud_delete_mock.assert_not_called()

    def test_signature_cloud_upload_failure_leaves_no_local_or_database_record(self):
        self.cloud_upload_mock.side_effect = CloudStorageError(
            "Cloudinary signature upload failed."
        )

        with self.assertRaises(CloudStorageError):
            self.register(FileStorage(stream=io.BytesIO(b"content"), filename="x.txt"))

        self.assertEqual(self.get_file_records(), [])
        self.assertEqual(list(self.upload_folder.iterdir()), [])
        # The cloud_storage pair helper owns partial-upload cleanup when the
        # signature upload fails before it can return both public IDs.
        self.cloud_delete_mock.assert_not_called()

    def test_database_insertion_failure_deletes_both_cloud_resources(self):
        connection = database.get_db_connection()
        try:
            connection.execute(
                """
                CREATE TRIGGER reject_file_record
                BEFORE INSERT ON file_records
                BEGIN
                    SELECT RAISE(FAIL, 'test insertion failure');
                END
                """
            )
        finally:
            connection.close()

        with patch.dict("os.environ", {"CFIV_ENV": "development"}):
            with self.assertLogs("cfiv.registration", level="INFO") as captured:
                with self.assertRaises(sqlite3.IntegrityError):
                    self.register(
                        FileStorage(stream=io.BytesIO(b"content"), filename="x.txt")
                    )

        diagnostic_output = "\n".join(captured.output)
        self.assertIn("stage=local_staging_file_cleanup status=success", diagnostic_output)
        self.assertIn(
            "stage=database_insertion status=failure error_category=database_error",
            diagnostic_output,
        )
        self.assertEqual(self.get_file_records(), [])
        self.assertEqual(list(self.upload_folder.iterdir()), [])
        self.assertEqual(self.cloud_delete_mock.call_count, 2)
        self.assertEqual(
            {call.args[0] for call in self.cloud_delete_mock.call_args_list},
            set(self.uploaded_ids[-1]),
        )

    def test_missing_cloudinary_configuration_cleans_staged_file(self):
        self.cloud_upload_mock.side_effect = CloudStorageConfigurationError(
            "Cloudinary storage is not configured on this server."
        )

        with self.assertRaises(CloudStorageConfigurationError):
            self.register(FileStorage(stream=io.BytesIO(b"content"), filename="x.txt"))

        self.assertEqual(self.get_file_records(), [])
        self.assertEqual(list(self.upload_folder.iterdir()), [])
        self.cloud_delete_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
