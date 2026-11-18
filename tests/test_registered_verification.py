"""Tests for database-backed verification with isolated temporary data."""

import base64
import io
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from werkzeug.datastructures import FileStorage

from backend import database
from backend.cloud_storage import CloudStorageError
from backend.file_service import register_uploaded_file
from backend.key_registry import register_public_key
from backend.signatures import generate_key_pair, sign_hash
from backend.verification import verify_registered_file
from config import Config


class RegisteredVerificationTests(unittest.TestCase):
    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)
        self.upload_folder = self.root / "uploads"
        self.key_folder = self.root / "keys"
        self.password = b"verification-test-password"

        database_patch = patch.object(
            database, "DATABASE_PATH", self.root / "test.db"
        )
        database_patch.start()
        self.addCleanup(database_patch.stop)

        upload_patch = patch.object(Config, "UPLOAD_FOLDER", self.upload_folder)
        upload_patch.start()
        self.addCleanup(upload_patch.stop)

        database.init_db()
        self.private_key_path, self.public_key_path = generate_key_pair(
            self.key_folder,
            self.password,
        )
        self.key_id = register_public_key(self.public_key_path)
        cloud_upload_patch = patch(
            "backend.file_service.upload_file_and_signature",
            side_effect=lambda _path, _artifact, correlation_id=None: (
                f"cfiv/files/{uuid4().hex}.bin",
                f"cfiv/signatures/{uuid4().hex}.txt",
            ),
        )
        cloud_upload_patch.start()
        self.addCleanup(cloud_upload_patch.stop)

    def register_file(self, content=b"CFIV registered verification test", filename="sample.txt"):
        """Register a test upload using this test's temporary database and files."""
        upload = FileStorage(
            stream=io.BytesIO(content),
            filename=filename,
        )
        registered = register_uploaded_file(
            upload,
            private_key_path=self.private_key_path,
            private_key_password=self.password,
            key_id=self.key_id,
            upload_folder=self.upload_folder,
        )
        # These tests exercise the existing local-file verification path.
        # Convert the newly created temporary record into a local record, as
        # would be the case for pre-Cloudinary records in production.
        stored_name = f"{uuid4()}.bin"
        self.upload_folder.mkdir(parents=True, exist_ok=True)
        (self.upload_folder / stored_name).write_bytes(content)
        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    UPDATE file_records
                    SET stored_name = ?, storage_backend = 'local',
                        cloudinary_file_public_id = NULL,
                        cloudinary_signature_public_id = NULL
                    WHERE file_id = ?
                    """,
                    (stored_name, registered["file_id"]),
                )
        finally:
            connection.close()
        return registered

    def get_file_record(self, file_id):
        """Fetch one file record and close the temporary database connection."""
        connection = database.get_db_connection()
        try:
            return connection.execute(
                "SELECT * FROM file_records WHERE file_id = ?",
                (file_id,),
            ).fetchone()
        finally:
            connection.close()

    def get_verification_attempt(self, attempt_id):
        """Fetch one history row and close the temporary database connection."""
        connection = database.get_db_connection()
        try:
            return connection.execute(
                "SELECT * FROM verification_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
        finally:
            connection.close()

    @staticmethod
    def signature_artifact(signature, scheme="combined-sha256-sha3-v2"):
        return (
            "CFIV-SIGNATURE-V1\n"
            f"scheme={scheme}\n"
            f"signature={base64.b64encode(signature).decode('ascii')}\n"
        ).encode("utf-8")

    def make_cloud_record(self, registered):
        """Change a temporary local fixture to a DB-backed cloud fixture."""
        file_public_id = f"cfiv/files/{uuid4().hex}.bin"
        signature_public_id = f"cfiv/signatures/{uuid4().hex}.txt"
        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    UPDATE file_records
                    SET stored_name = NULL, storage_backend = 'cloudinary',
                        cloudinary_file_public_id = ?,
                        cloudinary_signature_public_id = ?
                    WHERE file_id = ?
                    """,
                    (file_public_id, signature_public_id, registered["file_id"]),
                )
        finally:
            connection.close()
        record = self.get_file_record(registered["file_id"])
        return record, file_public_id, signature_public_id

    def mock_cloud_downloads(self, content, artifact):
        """Mock the two Cloudinary retrieval calls without network access."""
        original_patch = patch(
            "backend.verification.download_original_file",
            side_effect=lambda _public_id, destination: destination.write(content),
        )
        original_mock = original_patch.start()
        self.addCleanup(original_patch.stop)
        signature_patch = patch(
            "backend.verification.download_signature_artifact",
            return_value=artifact,
        )
        signature_mock = signature_patch.start()
        self.addCleanup(signature_patch.stop)
        return original_mock, signature_mock

    def test_original_file_verifies_successfully(self):
        registered = self.register_file()

        record = self.get_file_record(registered["file_id"])
        self.assertEqual(record["signature_scheme"], "combined-sha256-sha3-v2")

        result = verify_registered_file(registered["file_id"])

        self.assertEqual(result["file_id"], registered["file_id"])
        self.assertEqual(result["original_name"], "sample.txt")
        self.assertTrue(result["sha256_match"])
        self.assertTrue(result["sha3_256_match"])
        self.assertTrue(result["signature_valid"])
        self.assertTrue(result["integrity_verified"])
        attempt = self.get_verification_attempt(result["attempt_id"])
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt["file_id"], registered["file_id"])
        self.assertEqual(attempt["sha256_match"], 1)
        self.assertEqual(attempt["sha3_256_match"], 1)
        self.assertEqual(attempt["signature_valid"], 1)
        self.assertEqual(attempt["integrity_verified"], 1)

    def test_legacy_sha256_v1_record_remains_verifiable(self):
        registered = self.register_file(content=b"Legacy signature content")
        legacy_signature = sign_hash(
            registered["sha256"], self.private_key_path, self.password
        )

        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    UPDATE file_records
                    SET signature_scheme = ?, signature = ?
                    WHERE file_id = ?
                    """,
                    ("sha256-v1", legacy_signature, registered["file_id"]),
                )
        finally:
            connection.close()

        result = verify_registered_file(registered["file_id"])

        self.assertTrue(result["sha256_match"])
        self.assertTrue(result["sha3_256_match"])
        self.assertTrue(result["signature_valid"])
        self.assertTrue(result["integrity_verified"])

    def test_unsupported_signature_scheme_is_rejected(self):
        registered = self.register_file()
        connection = database.get_db_connection()
        try:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            with connection:
                connection.execute(
                    "UPDATE file_records SET signature_scheme = ? WHERE file_id = ?",
                    ("unknown-scheme", registered["file_id"]),
                )
        finally:
            connection.close()

        with self.assertRaisesRegex(ValueError, "unsupported signature scheme"):
            verify_registered_file(registered["file_id"])

    def test_modified_file_fails_integrity_checks(self):
        registered = self.register_file(content=b"Original content")
        record = self.get_file_record(registered["file_id"])
        stored_path = self.upload_folder / record["stored_name"]
        stored_path.write_bytes(b"Modified content")

        result = verify_registered_file(registered["file_id"])

        self.assertFalse(result["sha256_match"])
        self.assertFalse(result["sha3_256_match"])
        self.assertFalse(result["signature_valid"])
        self.assertFalse(result["integrity_verified"])
        attempt = self.get_verification_attempt(result["attempt_id"])
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt["file_id"], registered["file_id"])
        self.assertEqual(attempt["sha256_match"], 0)
        self.assertEqual(attempt["sha3_256_match"], 0)
        self.assertEqual(attempt["signature_valid"], 0)
        self.assertEqual(attempt["integrity_verified"], 0)

    def test_missing_stored_file_raises_file_not_found_error(self):
        registered = self.register_file()
        record = self.get_file_record(registered["file_id"])
        (self.upload_folder / record["stored_name"]).unlink()

        with self.assertRaises(FileNotFoundError):
            verify_registered_file(registered["file_id"])

    def test_unknown_file_id_raises_lookup_error(self):
        with self.assertRaises(LookupError):
            verify_registered_file(str(uuid4()))

    def test_missing_public_key_raises_lookup_error(self):
        registered = self.register_file()
        missing_key_id = "0" * 64
        if missing_key_id == self.key_id:
            missing_key_id = "1" * 64

        connection = database.get_db_connection()
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            with connection:
                connection.execute(
                    "UPDATE file_records SET key_id = ? WHERE file_id = ?",
                    (missing_key_id, registered["file_id"]),
                )
        finally:
            connection.close()

        with self.assertRaisesRegex(LookupError, "public key"):
            verify_registered_file(registered["file_id"])

    def test_public_key_fingerprint_mismatch_raises_value_error(self):
        registered = self.register_file()
        mismatched_key_id = "0" * 64
        if mismatched_key_id == self.key_id:
            mismatched_key_id = "1" * 64
        public_key_pem = Path(self.public_key_path).read_bytes()
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO public_keys (key_id, public_key_pem, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (mismatched_key_id, public_key_pem, created_at),
                )
                connection.execute(
                    "UPDATE file_records SET key_id = ? WHERE file_id = ?",
                    (mismatched_key_id, registered["file_id"]),
                )
        finally:
            connection.close()

        with self.assertRaisesRegex(ValueError, "fingerprint"):
            verify_registered_file(registered["file_id"])

    def test_cloudinary_file_verifies_and_records_attempt(self):
        content = b"Cloudinary verification content"
        registered = self.register_file(content=content)
        record, file_public_id, signature_public_id = self.make_cloud_record(registered)
        artifact = self.signature_artifact(record["signature"])
        original_mock, signature_mock = self.mock_cloud_downloads(content, artifact)

        result = verify_registered_file(registered["file_id"])

        self.assertTrue(result["sha256_match"])
        self.assertTrue(result["sha3_256_match"])
        self.assertTrue(result["signature_valid"])
        self.assertTrue(result["integrity_verified"])
        original_mock.assert_called_once()
        signature_mock.assert_called_once_with(signature_public_id)
        self.assertEqual(original_mock.call_args.args[0], file_public_id)
        attempt = self.get_verification_attempt(result["attempt_id"])
        self.assertEqual(attempt["integrity_verified"], 1)

    def test_modified_cloud_original_is_recorded_as_failed(self):
        registered = self.register_file(content=b"Original cloud bytes")
        record, _, _ = self.make_cloud_record(registered)
        self.mock_cloud_downloads(
            b"Modified cloud bytes",
            self.signature_artifact(record["signature"]),
        )

        result = verify_registered_file(registered["file_id"])

        self.assertFalse(result["sha256_match"])
        self.assertFalse(result["sha3_256_match"])
        self.assertFalse(result["signature_valid"])
        self.assertFalse(result["integrity_verified"])
        attempt = self.get_verification_attempt(result["attempt_id"])
        self.assertEqual(attempt["integrity_verified"], 0)

    def test_modified_cloud_signature_artifact_is_recorded_as_failed(self):
        registered = self.register_file()
        record, _, _ = self.make_cloud_record(registered)
        modified_signature = b"different signature bytes"
        self.mock_cloud_downloads(
            b"CFIV registered verification test",
            self.signature_artifact(modified_signature),
        )

        result = verify_registered_file(registered["file_id"])

        self.assertTrue(result["sha256_match"])
        self.assertTrue(result["sha3_256_match"])
        self.assertFalse(result["signature_valid"])
        self.assertFalse(result["integrity_verified"])
        attempt = self.get_verification_attempt(result["attempt_id"])
        self.assertEqual(attempt["signature_valid"], 0)

    def test_cloud_signature_artifact_scheme_mismatch_is_rejected(self):
        registered = self.register_file()
        record, _, _ = self.make_cloud_record(registered)
        self.mock_cloud_downloads(
            b"CFIV registered verification test",
            self.signature_artifact(record["signature"], scheme="sha256-v1"),
        )

        with self.assertRaisesRegex(ValueError, "scheme does not match"):
            verify_registered_file(registered["file_id"])

    def test_invalid_cloud_signature_artifact_base64_is_rejected(self):
        registered = self.register_file()
        self.make_cloud_record(registered)
        artifact = (
            b"CFIV-SIGNATURE-V1\n"
            b"scheme=combined-sha256-sha3-v2\n"
            b"signature=%%%\n"
        )
        self.mock_cloud_downloads(b"CFIV registered verification test", artifact)

        with self.assertRaisesRegex(ValueError, "artifact is malformed"):
            verify_registered_file(registered["file_id"])

    def test_database_signature_blob_mismatch_is_recorded_as_failed(self):
        registered = self.register_file()
        record, _, _ = self.make_cloud_record(registered)
        artifact = self.signature_artifact(record["signature"])
        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    "UPDATE file_records SET signature = ? WHERE file_id = ?",
                    (b"different database signature", registered["file_id"]),
                )
        finally:
            connection.close()
        self.mock_cloud_downloads(b"CFIV registered verification test", artifact)

        result = verify_registered_file(registered["file_id"])

        self.assertTrue(result["sha256_match"])
        self.assertTrue(result["sha3_256_match"])
        self.assertFalse(result["signature_valid"])
        self.assertFalse(result["integrity_verified"])

    def test_missing_cloud_resource_fails_safely(self):
        registered = self.register_file()
        self.make_cloud_record(registered)
        original_patch = patch(
            "backend.verification.download_original_file",
            side_effect=CloudStorageError("Cloudinary resource retrieval failed."),
        )
        original_patch.start()
        self.addCleanup(original_patch.stop)
        signature_patch = patch("backend.verification.download_signature_artifact")
        signature_mock = signature_patch.start()
        self.addCleanup(signature_patch.stop)

        with self.assertRaisesRegex(CloudStorageError, "resource retrieval failed"):
            verify_registered_file(registered["file_id"])
        signature_mock.assert_not_called()

    def test_missing_cloud_signature_resource_fails_safely(self):
        registered = self.register_file()
        record, _, _ = self.make_cloud_record(registered)
        self.mock_cloud_downloads(
            b"CFIV registered verification test",
            self.signature_artifact(record["signature"]),
        )
        with patch(
            "backend.verification.download_signature_artifact",
            side_effect=CloudStorageError("Cloudinary resource retrieval failed."),
        ):
            with self.assertRaisesRegex(CloudStorageError, "resource retrieval failed"):
                verify_registered_file(registered["file_id"])

    def test_unsupported_storage_backend_is_rejected(self):
        registered = self.register_file()
        connection = database.get_db_connection()
        try:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            with connection:
                connection.execute(
                    "UPDATE file_records SET storage_backend = ? WHERE file_id = ?",
                    ("other", registered["file_id"]),
                )
        finally:
            connection.close()

        with self.assertRaisesRegex(ValueError, "unsupported storage backend"):
            verify_registered_file(registered["file_id"])

    def test_cloud_download_temporary_file_is_removed_after_verification(self):
        registered = self.register_file()
        record, _, _ = self.make_cloud_record(registered)
        self.mock_cloud_downloads(
            b"CFIV registered verification test",
            self.signature_artifact(record["signature"]),
        )
        real_temporary_directory = tempfile.TemporaryDirectory
        created_directories = []

        def track_temporary_directory(**kwargs):
            directory = real_temporary_directory(**kwargs)
            created_directories.append(directory)
            return directory

        with patch(
            "backend.verification.TemporaryDirectory",
            side_effect=track_temporary_directory,
        ):
            verify_registered_file(registered["file_id"])

        self.assertEqual(len(created_directories), 1)
        self.assertFalse(Path(created_directories[0].name).exists())

    def test_cloud_download_temporary_file_is_removed_after_artifact_error(self):
        registered = self.register_file()
        self.make_cloud_record(registered)
        self.mock_cloud_downloads(
            b"CFIV registered verification test",
            b"malformed artifact",
        )
        real_temporary_directory = tempfile.TemporaryDirectory
        created_directories = []

        def track_temporary_directory(**kwargs):
            directory = real_temporary_directory(**kwargs)
            created_directories.append(directory)
            return directory

        with patch(
            "backend.verification.TemporaryDirectory",
            side_effect=track_temporary_directory,
        ):
            with self.assertRaisesRegex(ValueError, "artifact is malformed"):
                verify_registered_file(registered["file_id"])

        self.assertEqual(len(created_directories), 1)
        self.assertFalse(Path(created_directories[0].name).exists())


if __name__ == "__main__":
    unittest.main()
