"""Tests for uploaded-copy integrity verification and its Flask route."""

import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from werkzeug.datastructures import FileStorage

from backend import database
from backend.file_service import register_uploaded_file
from backend.key_registry import register_public_key
from backend.signatures import generate_key_pair
from backend.verification import verify_uploaded_copy
from config import Config


# Keep app.py's import-time database initialization isolated without leaking
# temporary module configuration into other test modules.
if "app" in sys.modules:
    from app import app  # noqa: E402
else:
    _app_import_directory = tempfile.TemporaryDirectory()
    _previous_database_path = database.DATABASE_PATH
    _previous_secret_key = Config.SECRET_KEY
    try:
        database.DATABASE_PATH = Path(_app_import_directory.name) / "app-import.db"
        Config.SECRET_KEY = "uploaded-copy-tests-only-secret"
        from app import app  # noqa: E402
    finally:
        imported_app_module = sys.modules.get("app")
        flask_app = getattr(imported_app_module, "app", None)
        if flask_app is not None:
            flask_app.config["SECRET_KEY"] = _previous_secret_key
        database.DATABASE_PATH = _previous_database_path
        Config.SECRET_KEY = _previous_secret_key
        _app_import_directory.cleanup()


class UploadedCopyServiceTests(unittest.TestCase):
    """Exercise uploaded-copy checks with temporary keys, files, and SQLite."""

    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)
        self.upload_folder = self.root / "uploads"

        database_patch = patch.object(database, "DATABASE_PATH", self.root / "test.db")
        database_patch.start()
        self.addCleanup(database_patch.stop)
        upload_patch = patch.object(Config, "UPLOAD_FOLDER", self.upload_folder)
        upload_patch.start()
        self.addCleanup(upload_patch.stop)
        database.init_db()

        self.private_key_path, self.public_key_path = generate_key_pair(
            self.root / "keys", b"uploaded-copy-test-password"
        )
        self.key_id = register_public_key(self.public_key_path)
        self.cloud_upload_patch = patch(
            "backend.file_service.upload_file_and_signature",
            side_effect=lambda *_args, **_kwargs: (
                f"cfiv/files/{uuid4().hex}.txt",
                f"cfiv/signatures/{uuid4().hex}.txt",
            ),
        )
        self.cloud_upload_mock = self.cloud_upload_patch.start()
        self.addCleanup(self.cloud_upload_patch.stop)

    def register_local_file(self, content=b"Original registered contents"):
        """Create a normal registration fixture and make its record local."""
        registered = register_uploaded_file(
            FileStorage(stream=io.BytesIO(content), filename="original.txt"),
            private_key_path=self.private_key_path,
            private_key_password=b"uploaded-copy-test-password",
            key_id=self.key_id,
            upload_folder=self.upload_folder,
        )
        stored_name = f"{uuid4().hex}.txt"
        self.upload_folder.mkdir(parents=True, exist_ok=True)
        stored_path = self.upload_folder / stored_name
        stored_path.write_bytes(content)

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
        return registered, stored_path

    @staticmethod
    def upload(content, filename="copy.txt"):
        return FileStorage(stream=io.BytesIO(content), filename=filename)

    def get_file_record(self, file_id):
        connection = database.get_db_connection()
        try:
            row = connection.execute(
                "SELECT * FROM file_records WHERE file_id = ?", (file_id,)
            ).fetchone()
            return dict(row)
        finally:
            connection.close()

    def get_attempt(self, attempt_id):
        connection = database.get_db_connection()
        try:
            return connection.execute(
                "SELECT * FROM verification_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
        finally:
            connection.close()

    def attempt_count(self, file_id):
        connection = database.get_db_connection()
        try:
            return connection.execute(
                "SELECT COUNT(*) FROM verification_attempts WHERE file_id = ?",
                (file_id,),
            ).fetchone()[0]
        finally:
            connection.close()

    def test_unchanged_uploaded_copy_passes_and_records_attempt(self):
        content = b"Original registered contents"
        registered, stored_path = self.register_local_file(content)

        result = verify_uploaded_copy(registered["file_id"], self.upload(content))

        self.assertTrue(result["sha256_match"])
        self.assertTrue(result["sha3_256_match"])
        self.assertTrue(result["signature_valid"])
        self.assertTrue(result["integrity_verified"])
        self.assertEqual(self.attempt_count(registered["file_id"]), 1)
        attempt = self.get_attempt(result["attempt_id"])
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt["file_id"], registered["file_id"])
        self.assertEqual(attempt["integrity_verified"], 1)
        self.assertEqual(stored_path.read_bytes(), content)

    def test_modified_uploaded_copy_fails_and_records_failed_attempt(self):
        registered, _stored_path = self.register_local_file()

        result = verify_uploaded_copy(
            registered["file_id"], self.upload(b"Modified submitted contents")
        )

        self.assertFalse(result["sha256_match"])
        self.assertFalse(result["sha3_256_match"])
        self.assertFalse(result["signature_valid"])
        self.assertFalse(result["integrity_verified"])
        attempt = self.get_attempt(result["attempt_id"])
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt["sha256_match"], 0)
        self.assertEqual(attempt["sha3_256_match"], 0)
        self.assertEqual(attempt["signature_valid"], 0)
        self.assertEqual(attempt["integrity_verified"], 0)

    def test_unknown_registered_file_id_raises_lookup_error(self):
        with self.assertRaises(LookupError):
            verify_uploaded_copy(str(uuid4()), self.upload(b"copy"))

    def test_unsupported_extension_is_rejected(self):
        registered, _stored_path = self.register_local_file()

        with self.assertRaises(ValueError):
            verify_uploaded_copy(
                registered["file_id"], self.upload(b"copy", "copy.exe")
            )

        self.assertEqual(self.attempt_count(registered["file_id"]), 0)

    def test_empty_uploaded_copy_is_recorded_as_a_failed_check(self):
        registered, _stored_path = self.register_local_file()

        result = verify_uploaded_copy(registered["file_id"], self.upload(b""))

        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["sha256_match"])
        self.assertFalse(result["sha3_256_match"])
        self.assertIsNotNone(self.get_attempt(result["attempt_id"]))

    def test_unreadable_uploaded_copy_is_rejected_safely(self):
        registered, _stored_path = self.register_local_file()
        unreadable = self.upload(b"unreadable")
        unreadable.stream.close()

        with self.assertRaises(ValueError):
            verify_uploaded_copy(registered["file_id"], unreadable)

        self.assertEqual(self.attempt_count(registered["file_id"]), 0)

    def test_upload_over_configured_size_limit_is_rejected(self):
        registered, _stored_path = self.register_local_file()

        with patch.object(Config, "MAX_FILE_SIZE", 8):
            with self.assertRaisesRegex(ValueError, "exceeds the 16 MB limit"):
                verify_uploaded_copy(
                    registered["file_id"], self.upload(b"123456789")
                )

        self.assertEqual(self.attempt_count(registered["file_id"]), 0)

    def test_uploaded_copy_check_does_not_change_registration_or_call_mutations(self):
        original_content = b"Original registered contents"
        registered, stored_path = self.register_local_file(original_content)
        original_record = self.get_file_record(registered["file_id"])
        original_bytes = stored_path.read_bytes()

        with (
            patch("backend.file_service.register_uploaded_file") as registration_mock,
            patch("backend.file_service.sign_hash") as signing_mock,
            patch("backend.file_service.upload_file_and_signature") as registration_upload_mock,
            patch("backend.cloud_storage.upload_file_and_signature") as upload_pair_mock,
            patch("backend.cloud_storage.upload_original_file") as upload_original_mock,
            patch("backend.cloud_storage.upload_signature_artifact") as upload_signature_mock,
            patch("backend.cloud_storage.delete_resource") as delete_mock,
            patch("backend.verification.download_original_file") as download_original_mock,
            patch("backend.verification.download_signature_artifact") as download_signature_mock,
        ):
            result = verify_uploaded_copy(
                registered["file_id"], self.upload(original_content)
            )

        updated_record = self.get_file_record(registered["file_id"])
        for field in (
            "file_id",
            "original_name",
            "stored_name",
            "size_bytes",
            "sha256",
            "sha3_256",
            "signature",
            "key_id",
            "created_at",
            "storage_backend",
            "cloudinary_file_public_id",
            "cloudinary_signature_public_id",
            "signature_scheme",
        ):
            self.assertEqual(updated_record[field], original_record[field], field)
        self.assertEqual(stored_path.read_bytes(), original_bytes)
        self.assertTrue(result["integrity_verified"])
        self.assertEqual(self.attempt_count(registered["file_id"]), 1)
        registration_mock.assert_not_called()
        signing_mock.assert_not_called()
        registration_upload_mock.assert_not_called()
        upload_pair_mock.assert_not_called()
        upload_original_mock.assert_not_called()
        upload_signature_mock.assert_not_called()
        delete_mock.assert_not_called()
        download_original_mock.assert_not_called()
        download_signature_mock.assert_not_called()
        self.cloud_upload_mock.assert_called_once()


class UploadedCopyRouteTests(unittest.TestCase):
    """Exercise the dedicated route with mocked service and isolated DB state."""

    FILE_ID = "registered-file-for-uploaded-copy"
    CSRF_TOKEN = "uploaded-copy-csrf-token-for-test"
    ATTEMPT_ID = "uploaded-copy-attempt-for-test"

    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        database_patch = patch.object(
            database, "DATABASE_PATH", Path(temporary_directory.name) / "route.db"
        )
        database_patch.start()
        self.addCleanup(database_patch.stop)
        database.init_db()

        self.old_testing = app.config.get("TESTING")
        self.old_secret_key = app.config.get("SECRET_KEY")
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "uploaded-copy-tests-only-secret"
        self.addCleanup(self.restore_testing)
        self.client = app.test_client()

        listing_patch = patch(
            "app.list_registered_files",
            return_value=[
                {
                    "file_id": self.FILE_ID,
                    "original_name": "original.txt",
                    "created_at": "2026-11-21T10:00:00Z",
                    "size_bytes": 32,
                }
            ],
        )
        self.listing_mock = listing_patch.start()
        self.addCleanup(listing_patch.stop)
        service_patch = patch("app.verify_uploaded_copy")
        self.service_mock = service_patch.start()
        self.addCleanup(service_patch.stop)

    def restore_testing(self):
        app.config["TESTING"] = self.old_testing
        app.config["SECRET_KEY"] = self.old_secret_key

    def set_csrf(self, token=None):
        token = token or self.CSRF_TOKEN
        with self.client.session_transaction() as current_session:
            current_session["_uploaded_copy_verify_csrf_token"] = token
        return token

    def post_copy(self, *, token=None, file_id=FILE_ID, filename="copy.txt"):
        data = {}
        if token is not None:
            data["csrf_token"] = token
        if file_id is not None:
            data["file_id"] = file_id
        if filename is not None:
            data["uploaded_file"] = (io.BytesIO(b"submitted copy"), filename)
        return self.client.post(
            "/verify-uploaded-copy", data=data, content_type="multipart/form-data"
        )

    def test_missing_or_invalid_csrf_is_rejected_without_service_call(self):
        missing = self.post_copy()
        self.assertEqual(missing.status_code, 400)
        self.service_mock.assert_not_called()

        token = self.set_csrf()
        invalid = self.post_copy(token=f"{token}-invalid")
        self.assertEqual(invalid.status_code, 400)
        self.service_mock.assert_not_called()

    def test_route_rejects_missing_file_fields_before_service_call(self):
        token = self.set_csrf()

        response = self.post_copy(token=token, filename=None)

        self.assertEqual(response.status_code, 400)
        self.service_mock.assert_not_called()

    def test_valid_csrf_and_upload_without_file_id_is_rejected(self):
        token = self.set_csrf()

        response = self.post_copy(token=token, file_id=None)

        self.assertEqual(response.status_code, 400)
        self.service_mock.assert_not_called()

    def test_route_rejects_unsupported_extension_before_service_call(self):
        token = self.set_csrf()

        response = self.post_copy(token=token, filename="copy.exe")

        self.assertEqual(response.status_code, 400)
        self.service_mock.assert_not_called()

    def test_unknown_registered_file_is_handled_safely(self):
        self.service_mock.side_effect = LookupError("internal lookup detail")
        token = self.set_csrf()

        response = self.post_copy(token=token, file_id="unknown-file-id")

        self.assertEqual(response.status_code, 404)
        self.assertNotIn("internal lookup detail", response.get_data(as_text=True))
        self.service_mock.assert_called_once()

    def test_valid_submission_redirects_to_existing_attempt_result(self):
        self.service_mock.return_value = {
            "attempt_id": self.ATTEMPT_ID,
            "file_id": self.FILE_ID,
            "sha256_match": False,
            "sha3_256_match": False,
            "signature_valid": False,
            "integrity_verified": False,
        }
        token = self.set_csrf()

        response = self.post_copy(token=token)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers["Location"], f"/verify?attempt_id={self.ATTEMPT_ID}"
        )
        self.service_mock.assert_called_once()
        args, _kwargs = self.service_mock.call_args
        self.assertEqual(args[0], self.FILE_ID)
        self.assertEqual(args[1].filename, "copy.txt")
        with self.client.session_transaction() as current_session:
            self.assertNotIn("_uploaded_copy_verify_csrf_token", current_session)


if __name__ == "__main__":
    unittest.main()
