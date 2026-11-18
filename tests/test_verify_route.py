"""Route tests for CFIV verification with isolated database state."""

import atexit
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import UnsupportedAlgorithm

import config
from backend import database


# app.py validates configuration and initializes SQLite at import time. Point
# that initialization at a temporary database, never the user's CFIV database.
_APP_DATABASE_DIRECTORY = tempfile.TemporaryDirectory()
database.DATABASE_PATH = Path(_APP_DATABASE_DIRECTORY.name) / "app-import.db"
config.Config.SECRET_KEY = "verify-route-tests-only-secret"
atexit.register(_APP_DATABASE_DIRECTORY.cleanup)

from app import app  # noqa: E402


class VerifyRouteTests(unittest.TestCase):
    """Exercise /verify without accessing real upload files or keys."""

    FILE_ID = "registered-file-1"
    ATTEMPT_ID = "attempt-id-123"
    CSRF_TOKEN = "verify-csrf-token-for-tests"

    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        database_patch = patch.object(
            database, "DATABASE_PATH", Path(temporary_directory.name) / "test.db"
        )
        database_patch.start()
        self.addCleanup(database_patch.stop)
        database.init_db()

        self.old_testing = app.config.get("TESTING")
        app.config["TESTING"] = True
        self.addCleanup(self._restore_app_config)

        self.client = app.test_client()
        self.files = [
            {
                "file_id": self.FILE_ID,
                "original_name": "quarterly-report.txt",
                "created_at": "2026-11-05T12:30:00Z",
                "size_bytes": 128,
            }
        ]

        self.files_patch = patch("app.list_registered_files", return_value=self.files)
        self.files_mock = self.files_patch.start()
        self.addCleanup(self.files_patch.stop)

        self.verify_patch = patch("app.verify_registered_file")
        self.verify_mock = self.verify_patch.start()
        self.addCleanup(self.verify_patch.stop)

        self.history_patch = patch("app.get_verification_attempt", return_value=None)
        self.history_mock = self.history_patch.start()
        self.addCleanup(self.history_patch.stop)

        keys_patch = patch("app.list_registered_public_keys", return_value=[])
        self.keys_mock = keys_patch.start()
        self.addCleanup(keys_patch.stop)

    def _restore_app_config(self):
        app.config["TESTING"] = self.old_testing

    def set_csrf_token(self, token=None):
        """Prepare the verification CSRF token expected by a POST request."""
        token = token or self.CSRF_TOKEN
        with self.client.session_transaction() as current_session:
            current_session["_verify_csrf_token"] = token
        return token

    def post_verification(self, *, file_id="registered-file-1", token=None):
        """Submit a verification POST with the supplied form fields."""
        data = {}
        if token is not None:
            data["csrf_token"] = token
        if file_id is not None:
            data["file_id"] = file_id
        return self.client.post("/verify", data=data)

    @staticmethod
    def successful_attempt(attempt_id="attempt-id-123"):
        return {
            "attempt_id": attempt_id,
            "file_id": VerifyRouteTests.FILE_ID,
            "original_name": "quarterly-report.txt",
            "created_at": "2026-11-05T12:31:00Z",
            "sha256_match": True,
            "sha3_256_match": True,
            "signature_valid": True,
            "integrity_verified": True,
        }

    def test_get_renders_registered_files_and_verification_csrf_token(self):
        response = self.client.get("/verify")

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("quarterly-report.txt", page)
        self.assertIn('name="csrf_token"', page)
        self.assertIn('name="file_id"', page)
        with self.client.session_transaction() as current_session:
            token = current_session.get("_verify_csrf_token")
            self.assertTrue(token)
            self.assertNotIn("_csrf_token", current_session)
        self.assertIn(f'name="csrf_token" value="{token}"', page)

    def test_get_attempt_displays_stored_result_without_verifying_again(self):
        self.history_mock.return_value = self.successful_attempt()

        response = self.client.get(f"/verify?attempt_id={self.ATTEMPT_ID}")

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Verified", page)
        self.assertIn("quarterly-report.txt", page)
        self.assertIn("Passed", page)
        self.history_mock.assert_called_once_with(self.ATTEMPT_ID)
        self.verify_mock.assert_not_called()

    def test_get_unknown_attempt_id_returns_404(self):
        response = self.client.get("/verify?attempt_id=unknown-attempt")

        self.assertEqual(response.status_code, 404)
        self.assertIn("verification result was not found", response.get_data(as_text=True))
        self.verify_mock.assert_not_called()

    def test_post_missing_or_invalid_csrf_is_rejected(self):
        missing_token_response = self.post_verification()
        self.assertEqual(missing_token_response.status_code, 400)
        self.verify_mock.assert_not_called()
        with self.client.session_transaction() as current_session:
            self.assertTrue(current_session.get("_verify_csrf_token"))

        token = self.set_csrf_token()
        invalid_token_response = self.post_verification(token=f"{token}-invalid")
        self.assertEqual(invalid_token_response.status_code, 400)
        self.verify_mock.assert_not_called()
        with self.client.session_transaction() as current_session:
            self.assertTrue(current_session.get("_verify_csrf_token"))

    def test_post_missing_file_id_is_rejected(self):
        token = self.set_csrf_token()

        response = self.post_verification(file_id=None, token=token)

        self.assertEqual(response.status_code, 400)
        self.assertIn("Select a registered file", response.get_data(as_text=True))
        self.verify_mock.assert_not_called()

    def test_post_unregistered_file_id_is_rejected(self):
        token = self.set_csrf_token()

        response = self.post_verification(file_id="not-registered", token=token)

        self.assertEqual(response.status_code, 404)
        self.assertIn("registered file was not found", response.get_data(as_text=True))
        self.verify_mock.assert_not_called()

    def test_valid_post_verifies_once_and_redirects_to_attempt(self):
        self.verify_mock.return_value = {
            "attempt_id": self.ATTEMPT_ID,
            "integrity_verified": True,
        }
        token = self.set_csrf_token()

        response = self.post_verification(file_id=self.FILE_ID, token=token)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers["Location"],
            f"/verify?attempt_id={self.ATTEMPT_ID}",
        )
        self.verify_mock.assert_called_once_with(self.FILE_ID)

    def test_tampered_result_still_redirects_normally(self):
        self.verify_mock.return_value = {
            "attempt_id": self.ATTEMPT_ID,
            "integrity_verified": False,
            "sha256_match": False,
            "sha3_256_match": False,
            "signature_valid": False,
        }
        token = self.set_csrf_token()

        response = self.post_verification(file_id=self.FILE_ID, token=token)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers["Location"],
            f"/verify?attempt_id={self.ATTEMPT_ID}",
        )
        self.verify_mock.assert_called_once_with(self.FILE_ID)

    def test_documented_service_exceptions_return_safe_responses(self):
        cases = (
            (LookupError("secret lookup detail /private/key.pem"), 404),
            (FileNotFoundError("missing /private/storage/secret.bin"), 404),
            (
                ValueError(
                    "raw hash abcdef and private key material; "
                    "password=secret-password-foo; signature=raw-signature-bytes"
                ),
                400,
            ),
            (OSError("filesystem path C:\\private\\secret"), 500),
            (sqlite3.OperationalError("database details with secret hash"), 500),
            (UnsupportedAlgorithm("private key unsupported detail"), 500),
            (RuntimeError("internal filesystem path /private/secret"), 500),
        )
        forbidden_values = (
            "/private/key.pem",
            "/private/storage/secret.bin",
            "abcdef",
            "private key material",
            "secret-password-foo",
            "raw-signature-bytes",
            "C:\\private\\secret",
            "database details",
            "unsupported detail",
            "/private/secret",
        )

        for error, expected_status in cases:
            with self.subTest(error_type=type(error).__name__):
                self.verify_mock.reset_mock()
                self.verify_mock.side_effect = error
                token = self.set_csrf_token()

                response = self.post_verification(file_id=self.FILE_ID, token=token)

                self.assertEqual(response.status_code, expected_status)
                page = response.get_data(as_text=True)
                for forbidden_value in forbidden_values:
                    self.assertNotIn(forbidden_value, page)
                self.verify_mock.assert_called_once_with(self.FILE_ID)
                with self.client.session_transaction() as current_session:
                    self.assertTrue(current_session.get("_verify_csrf_token"))

    def test_opening_verify_page_preserves_registration_csrf_token(self):
        registration_response = self.client.get("/register")
        self.assertEqual(registration_response.status_code, 200)
        with self.client.session_transaction() as current_session:
            registration_token = current_session.get("_csrf_token")
            self.assertTrue(registration_token)

        response = self.client.get("/verify")

        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as current_session:
            self.assertEqual(current_session.get("_csrf_token"), registration_token)
            self.assertTrue(current_session.get("_verify_csrf_token"))


if __name__ == "__main__":
    unittest.main()
