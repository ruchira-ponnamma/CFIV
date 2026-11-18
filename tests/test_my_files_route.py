"""Route tests for the My Files page using an isolated SQLite database."""

import atexit
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
from backend import database


_APP_DATABASE_DIRECTORY = tempfile.TemporaryDirectory()
database.DATABASE_PATH = Path(_APP_DATABASE_DIRECTORY.name) / "app-import.db"
config.Config.SECRET_KEY = "my-files-route-tests-only-secret"
atexit.register(_APP_DATABASE_DIRECTORY.cleanup)

from app import app  # noqa: E402


class MyFilesRouteTests(unittest.TestCase):
    """Exercise the listing route and its reuse of the verification POST."""

    FILE_ID = "registered-file-for-my-files"
    KEY_ID = "k" * 64
    CSRF_TOKEN = "my-files-verification-token"
    ATTEMPT_ID = "my-files-attempt-id"

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
        verify_patch = patch("app.verify_registered_file")
        self.verify_mock = verify_patch.start()
        self.addCleanup(verify_patch.stop)

    def _restore_app_config(self):
        app.config["TESTING"] = self.old_testing

    def insert_file(self):
        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO public_keys (key_id, public_key_pem, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (self.KEY_ID, b"test public key", "2026-11-01T00:00:00Z"),
                )
                connection.execute(
                    """
                    INSERT INTO file_records (
                        file_id, original_name, stored_name, size_bytes,
                        sha256, sha3_256, signature, key_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.FILE_ID,
                        "my-report.txt",
                        "local-storage-name.bin",
                        128,
                        "a" * 64,
                        "b" * 64,
                        b"test signature bytes",
                        self.KEY_ID,
                        "2026-11-02T12:30:00Z",
                    ),
                )
        finally:
            connection.close()

    def verification_attempt_count(self):
        connection = database.get_db_connection()
        try:
            return connection.execute(
                "SELECT COUNT(*) FROM verification_attempts"
            ).fetchone()[0]
        finally:
            connection.close()

    def test_get_lists_registered_file_without_running_verification(self):
        self.insert_file()

        response = self.client.get("/my-files")

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("my-report.txt", page)
        self.assertIn("Unverified", page)
        self.assertIn('data-file-size="128"', page)
        self.assertNotIn("a" * 64, page)
        self.assertNotIn("local-storage-name.bin", page)
        self.verify_mock.assert_not_called()
        self.assertEqual(self.verification_attempt_count(), 0)

    def test_empty_listing_has_a_helpful_empty_state(self):
        response = self.client.get("/my-files")

        self.assertEqual(response.status_code, 200)
        self.assertIn("No registered files yet", response.get_data(as_text=True))
        self.assertEqual(self.verification_attempt_count(), 0)
        self.verify_mock.assert_not_called()

    def test_get_preserves_registration_csrf_and_supplies_verify_token(self):
        self.insert_file()
        with self.client.session_transaction() as current_session:
            current_session["_csrf_token"] = "registration-token-remains"

        response = self.client.get("/my-files")

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        with self.client.session_transaction() as current_session:
            self.assertEqual(current_session["_csrf_token"], "registration-token-remains")
            token = current_session.get("_verify_csrf_token")
            self.assertTrue(token)
        self.assertIn(f'action="/verify"', page)
        self.assertIn(f'name="csrf_token" value="{token}"', page)
        self.assertIn(f'name="file_id" value="{self.FILE_ID}"', page)

    def test_verify_form_posts_to_existing_route_and_csrf_contract(self):
        self.insert_file()
        with self.client.session_transaction() as current_session:
            current_session["_csrf_token"] = "registration-token-remains"

        page_response = self.client.get("/my-files")
        self.assertEqual(page_response.status_code, 200)
        with self.client.session_transaction() as current_session:
            token = current_session["_verify_csrf_token"]

        self.verify_mock.return_value = {
            "attempt_id": self.ATTEMPT_ID,
            "integrity_verified": True,
        }
        response = self.client.post(
            "/verify",
            data={"csrf_token": token, "file_id": self.FILE_ID},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], f"/verify?attempt_id={self.ATTEMPT_ID}")
        self.verify_mock.assert_called_once_with(self.FILE_ID)
        with self.client.session_transaction() as current_session:
            self.assertEqual(current_session["_csrf_token"], "registration-token-remains")

    def test_database_error_is_safe_and_returns_server_error(self):
        with patch(
            "app.get_registered_files_with_status",
            side_effect=sqlite3.OperationalError("private database detail"),
        ):
            response = self.client.get("/my-files")

        self.assertEqual(response.status_code, 500)
        page = response.get_data(as_text=True)
        self.assertIn("CFIV could not retrieve your files", page)
        self.assertNotIn("private database detail", page)


if __name__ == "__main__":
    unittest.main()
