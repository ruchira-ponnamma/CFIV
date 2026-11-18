"""Route tests for CFIV registration with isolated database state."""

import atexit
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
from backend import database
from backend.cloud_storage import CloudStorageError


# app.py validates configuration and initializes SQLite when imported. Point
# that one-time initialization at a temporary database, never the project DB.
_APP_DATABASE_DIRECTORY = tempfile.TemporaryDirectory()
database.DATABASE_PATH = Path(_APP_DATABASE_DIRECTORY.name) / "app-import.db"
config.Config.SECRET_KEY = "route-tests-only-secret"
atexit.register(_APP_DATABASE_DIRECTORY.cleanup)

from app import app  # noqa: E402
from config import Config  # noqa: E402


class RegisterRouteTests(unittest.TestCase):
    """Test registration request handling without real uploads or key files."""

    KEY_ID = "a" * 64

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
        self.old_max_content_length = app.config.get("MAX_CONTENT_LENGTH")
        app.config.update(TESTING=True, MAX_CONTENT_LENGTH=17 * 1024 * 1024)
        self.addCleanup(self._restore_app_config)

        self.client = app.test_client()
        self.keys = [{"key_id": self.KEY_ID, "created_at": "2026-11-04T00:00:00Z"}]
        key_list_patch = patch("app.list_registered_public_keys", return_value=self.keys)
        key_list_patch.start()
        self.addCleanup(key_list_patch.stop)
        service_patch = patch("app.register_uploaded_file")
        self.register_service_mock = service_patch.start()
        self.addCleanup(service_patch.stop)

    def _restore_app_config(self):
        app.config["TESTING"] = self.old_testing
        app.config["MAX_CONTENT_LENGTH"] = self.old_max_content_length

    def get_csrf_token(self):
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as current_session:
            token = current_session["_csrf_token"]
        self.assertIn(f'name="csrf_token" value="{token}"', response.get_data(as_text=True))
        return token

    def post_registration(self, *, token=None, include_file=True, key_id=None, password="test-pass"):
        """Submit a multipart request using the test client."""
        token = token or self.get_csrf_token()
        data = {
            "csrf_token": token,
            "key_id": self.KEY_ID if key_id is None else key_id,
            "private_key_password": password,
        }
        if include_file:
            data["upload_file"] = (io.BytesIO(b"test upload"), "test.txt")
        return self.client.post("/register", data=data)

    def test_get_renders_registered_keys_and_csrf_token(self):
        response = self.client.get("/register")

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn(self.KEY_ID, page)
        self.assertIn('name="csrf_token"', page)
        with self.client.session_transaction() as current_session:
            self.assertTrue(current_session.get("_csrf_token"))
            self.assertNotIn("private_key_password", current_session)

    def test_successful_registration_calls_service_and_redirects(self):
        response = self.post_registration(password="do-not-persist-this")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        args, kwargs = self.register_service_mock.call_args
        self.assertEqual(args[0].filename, "test.txt")
        self.assertEqual(kwargs["private_key_path"], Config.PRIVATE_KEY_PATH)
        self.assertEqual(kwargs["private_key_password"], "do-not-persist-this")
        self.assertEqual(kwargs["key_id"], self.KEY_ID)
        self.assertRegex(kwargs["correlation_id"], r"^[0-9a-f]{32}$")

        with self.client.session_transaction() as current_session:
            session_contents = repr(dict(current_session))
            self.assertNotIn("do-not-persist-this", session_contents)
            self.assertNotIn("_csrf_token", current_session)
            flashes = current_session.get("_flashes", [])
            self.assertTrue(any("successfully" in message for _, message in flashes))
            self.assertNotIn("do-not-persist-this", repr(flashes))

        dashboard_response = self.client.get("/")
        self.assertEqual(dashboard_response.status_code, 200)
        self.assertIn("File registered successfully.", dashboard_response.get_data(as_text=True))

    def test_missing_file_key_and_password_are_rejected(self):
        cases = (
            {"include_file": False},
            {"key_id": ""},
            {"password": ""},
        )
        for options in cases:
            with self.subTest(options=options):
                response = self.post_registration(**options)
                self.assertEqual(response.status_code, 400)
                self.assertIn("form-feedback-error", response.get_data(as_text=True))
        self.register_service_mock.assert_not_called()

    def test_invalid_csrf_token_is_rejected(self):
        token = self.get_csrf_token()

        response = self.post_registration(token=f"{token}-invalid")

        self.assertEqual(response.status_code, 400)
        self.assertIn("form session expired", response.get_data(as_text=True))

    def test_unregistered_key_id_is_rejected(self):
        response = self.post_registration(key_id="b" * 64)

        self.assertEqual(response.status_code, 400)
        self.assertIn("currently registered", response.get_data(as_text=True))
        self.register_service_mock.assert_not_called()

    def test_incorrect_password_displays_safe_error_without_persisting_password(self):
        password = "incorrect-secret-value"
        self.register_service_mock.side_effect = ValueError(
            "private-key password was incorrect"
        )
        response = self.post_registration(password=password)

        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Check the selected file", page)
        self.assertNotIn("private-key password was incorrect", page)
        self.assertNotIn(password, page)
        with self.client.session_transaction() as current_session:
            self.assertNotIn(password, repr(dict(current_session)))

    def test_cloud_storage_failure_displays_safe_message(self):
        self.register_service_mock.side_effect = CloudStorageError(
            "provider detail must not be shown"
        )

        response = self.post_registration()

        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 500)
        self.assertIn("could not securely store the file", page)
        self.assertNotIn("provider detail must not be shown", page)

    def test_oversized_request_returns_clear_413_message(self):
        app.config["MAX_CONTENT_LENGTH"] = 128
        response = self.client.post(
            "/register",
            data={
                "csrf_token": "unused-token",
                "upload_file": (io.BytesIO(b"x" * 1024), "large.bin"),
            },
        )

        self.assertEqual(response.status_code, 413)
        self.assertIn("16 MiB", response.get_data(as_text=True))
        self.assertIn("17 MiB", response.get_data(as_text=True))

    def test_dashboard_route_remains_functional(self):
        dashboard_data = {
            "total_files": 0,
            "total_public_keys": 0,
            "verified_files": 0,
            "failed_files": 0,
            "unverified_files": 0,
            "recent_files": [],
        }
        with patch("app.get_dashboard_data", return_value=dashboard_data):
            response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Overview", response.get_data(as_text=True))

    def test_flask_debug_cannot_be_enabled_without_local_development_config(self):
        previous_debug = app.config["DEBUG"]
        try:
            with patch.object(Config, "DEBUG", False):
                app.debug = True
                self.assertFalse(app.debug)
        finally:
            app.config["DEBUG"] = previous_debug


if __name__ == "__main__":
    unittest.main()
