"""Route tests for the CFIV Security page using isolated database state."""

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
config.Config.SECRET_KEY = "security-route-tests-only-secret"
atexit.register(_APP_DATABASE_DIRECTORY.cleanup)

from app import app  # noqa: E402


class SecurityRouteTests(unittest.TestCase):
    """Ensure safe registered-key details render without exposing PEM data."""

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

    def _restore_app_config(self):
        app.config["TESTING"] = self.old_testing

    def test_security_page_displays_safe_public_key_metadata(self):
        metadata = [{
            "key_id": "a" * 64,
            "fingerprint": "a" * 64,
            "created_at": "2026-11-18T10:00:00Z",
            "algorithm": "RSA",
            "key_size_bits": 3072,
        }]
        with patch("app.list_registered_public_key_metadata", return_value=metadata):
            response = self.client.get("/security")

        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("RSA public key", page)
        self.assertIn("3072-bit", page)
        self.assertIn("2026-11-18T10:00:00Z", page)
        self.assertIn('data-copy-fingerprint="' + "a" * 64 + '"', page)
        self.assertIn("BestAvailableEncryption", page)
        self.assertNotIn("PUBLIC KEY-----", page)

    def test_empty_registry_has_an_informative_empty_state(self):
        with patch("app.list_registered_public_key_metadata", return_value=[]):
            response = self.client.get("/security")

        self.assertEqual(response.status_code, 200)
        self.assertIn("No public keys registered", response.get_data(as_text=True))

    def test_database_error_returns_safe_page(self):
        with patch(
            "app.list_registered_public_key_metadata",
            side_effect=sqlite3.OperationalError("sensitive database detail"),
        ):
            response = self.client.get("/security")

        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 500)
        self.assertIn("CFIV could not retrieve registered key details", page)
        self.assertNotIn("sensitive database detail", page)

    def test_security_navigation_is_available_across_existing_pages(self):
        with patch("app.list_registered_public_keys", return_value=[]):
            for path in ("/", "/register", "/verify", "/my-files"):
                with self.subTest(path=path):
                    response = self.client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertIn('href="/security"', response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
