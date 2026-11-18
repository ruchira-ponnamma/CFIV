"""Tests for the safe registered-file listing helper."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backend import database
from backend.file_service import list_registered_files


class RegisteredFileListingTests(unittest.TestCase):
    """Check listing behavior using an isolated temporary database."""

    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)

        database_patch = patch.object(database, "DATABASE_PATH", self.root / "test.db")
        database_patch.start()
        self.addCleanup(database_patch.stop)

        database.init_db()

    def add_file(self, file_id, created_at, *, original_name=None, size_bytes=12):
        """Insert one valid file row and its required public key."""
        key_id = (file_id + "k" * 64)[:64]
        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO public_keys (key_id, public_key_pem, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (key_id, b"test public key", created_at),
                )
                connection.execute(
                    """
                    INSERT INTO file_records (
                        file_id, original_name, stored_name, size_bytes,
                        sha256, sha3_256, signature, key_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        file_id,
                        original_name or f"{file_id}.txt",
                        f"{file_id}.bin",
                        size_bytes,
                        "a" * 64,
                        "b" * 64,
                        b"test signature",
                        key_id,
                        created_at,
                    ),
                )
        finally:
            connection.close()

    def test_empty_database_returns_empty_list(self):
        self.assertEqual(list_registered_files(), [])

    def test_one_registered_file_is_returned(self):
        self.add_file("file-one", "2026-11-01T10:00:00Z", original_name="report.pdf")

        files = list_registered_files()

        self.assertEqual(
            files,
            [
                {
                    "file_id": "file-one",
                    "original_name": "report.pdf",
                    "created_at": "2026-11-01T10:00:00Z",
                    "size_bytes": 12,
                }
            ],
        )

    def test_multiple_files_are_ordered_deterministically(self):
        self.add_file("file-a", "2026-11-01T10:00:00Z")
        self.add_file("file-b", "2026-11-03T10:00:00Z")
        self.add_file("file-c", "2026-11-03T10:00:00Z")

        files = list_registered_files()

        self.assertEqual(
            [file["file_id"] for file in files],
            ["file-c", "file-b", "file-a"],
        )

    def test_items_contain_only_approved_fields(self):
        self.add_file("file-one", "2026-11-01T10:00:00Z")

        files = list_registered_files()

        self.assertEqual(
            set(files[0]),
            {"file_id", "original_name", "created_at", "size_bytes"},
        )

    def test_database_connection_is_closed(self):
        connection = Mock()
        connection.execute.return_value.fetchall.return_value = []

        with patch("backend.file_service.get_db_connection", return_value=connection):
            self.assertEqual(list_registered_files(), [])

        connection.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
