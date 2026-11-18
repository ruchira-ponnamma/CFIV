"""Tests for the CFIV dashboard queries using an isolated SQLite database."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import database
from backend.dashboard_service import get_dashboard_data, get_registered_files_with_status


class DashboardServiceTests(unittest.TestCase):
    """Verify dashboard counts and file summaries from temporary data."""

    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)

        database_patch = patch.object(database, "DATABASE_PATH", self.root / "test.db")
        database_patch.start()
        self.addCleanup(database_patch.stop)

        database.init_db()

    def add_file(self, file_id, created_at, *, original_name=None, size_bytes=10, key_id=None):
        """Insert a public key if needed and one file record."""
        key_id = key_id or ("k" * 64)
        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO public_keys (key_id, public_key_pem, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (key_id, b"test-key", created_at),
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
                        b"signature",
                        key_id,
                        created_at,
                    ),
                )
        finally:
            connection.close()

    def add_attempt(self, attempt_id, file_id, created_at, passed):
        """Insert a verification attempt for one file."""
        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO verification_attempts (
                        attempt_id, file_id, created_at, sha256_match,
                        sha3_256_match, signature_valid, integrity_verified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attempt_id,
                        file_id,
                        created_at,
                        int(passed),
                        int(passed),
                        int(passed),
                        int(passed),
                    ),
                )
        finally:
            connection.close()

    def test_empty_database_returns_zero_counts_and_no_recent_files(self):
        self.assertEqual(
            get_dashboard_data(),
            {
                "total_files": 0,
                "total_public_keys": 0,
                "verified_files": 0,
                "failed_files": 0,
                "unverified_files": 0,
                "recent_files": [],
            },
        )

    def test_file_and_public_key_totals_are_counted(self):
        self.add_file("file-1", "2026-11-01T10:00:00Z")
        self.add_file("file-2", "2026-11-02T10:00:00Z", key_id="p" * 64)

        data = get_dashboard_data()

        self.assertEqual(data["total_files"], 2)
        self.assertEqual(data["total_public_keys"], 2)

    def test_counts_latest_verified_failed_and_unverified_files(self):
        self.add_file("passed", "2026-11-01T10:00:00Z")
        self.add_file("failed", "2026-11-02T10:00:00Z")
        self.add_file("unverified", "2026-11-03T10:00:00Z")
        self.add_attempt("pass-1", "passed", "2026-11-03T10:00:00Z", True)
        self.add_attempt("fail-1", "failed", "2026-11-03T10:00:00Z", False)

        data = get_dashboard_data()

        self.assertEqual(data["verified_files"], 1)
        self.assertEqual(data["failed_files"], 1)
        self.assertEqual(data["unverified_files"], 1)

    def test_multiple_attempts_count_file_by_latest_attempt_only(self):
        self.add_file("file-1", "2026-11-01T10:00:00Z")
        self.add_attempt("old-pass", "file-1", "2026-11-02T10:00:00Z", True)
        self.add_attempt("new-fail", "file-1", "2026-11-03T10:00:00Z", False)

        data = get_dashboard_data()

        self.assertEqual(data["total_files"], 1)
        self.assertEqual(data["verified_files"], 0)
        self.assertEqual(data["failed_files"], 1)
        self.assertEqual(data["unverified_files"], 0)

    def test_equal_attempt_timestamps_use_attempt_id_as_tie_breaker(self):
        self.add_file("file-1", "2026-11-01T10:00:00Z")
        self.add_attempt("attempt-a", "file-1", "2026-11-03T10:00:00Z", True)
        self.add_attempt("attempt-z", "file-1", "2026-11-03T10:00:00Z", False)

        data = get_dashboard_data()

        self.assertEqual(data["failed_files"], 1)
        self.assertEqual(data["verified_files"], 0)
        self.assertEqual(data["recent_files"][0]["status"], "Tampered")

    def test_recent_files_are_ordered_by_date_then_file_id(self):
        self.add_file("file-a", "2026-11-01T10:00:00Z")
        self.add_file("file-b", "2026-11-03T10:00:00Z")
        self.add_file("file-c", "2026-11-03T10:00:00Z")

        rows = get_dashboard_data()["recent_files"]

        self.assertEqual([row["file_id"] for row in rows], ["file-c", "file-b", "file-a"])

    def test_recent_file_limit_is_applied(self):
        for index in range(3):
            self.add_file(
                f"file-{index}",
                f"2026-11-0{index + 1}T10:00:00Z",
            )

        data = get_dashboard_data(recent_limit=2)

        self.assertEqual(len(data["recent_files"]), 2)
        self.assertEqual(
            [row["file_id"] for row in data["recent_files"]],
            ["file-2", "file-1"],
        )

    def test_invalid_recent_limits_are_rejected(self):
        for invalid_limit in (0, -1, True, False, 1.5, "2", None):
            with self.subTest(limit=invalid_limit):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    get_dashboard_data(recent_limit=invalid_limit)

    def test_recent_items_contain_only_approved_fields(self):
        self.add_file("file-1", "2026-11-03T10:00:00Z", size_bytes=42)
        data = get_dashboard_data()

        self.assertEqual(
            set(data["recent_files"][0]),
            {"file_id", "original_name", "created_at", "size_bytes", "status"},
        )
        self.assertEqual(data["recent_files"][0]["status"], "Unverified")

    def test_registered_file_listing_returns_verified_tampered_and_unverified(self):
        self.add_file("verified", "2026-11-01T10:00:00Z")
        self.add_file("tampered", "2026-11-02T10:00:00Z")
        self.add_file("cloud-unverified", "2026-11-03T10:00:00Z")
        self.add_attempt("attempt-pass", "verified", "2026-11-04T10:00:00Z", True)
        self.add_attempt("attempt-a", "tampered", "2026-11-04T10:00:00Z", True)
        self.add_attempt("attempt-z", "tampered", "2026-11-04T10:00:00Z", False)

        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    UPDATE file_records
                    SET stored_name = NULL,
                        storage_backend = 'cloudinary',
                        cloudinary_file_public_id = ?,
                        cloudinary_signature_public_id = ?
                    WHERE file_id = ?
                    """,
                    ("cfiv/files/cloud-unverified.txt", "cfiv/signatures/cloud-unverified", "cloud-unverified"),
                )
        finally:
            connection.close()

        files = get_registered_files_with_status()

        self.assertEqual(
            [(file["file_id"], file["status"]) for file in files],
            [
                ("cloud-unverified", "Unverified"),
                ("tampered", "Tampered"),
                ("verified", "Verified"),
            ],
        )
        self.assertEqual(
            set(files[0]),
            {"file_id", "original_name", "created_at", "size_bytes", "status"},
        )
        self.assertNotIn("cloudinary_file_public_id", files[0])
        self.assertNotIn("sha256", files[0])

    def test_registered_file_listing_empty_database_returns_empty_list(self):
        self.assertEqual(get_registered_files_with_status(), [])


if __name__ == "__main__":
    unittest.main()
