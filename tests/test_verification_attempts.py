"""Focused tests for the verification-attempt SQLite schema."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import database


class VerificationAttemptsDatabaseTests(unittest.TestCase):
    """Exercise the schema using an isolated temporary database."""

    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.database_path = Path(temporary_directory.name) / "test.db"

        database_patch = patch.object(database, "DATABASE_PATH", self.database_path)
        database_patch.start()
        self.addCleanup(database_patch.stop)

        database.init_db()

    def _insert_parent_records(self, connection, file_id="file-1"):
        """Insert the public key and file row required by the foreign keys."""
        connection.execute(
            """
            INSERT INTO public_keys (key_id, public_key_pem, created_at)
            VALUES (?, ?, ?)
            """,
            ("k" * 64, b"test-public-key", "2026-11-02T00:00:00Z"),
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
                "sample.txt",
                f"{file_id}.bin",
                4,
                "a" * 64,
                "b" * 64,
                b"signature",
                "k" * 64,
                "2026-11-02T00:00:00Z",
            ),
        )

    def _insert_attempt(self, connection, attempt_id="attempt-1", file_id="file-1", values=(1, 1, 1, 1)):
        """Insert one verification attempt, optionally with test values."""
        connection.execute(
            """
            INSERT INTO verification_attempts (
                attempt_id, file_id, created_at, sha256_match,
                sha3_256_match, signature_valid, integrity_verified
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (attempt_id, file_id, "2026-11-02T00:01:00Z", *values),
        )

    def test_init_db_creates_table_expected_columns_and_index(self):
        connection = database.get_db_connection()
        try:
            columns = connection.execute(
                "PRAGMA table_info(verification_attempts)"
            ).fetchall()
            self.assertEqual(
                [column["name"] for column in columns],
                [
                    "attempt_id",
                    "file_id",
                    "created_at",
                    "sha256_match",
                    "sha3_256_match",
                    "signature_valid",
                    "integrity_verified",
                ],
            )

            index = connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'index'
                  AND name = 'idx_verification_attempts_file_created'
                """
            ).fetchone()
            self.assertIsNotNone(index)
            index_columns = connection.execute(
                "PRAGMA index_info(idx_verification_attempts_file_created)"
            ).fetchall()
            self.assertEqual([column["name"] for column in index_columns], ["file_id", "created_at"])
        finally:
            connection.close()

    def test_attempt_can_be_inserted_for_existing_file(self):
        connection = database.get_db_connection()
        try:
            with connection:
                self._insert_parent_records(connection)
                self._insert_attempt(connection)
            row = connection.execute(
                "SELECT * FROM verification_attempts WHERE attempt_id = ?",
                ("attempt-1",),
            ).fetchone()
            self.assertEqual(row["file_id"], "file-1")
            self.assertEqual(row["integrity_verified"], 1)
        finally:
            connection.close()

    def test_unknown_file_id_is_rejected_by_foreign_key(self):
        connection = database.get_db_connection()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                self._insert_attempt(connection, file_id="missing-file")
        finally:
            connection.close()

    def test_each_result_column_rejects_values_outside_zero_and_one(self):
        result_columns = (
            "sha256_match",
            "sha3_256_match",
            "signature_valid",
            "integrity_verified",
        )
        for column_index, column_name in enumerate(result_columns):
            with self.subTest(column=column_name):
                connection = database.get_db_connection()
                try:
                    self._insert_parent_records(connection)
                    values = [1, 1, 1, 1]
                    values[column_index] = 2
                    with self.assertRaises(sqlite3.IntegrityError):
                        self._insert_attempt(connection, values=tuple(values))
                finally:
                    connection.close()

    def test_deleting_file_cascades_to_verification_attempts(self):
        connection = database.get_db_connection()
        try:
            with connection:
                self._insert_parent_records(connection)
                self._insert_attempt(connection)
                connection.execute(
                    "DELETE FROM file_records WHERE file_id = ?", ("file-1",)
                )
            count = connection.execute(
                "SELECT COUNT(*) FROM verification_attempts WHERE file_id = ?",
                ("file-1",),
            ).fetchone()[0]
            self.assertEqual(count, 0)
        finally:
            connection.close()

    def test_init_db_is_idempotent_without_duplicate_schema_objects(self):
        database.init_db()
        database.init_db()

        connection = database.get_db_connection()
        try:
            table_count = connection.execute(
                """
                SELECT COUNT(*) FROM sqlite_master
                WHERE type = 'table' AND name = 'verification_attempts'
                """
            ).fetchone()[0]
            index_count = connection.execute(
                """
                SELECT COUNT(*) FROM sqlite_master
                WHERE type = 'index'
                  AND name = 'idx_verification_attempts_file_created'
                """
            ).fetchone()[0]
            self.assertEqual(table_count, 1)
            self.assertEqual(index_count, 1)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
