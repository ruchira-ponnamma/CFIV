"""Tests for recording verification history in an isolated database."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backend import database
from backend.verification_history import (
    get_verification_attempt,
    record_verification_attempt,
)


class VerificationHistoryTests(unittest.TestCase):
    """Exercise history writes using a temporary SQLite database."""

    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.database_path = Path(temporary_directory.name) / "test.db"

        database_patch = patch.object(database, "DATABASE_PATH", self.database_path)
        database_patch.start()
        self.addCleanup(database_patch.stop)

        database.init_db()
        self._insert_file_record()

    def _insert_file_record(self, file_id="file-1"):
        """Create the public-key and file rows required by the foreign keys."""
        connection = database.get_db_connection()
        try:
            with connection:
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
        finally:
            connection.close()

    @staticmethod
    def _result():
        """Return distinct booleans so each stored value can be checked."""
        return {
            "sha256_match": True,
            "sha3_256_match": False,
            "signature_valid": True,
            "integrity_verified": False,
        }

    def test_successful_insertion_stores_all_boolean_values(self):
        attempt_id = record_verification_attempt("file-1", self._result())

        connection = database.get_db_connection()
        try:
            row = connection.execute(
                "SELECT * FROM verification_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["file_id"], "file-1")
        self.assertTrue(row["created_at"].endswith("Z"))
        self.assertEqual(row["sha256_match"], 1)
        self.assertEqual(row["sha3_256_match"], 0)
        self.assertEqual(row["signature_valid"], 1)
        self.assertEqual(row["integrity_verified"], 0)

    def test_missing_result_fields_are_rejected(self):
        incomplete_result = self._result()
        del incomplete_result["signature_valid"]

        with self.assertRaisesRegex(ValueError, "signature_valid"):
            record_verification_attempt("file-1", incomplete_result)

        connection = database.get_db_connection()
        try:
            count = connection.execute(
                "SELECT COUNT(*) FROM verification_attempts"
            ).fetchone()[0]
            self.assertEqual(count, 0)
        finally:
            connection.close()

    def test_empty_file_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            record_verification_attempt("", self._result())

    def test_non_string_file_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            record_verification_attempt(123, self._result())

    def test_unknown_file_id_is_rejected_by_foreign_key(self):
        with self.assertRaises(sqlite3.IntegrityError):
            record_verification_attempt("missing-file", self._result())

    def test_multiple_attempts_create_independent_records(self):
        first_id = record_verification_attempt("file-1", self._result())
        second_id = record_verification_attempt("file-1", {
            "sha256_match": False,
            "sha3_256_match": False,
            "signature_valid": False,
            "integrity_verified": False,
        })

        self.assertNotEqual(first_id, second_id)
        connection = database.get_db_connection()
        try:
            rows = connection.execute(
                """
                SELECT attempt_id FROM verification_attempts
                WHERE file_id = ?
                """,
                ("file-1",),
            ).fetchall()
            self.assertEqual({row["attempt_id"] for row in rows}, {first_id, second_id})
        finally:
            connection.close()

    def test_retrieves_existing_successful_attempt(self):
        result = {
            "sha256_match": True,
            "sha3_256_match": True,
            "signature_valid": True,
            "integrity_verified": True,
        }
        attempt_id = record_verification_attempt("file-1", result)

        attempt = get_verification_attempt(attempt_id)

        self.assertEqual(attempt["attempt_id"], attempt_id)
        self.assertEqual(attempt["file_id"], "file-1")
        self.assertEqual(attempt["original_name"], "sample.txt")
        self.assertTrue(attempt["created_at"].endswith("Z"))
        self.assertTrue(attempt["sha256_match"])
        self.assertTrue(attempt["sha3_256_match"])
        self.assertTrue(attempt["signature_valid"])
        self.assertTrue(attempt["integrity_verified"])

    def test_retrieves_existing_failed_attempt(self):
        result = {
            "sha256_match": False,
            "sha3_256_match": False,
            "signature_valid": False,
            "integrity_verified": False,
        }
        attempt_id = record_verification_attempt("file-1", result)

        attempt = get_verification_attempt(attempt_id)

        self.assertFalse(attempt["sha256_match"])
        self.assertFalse(attempt["sha3_256_match"])
        self.assertFalse(attempt["signature_valid"])
        self.assertFalse(attempt["integrity_verified"])

    def test_unknown_attempt_id_returns_none(self):
        self.assertIsNone(get_verification_attempt("not-a-real-attempt"))

    def test_retrieved_attempt_contains_only_approved_fields(self):
        attempt_id = record_verification_attempt("file-1", self._result())

        attempt = get_verification_attempt(attempt_id)

        self.assertEqual(
            set(attempt),
            {
                "attempt_id",
                "file_id",
                "original_name",
                "created_at",
                "sha256_match",
                "sha3_256_match",
                "signature_valid",
                "integrity_verified",
            },
        )

    def test_retrieval_closes_database_connection(self):
        connection = Mock()
        connection.execute.return_value.fetchone.return_value = {
            "attempt_id": "attempt-id",
            "file_id": "file-1",
            "original_name": "sample.txt",
            "created_at": "2026-11-02T00:00:00Z",
            "sha256_match": 1,
            "sha3_256_match": 1,
            "signature_valid": 1,
            "integrity_verified": 1,
        }
        with patch("backend.verification_history.get_db_connection", return_value=connection):
            attempt = get_verification_attempt("attempt-id")

        self.assertIsNotNone(attempt)
        connection.close.assert_called_once_with()

    def test_retrieval_closes_connection_when_query_fails(self):
        connection = Mock()
        connection.execute.side_effect = RuntimeError("query failed")

        with patch("backend.verification_history.get_db_connection", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "query failed"):
                get_verification_attempt("attempt-id")

        connection.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
