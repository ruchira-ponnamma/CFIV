"""Tests for the local-to-Cloudinary SQLite schema migration."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import database


class DatabaseMigrationTests(unittest.TestCase):
    """Exercise migrations using a temporary copy of the legacy schema."""

    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.database_path = Path(temporary_directory.name) / "legacy.db"

        database_patch = patch.object(database, "DATABASE_PATH", self.database_path)
        database_patch.start()
        self.addCleanup(database_patch.stop)

        self._create_legacy_database()

    def _create_legacy_database(self):
        """Create the current pre-migration tables and representative records."""
        connection = database.get_db_connection()
        try:
            connection.executescript(
                """
                CREATE TABLE public_keys (
                    key_id TEXT PRIMARY KEY CHECK (length(key_id) = 64),
                    public_key_pem BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE file_records (
                    file_id TEXT PRIMARY KEY,
                    original_name TEXT NOT NULL,
                    stored_name TEXT NOT NULL UNIQUE,
                    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
                    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
                    sha3_256 TEXT NOT NULL CHECK (length(sha3_256) = 64),
                    signature BLOB NOT NULL CHECK (length(signature) > 0),
                    key_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (key_id) REFERENCES public_keys(key_id)
                        ON UPDATE RESTRICT
                        ON DELETE RESTRICT
                );

                CREATE INDEX idx_file_records_key_id ON file_records(key_id);

                CREATE TABLE verification_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    sha256_match INTEGER NOT NULL CHECK (sha256_match IN (0, 1)),
                    sha3_256_match INTEGER NOT NULL CHECK (sha3_256_match IN (0, 1)),
                    signature_valid INTEGER NOT NULL CHECK (signature_valid IN (0, 1)),
                    integrity_verified INTEGER NOT NULL CHECK (integrity_verified IN (0, 1)),
                    FOREIGN KEY (file_id) REFERENCES file_records(file_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX idx_verification_attempts_file_created
                    ON verification_attempts(file_id, created_at);
                """
            )
            with connection:
                connection.execute(
                    """
                    INSERT INTO public_keys (key_id, public_key_pem, created_at)
                    VALUES (?, ?, ?)
                    """,
                    ("k" * 64, b"test public key bytes", "2026-11-01T00:00:00Z"),
                )
                connection.execute(
                    """
                    INSERT INTO file_records (
                        file_id, original_name, stored_name, size_bytes,
                        sha256, sha3_256, signature, key_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "legacy-file-1",
                        "legacy.txt",
                        "legacy-uuid.bin",
                        4,
                        "a" * 64,
                        "b" * 64,
                        b"original signature bytes",
                        "k" * 64,
                        "2026-11-02T01:02:03Z",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO verification_attempts (
                        attempt_id, file_id, created_at, sha256_match,
                        sha3_256_match, signature_valid, integrity_verified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "legacy-attempt-1",
                        "legacy-file-1",
                        "2026-11-02T02:03:04Z",
                        1,
                        1,
                        1,
                        1,
                    ),
                )
        finally:
            connection.close()

    def _replace_with_cloudinary_schema_without_signature_scheme(self):
        """Build the previously deployed Cloudinary schema in this temp DB."""
        connection = database.get_db_connection()
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE file_records_migration (
                    file_id TEXT PRIMARY KEY,
                    original_name TEXT NOT NULL,
                    stored_name TEXT UNIQUE,
                    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
                    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
                    sha3_256 TEXT NOT NULL CHECK (length(sha3_256) = 64),
                    signature BLOB NOT NULL CHECK (length(signature) > 0),
                    key_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    storage_backend TEXT NOT NULL DEFAULT 'local',
                    cloudinary_file_public_id TEXT,
                    cloudinary_signature_public_id TEXT,
                    FOREIGN KEY (key_id) REFERENCES public_keys(key_id)
                        ON UPDATE RESTRICT ON DELETE RESTRICT,
                    CHECK (
                        (storage_backend = 'local' AND stored_name IS NOT NULL
                         AND cloudinary_file_public_id IS NULL
                         AND cloudinary_signature_public_id IS NULL)
                        OR
                        (storage_backend = 'cloudinary' AND stored_name IS NULL
                         AND cloudinary_file_public_id IS NOT NULL
                         AND length(trim(cloudinary_file_public_id)) > 0
                         AND cloudinary_signature_public_id IS NOT NULL
                         AND length(trim(cloudinary_signature_public_id)) > 0)
                    )
                )
                """
            )
            connection.execute(
                """
                INSERT INTO file_records_migration (
                    file_id, original_name, stored_name, size_bytes, sha256,
                    sha3_256, signature, key_id, created_at, storage_backend,
                    cloudinary_file_public_id, cloudinary_signature_public_id
                )
                SELECT file_id, original_name, stored_name, size_bytes, sha256,
                       sha3_256, signature, key_id, created_at, 'local', NULL, NULL
                FROM file_records
                """
            )
            connection.execute("DROP TABLE file_records")
            connection.execute(
                "ALTER TABLE file_records_migration RENAME TO file_records"
            )
            connection.execute(
                "CREATE INDEX idx_file_records_key_id ON file_records(key_id)"
            )
            connection.commit()
            connection.execute("PRAGMA foreign_keys = ON")
        finally:
            connection.close()

    def _migrate(self):
        database.init_db()

    def _insert_file(
        self,
        *,
        file_id,
        stored_name,
        storage_backend="local",
        file_public_id=None,
        signature_public_id=None,
    ):
        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO file_records (
                        file_id, original_name, stored_name, size_bytes,
                        sha256, sha3_256, signature, key_id, created_at,
                        storage_backend, cloudinary_file_public_id,
                        cloudinary_signature_public_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        file_id,
                        f"{file_id}.txt",
                        stored_name,
                        4,
                        "c" * 64,
                        "d" * 64,
                        b"signature",
                        "k" * 64,
                        "2026-11-03T00:00:00Z",
                        storage_backend,
                        file_public_id,
                        signature_public_id,
                    ),
                )
        finally:
            connection.close()

    def test_existing_file_record_and_signature_are_preserved(self):
        self._migrate()

        connection = database.get_db_connection()
        try:
            row = connection.execute(
                "SELECT * FROM file_records WHERE file_id = ?",
                ("legacy-file-1",),
            ).fetchone()
            self.assertEqual(
                tuple(row[field] for field in (
                    "file_id", "original_name", "stored_name", "size_bytes",
                    "sha256", "sha3_256", "signature", "key_id", "created_at",
                )),
                (
                    "legacy-file-1", "legacy.txt", "legacy-uuid.bin", 4,
                    "a" * 64, "b" * 64, b"original signature bytes", "k" * 64,
                    "2026-11-02T01:02:03Z",
                ),
            )
            self.assertEqual(row["storage_backend"], "local")
            self.assertIsNone(row["cloudinary_file_public_id"])
            self.assertIsNone(row["cloudinary_signature_public_id"])
        finally:
            connection.close()

    def test_public_key_and_verification_history_are_preserved(self):
        self._migrate()

        connection = database.get_db_connection()
        try:
            key = connection.execute(
                "SELECT * FROM public_keys WHERE key_id = ?", ("k" * 64,)
            ).fetchone()
            attempt = connection.execute(
                "SELECT * FROM verification_attempts WHERE attempt_id = ?",
                ("legacy-attempt-1",),
            ).fetchone()
            self.assertEqual(key["public_key_pem"], b"test public key bytes")
            self.assertEqual(key["created_at"], "2026-11-01T00:00:00Z")
            self.assertEqual(attempt["file_id"], "legacy-file-1")
            self.assertEqual(attempt["integrity_verified"], 1)
        finally:
            connection.close()

    def test_valid_local_and_cloudinary_records_are_accepted(self):
        self._migrate()

        self._insert_file(file_id="local-2", stored_name="local-2.bin")
        self._insert_file(
            file_id="cloud-1",
            stored_name=None,
            storage_backend="cloudinary",
            file_public_id="cfiv/files/cloud-1",
            signature_public_id="cfiv/signatures/cloud-1",
        )

        connection = database.get_db_connection()
        try:
            rows = connection.execute(
                """
                SELECT file_id, stored_name, storage_backend,
                       cloudinary_file_public_id, cloudinary_signature_public_id
                FROM file_records WHERE file_id IN (?, ?)
                """,
                ("local-2", "cloud-1"),
            ).fetchall()
            by_id = {row["file_id"]: row for row in rows}
            self.assertEqual(by_id["local-2"]["storage_backend"], "local")
            self.assertEqual(by_id["local-2"]["stored_name"], "local-2.bin")
            self.assertEqual(by_id["cloud-1"]["storage_backend"], "cloudinary")
            self.assertIsNone(by_id["cloud-1"]["stored_name"])
            self.assertEqual(
                by_id["cloud-1"]["cloudinary_file_public_id"],
                "cfiv/files/cloud-1",
            )
            self.assertEqual(
                by_id["cloud-1"]["cloudinary_signature_public_id"],
                "cfiv/signatures/cloud-1",
            )
        finally:
            connection.close()

    def test_invalid_storage_combinations_are_rejected(self):
        self._migrate()

        invalid_rows = (
            # A local record must not contain remote IDs.
            ("bad-local", "bad-local.bin", "local", "remote-file", None),
            # Cloudinary rows cannot have a local stored name.
            ("bad-cloud-path", "bad-cloud.bin", "cloudinary", "remote-file", "remote-sig"),
            # Both Cloudinary identifiers are required and non-empty.
            ("bad-cloud-no-sig", None, "cloudinary", "remote-file", None),
            ("bad-cloud-empty-id", None, "cloudinary", "   ", "remote-sig"),
            # Only the two supported backend names are accepted.
            ("bad-backend", "bad-backend.bin", "other", None, None),
        )
        for file_id, stored_name, backend_name, file_id_value, sig_id_value in invalid_rows:
            with self.subTest(file_id=file_id):
                with self.assertRaises(sqlite3.IntegrityError):
                    self._insert_file(
                        file_id=file_id,
                        stored_name=stored_name,
                        storage_backend=backend_name,
                        file_public_id=file_id_value,
                        signature_public_id=sig_id_value,
                    )

    def test_primary_key_unique_and_original_check_constraints_remain(self):
        self._migrate()

        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_file(file_id="legacy-file-1", stored_name="another.bin")
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_file(file_id="duplicate-name", stored_name="legacy-uuid.bin")

        connection = database.get_db_connection()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                with connection:
                    connection.execute(
                        "UPDATE file_records SET size_bytes = -1 WHERE file_id = ?",
                        ("legacy-file-1",),
                    )
            with self.assertRaises(sqlite3.IntegrityError):
                with connection:
                    connection.execute(
                        "UPDATE file_records SET sha256 = 'short' WHERE file_id = ?",
                        ("legacy-file-1",),
                    )
        finally:
            connection.close()

    def test_foreign_keys_and_cascade_behaviour_are_preserved(self):
        self._migrate()

        connection = database.get_db_connection()
        try:
            file_fk = connection.execute(
                "PRAGMA foreign_key_list(file_records)"
            ).fetchall()
            attempt_fk = connection.execute(
                "PRAGMA foreign_key_list(verification_attempts)"
            ).fetchall()
            self.assertEqual(len(file_fk), 1)
            self.assertEqual(
                (file_fk[0]["table"], file_fk[0]["from"], file_fk[0]["to"],
                 file_fk[0]["on_update"], file_fk[0]["on_delete"]),
                ("public_keys", "key_id", "key_id", "RESTRICT", "RESTRICT"),
            )
            self.assertEqual(len(attempt_fk), 1)
            self.assertEqual(
                (attempt_fk[0]["table"], attempt_fk[0]["from"], attempt_fk[0]["to"],
                 attempt_fk[0]["on_delete"]),
                ("file_records", "file_id", "file_id", "CASCADE"),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                with connection:
                    connection.execute(
                        "DELETE FROM public_keys WHERE key_id = ?", ("k" * 64,)
                    )
            with connection:
                connection.execute(
                    "DELETE FROM file_records WHERE file_id = ?", ("legacy-file-1",)
                )
            attempt_count = connection.execute(
                "SELECT COUNT(*) FROM verification_attempts WHERE file_id = ?",
                ("legacy-file-1",),
            ).fetchone()[0]
            self.assertEqual(attempt_count, 0)
        finally:
            connection.close()

    def test_indexes_foreign_key_check_and_enforcement_are_preserved(self):
        self._migrate()

        connection = database.get_db_connection()
        try:
            index_names = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                ).fetchall()
            }
            self.assertIn("idx_file_records_key_id", index_names)
            self.assertIn("idx_verification_attempts_file_created", index_names)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        finally:
            connection.close()

    def test_repeated_migration_and_initialization_do_not_change_data(self):
        self._migrate()
        self._migrate()
        database.init_db()

        connection = database.get_db_connection()
        try:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM file_records").fetchone()[0], 1
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM public_keys").fetchone()[0], 1
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM verification_attempts").fetchone()[0],
                1,
            )
            row = connection.execute(
                "SELECT stored_name, storage_backend, signature_scheme "
                "FROM file_records WHERE file_id = ?",
                ("legacy-file-1",),
            ).fetchone()
            self.assertEqual((row["stored_name"], row["storage_backend"]),
                             ("legacy-uuid.bin", "local"))
            self.assertEqual(row["signature_scheme"], "sha256-v1")
        finally:
            connection.close()

    def test_cloudinary_schema_migration_preserves_records_and_defaults_scheme(self):
        self._replace_with_cloudinary_schema_without_signature_scheme()

        before = database.get_db_connection()
        try:
            original = dict(before.execute(
                "SELECT * FROM file_records WHERE file_id = ?", ("legacy-file-1",)
            ).fetchone())
            key_count = before.execute("SELECT COUNT(*) FROM public_keys").fetchone()[0]
            attempt = dict(before.execute(
                "SELECT * FROM verification_attempts WHERE attempt_id = ?",
                ("legacy-attempt-1",),
            ).fetchone())
        finally:
            before.close()

        self._migrate()

        connection = database.get_db_connection()
        try:
            migrated = dict(connection.execute(
                "SELECT * FROM file_records WHERE file_id = ?", ("legacy-file-1",)
            ).fetchone())
            self.assertEqual(migrated["signature_scheme"], "sha256-v1")
            original["signature_scheme"] = "sha256-v1"
            self.assertEqual(migrated, original)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM public_keys").fetchone()[0],
                key_count,
            )
            self.assertEqual(dict(connection.execute(
                "SELECT * FROM verification_attempts WHERE attempt_id = ?",
                ("legacy-attempt-1",),
            ).fetchone()), attempt)
            indexes = {
                row["name"] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                ).fetchall()
            }
            self.assertIn("idx_file_records_key_id", indexes)
            self.assertIn("idx_verification_attempts_file_created", indexes)
            self.assertEqual(len(connection.execute(
                "PRAGMA foreign_key_list(file_records)"
            ).fetchall()), 1)
            self.assertEqual(len(connection.execute(
                "PRAGMA foreign_key_list(verification_attempts)"
            ).fetchall()), 1)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        finally:
            connection.close()

    def test_invalid_signature_scheme_is_rejected(self):
        self._migrate()

        connection = database.get_db_connection()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                with connection:
                    connection.execute(
                        "UPDATE file_records SET signature_scheme = ? WHERE file_id = ?",
                        ("unknown-scheme", "legacy-file-1"),
                    )
        finally:
            connection.close()

    def test_complete_schema_is_recognized_and_repeated_init_is_safe(self):
        self._migrate()
        connection = database.get_db_connection()
        try:
            self.assertTrue(database._is_migrated_file_records_schema(connection))
            self.assertEqual(
                connection.execute(
                    "PRAGMA table_info(file_records)"
                ).fetchall()[-1]["name"],
                "signature_scheme",
            )
        finally:
            connection.close()

        self._migrate()
        self._migrate()
        connection = database.get_db_connection()
        try:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM file_records").fetchone()[0],
                1,
            )
            self.assertEqual(connection.execute(
                "SELECT signature_scheme FROM file_records WHERE file_id = ?",
                ("legacy-file-1",),
            ).fetchone()[0], "sha256-v1")
        finally:
            connection.close()

    def test_foreign_key_check_failure_rolls_back_and_restores_enforcement(self):
        connection = database.get_db_connection()
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            with connection:
                connection.execute(
                    """
                    INSERT INTO verification_attempts (
                        attempt_id, file_id, created_at, sha256_match,
                        sha3_256_match, signature_valid, integrity_verified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("orphan-attempt", "no-such-file", "2026-11-04Z", 0, 0, 0, 0),
                )
        finally:
            connection.close()

        with self.assertRaisesRegex(sqlite3.IntegrityError, "Foreign-key validation"):
            database.init_db()

        connection = database.get_db_connection()
        try:
            columns = {row["name"] for row in connection.execute(
                "PRAGMA table_info(file_records)"
            ).fetchall()}
            self.assertEqual(columns, _LEGACY_FILE_RECORD_COLUMNS_FOR_TEST)
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(
                connection.execute(
                    "SELECT stored_name FROM file_records WHERE file_id = ?",
                    ("legacy-file-1",),
                ).fetchone()[0],
                "legacy-uuid.bin",
            )
        finally:
            connection.close()


_LEGACY_FILE_RECORD_COLUMNS_FOR_TEST = {
    "file_id", "original_name", "stored_name", "size_bytes", "sha256",
    "sha3_256", "signature", "key_id", "created_at",
}


if __name__ == "__main__":
    unittest.main()
