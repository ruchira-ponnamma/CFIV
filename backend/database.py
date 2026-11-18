"""SQLite connection and schema initialization helpers for CFIV."""

import re
import sqlite3
from pathlib import Path

from config import Config

DATABASE_PATH = Config.DATABASE_PATH


_LEGACY_FILE_RECORD_COLUMNS = {
    "file_id",
    "original_name",
    "stored_name",
    "size_bytes",
    "sha256",
    "sha3_256",
    "signature",
    "key_id",
    "created_at",
}
_MIGRATED_FILE_RECORD_COLUMNS = _LEGACY_FILE_RECORD_COLUMNS | {
    "storage_backend",
    "cloudinary_file_public_id",
    "cloudinary_signature_public_id",
}
_CURRENT_FILE_RECORD_COLUMNS = _MIGRATED_FILE_RECORD_COLUMNS | {
    "signature_scheme",
}


def _create_file_records_table_sql(table_name):
    """Return the current file-record schema for a fixed internal table name."""
    if table_name not in {"file_records", "file_records_migration"}:
        raise ValueError("Unsupported file-record table name.")

    return f"""
        CREATE TABLE {table_name} (
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
            signature_scheme TEXT NOT NULL DEFAULT 'sha256-v1'
                CHECK (signature_scheme IN (
                    'sha256-v1', 'combined-sha256-sha3-v2'
                )),
            FOREIGN KEY (key_id) REFERENCES public_keys(key_id)
                ON UPDATE RESTRICT
                ON DELETE RESTRICT,
            CHECK (
                (
                    storage_backend = 'local'
                    AND stored_name IS NOT NULL
                    AND cloudinary_file_public_id IS NULL
                    AND cloudinary_signature_public_id IS NULL
                )
                OR
                (
                    storage_backend = 'cloudinary'
                    AND stored_name IS NULL
                    AND cloudinary_file_public_id IS NOT NULL
                    AND length(trim(cloudinary_file_public_id)) > 0
                    AND cloudinary_signature_public_id IS NOT NULL
                    AND length(trim(cloudinary_signature_public_id)) > 0
                )
            )
        )
    """


def _normalized_schema_sql(schema_sql):
    """Normalize SQLite's stored CREATE statement for schema comparisons."""
    return re.sub(r"\s+", "", schema_sql.lower())


def _file_records_columns(connection):
    return {
        row["name"]: row
        for row in connection.execute("PRAGMA table_info(file_records)").fetchall()
    }


def _has_unique_single_column_index(connection, column_name):
    """Check that a column has a unique index of its own."""
    for index in connection.execute("PRAGMA index_list(file_records)").fetchall():
        if not index["unique"]:
            continue
        indexed_columns = connection.execute(
            f"PRAGMA index_info('{index['name']}')"
        ).fetchall()
        if [row["name"] for row in indexed_columns] == [column_name]:
            return True
    return False


def _has_expected_key_foreign_key(connection):
    foreign_keys = connection.execute(
        "PRAGMA foreign_key_list(file_records)"
    ).fetchall()
    return len(foreign_keys) == 1 and (
        foreign_keys[0]["table"],
        foreign_keys[0]["from"],
        foreign_keys[0]["to"],
        foreign_keys[0]["on_update"].upper(),
        foreign_keys[0]["on_delete"].upper(),
    ) == ("public_keys", "key_id", "key_id", "RESTRICT", "RESTRICT")


def _has_file_records_key_index(connection):
    index = connection.execute(
        """
        SELECT sql FROM sqlite_master
        WHERE type = 'index' AND name = 'idx_file_records_key_id'
          AND tbl_name = 'file_records'
        """
    ).fetchone()
    return index is not None and _normalized_schema_sql(index["sql"] or "") == (
        "createindexidx_file_records_key_idonfile_records(key_id)"
    )


def _is_legacy_file_records_schema(connection):
    """Recognize only the known pre-Cloudinary file-record table."""
    columns = _file_records_columns(connection)
    if set(columns) != _LEGACY_FILE_RECORD_COLUMNS:
        return False

    schema_row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'file_records'"
    ).fetchone()
    if schema_row is None:
        return False

    schema_sql = _normalized_schema_sql(schema_row["sql"] or "")
    required_checks = (
        "check(size_bytes>=0)",
        "check(length(sha256)=64)",
        "check(length(sha3_256)=64)",
        "check(length(signature)>0)",
    )
    expected_column_types = {
        "file_id": "TEXT",
        "original_name": "TEXT",
        "stored_name": "TEXT",
        "size_bytes": "INTEGER",
        "sha256": "TEXT",
        "sha3_256": "TEXT",
        "signature": "BLOB",
        "key_id": "TEXT",
        "created_at": "TEXT",
    }
    required_columns = {
        "original_name", "stored_name", "size_bytes", "sha256", "sha3_256",
        "signature", "key_id", "created_at",
    }
    return (
        all(
            columns[name]["type"].upper() == column_type
            for name, column_type in expected_column_types.items()
        )
        and columns["file_id"]["pk"] == 1
        and all(columns[name]["notnull"] == 1 for name in required_columns)
        and all(check in schema_sql for check in required_checks)
        and _has_unique_single_column_index(connection, "stored_name")
        and _has_expected_key_foreign_key(connection)
    )


def _is_cloudinary_file_records_schema(connection):
    """Recognize the Cloudinary schema before signature-scheme tracking."""
    columns = _file_records_columns(connection)
    if set(columns) != _MIGRATED_FILE_RECORD_COLUMNS:
        return False

    schema_row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'file_records'"
    ).fetchone()
    if schema_row is None:
        return False

    schema_sql = _normalized_schema_sql(schema_row["sql"] or "")
    required_fragments = (
        "check(size_bytes>=0)",
        "check(length(sha256)=64)",
        "check(length(sha3_256)=64)",
        "check(length(signature)>0)",
        "default'local'",
        "check((storage_backend='local'andstored_nameisnotnull"
        "andcloudinary_file_public_idisnullandcloudinary_signature_public_idisnull)"
        "or(storage_backend='cloudinary'andstored_nameisnull"
        "andcloudinary_file_public_idisnotnull"
        "andlength(trim(cloudinary_file_public_id))>0"
        "andcloudinary_signature_public_idisnotnull"
        "andlength(trim(cloudinary_signature_public_id))>0)))",
    )
    expected_column_types = {
        "file_id": "TEXT",
        "original_name": "TEXT",
        "stored_name": "TEXT",
        "size_bytes": "INTEGER",
        "sha256": "TEXT",
        "sha3_256": "TEXT",
        "signature": "BLOB",
        "key_id": "TEXT",
        "created_at": "TEXT",
        "storage_backend": "TEXT",
        "cloudinary_file_public_id": "TEXT",
        "cloudinary_signature_public_id": "TEXT",
    }
    return (
        all(
            columns[name]["type"].upper() == column_type
            for name, column_type in expected_column_types.items()
        )
        and columns["file_id"]["pk"] == 1
        and columns["original_name"]["notnull"] == 1
        and columns["stored_name"]["notnull"] == 0
        and columns["size_bytes"]["notnull"] == 1
        and columns["sha256"]["notnull"] == 1
        and columns["sha3_256"]["notnull"] == 1
        and columns["signature"]["notnull"] == 1
        and columns["key_id"]["notnull"] == 1
        and columns["created_at"]["notnull"] == 1
        and columns["storage_backend"]["notnull"] == 1
        and columns["storage_backend"]["dflt_value"] == "'local'"
        and columns["cloudinary_file_public_id"]["notnull"] == 0
        and columns["cloudinary_signature_public_id"]["notnull"] == 0
        and all(fragment in schema_sql for fragment in required_fragments)
        and _has_unique_single_column_index(connection, "stored_name")
        and _has_expected_key_foreign_key(connection)
        and _has_file_records_key_index(connection)
    )


def _is_migrated_file_records_schema(connection):
    """Check that the current complete file-record schema is present."""
    columns = _file_records_columns(connection)
    if set(columns) != _CURRENT_FILE_RECORD_COLUMNS:
        return False

    schema_row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'file_records'"
    ).fetchone()
    if schema_row is None:
        return False

    schema_sql = _normalized_schema_sql(schema_row["sql"] or "")
    return (
        columns["signature_scheme"]["type"].upper() == "TEXT"
        and columns["signature_scheme"]["notnull"] == 1
        and columns["signature_scheme"]["dflt_value"] == "'sha256-v1'"
        and "check(signature_schemein('sha256-v1','combined-sha256-sha3-v2'))"
        in schema_sql
        and _is_cloudinary_file_records_schema_without_column_checks(
            connection, columns, schema_sql
        )
    )


def _is_cloudinary_file_records_schema_without_column_checks(
    connection, columns, schema_sql
):
    """Validate the unchanged Cloudinary columns and constraints in current schema."""
    required_fragments = (
        "check(size_bytes>=0)",
        "check(length(sha256)=64)",
        "check(length(sha3_256)=64)",
        "check(length(signature)>0)",
        "default'local'",
        "check((storage_backend='local'andstored_nameisnotnull"
        "andcloudinary_file_public_idisnullandcloudinary_signature_public_idisnull)"
        "or(storage_backend='cloudinary'andstored_nameisnull"
        "andcloudinary_file_public_idisnotnull"
        "andlength(trim(cloudinary_file_public_id))>0"
        "andcloudinary_signature_public_idisnotnull"
        "andlength(trim(cloudinary_signature_public_id))>0)))",
    )
    expected_column_types = {
        "file_id": "TEXT",
        "original_name": "TEXT",
        "stored_name": "TEXT",
        "size_bytes": "INTEGER",
        "sha256": "TEXT",
        "sha3_256": "TEXT",
        "signature": "BLOB",
        "key_id": "TEXT",
        "created_at": "TEXT",
        "storage_backend": "TEXT",
        "cloudinary_file_public_id": "TEXT",
        "cloudinary_signature_public_id": "TEXT",
    }
    return (
        all(
            columns[name]["type"].upper() == column_type
            for name, column_type in expected_column_types.items()
        )
        and columns["file_id"]["pk"] == 1
        and columns["original_name"]["notnull"] == 1
        and columns["stored_name"]["notnull"] == 0
        and columns["size_bytes"]["notnull"] == 1
        and columns["sha256"]["notnull"] == 1
        and columns["sha3_256"]["notnull"] == 1
        and columns["signature"]["notnull"] == 1
        and columns["key_id"]["notnull"] == 1
        and columns["created_at"]["notnull"] == 1
        and columns["storage_backend"]["notnull"] == 1
        and columns["storage_backend"]["dflt_value"] == "'local'"
        and columns["cloudinary_file_public_id"]["notnull"] == 0
        and columns["cloudinary_signature_public_id"]["notnull"] == 0
        and all(fragment in schema_sql for fragment in required_fragments)
        and _has_unique_single_column_index(connection, "stored_name")
        and _has_expected_key_foreign_key(connection)
        and _has_file_records_key_index(connection)
    )


def _add_signature_scheme_column(connection):
    """Safely upgrade the known Cloudinary schema without changing old values."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """
            ALTER TABLE file_records ADD COLUMN signature_scheme TEXT NOT NULL
                DEFAULT 'sha256-v1'
                CHECK (signature_scheme IN (
                    'sha256-v1', 'combined-sha256-sha3-v2'
                ))
            """
        )
        if not _is_migrated_file_records_schema(connection):
            raise RuntimeError(
                "The file_records table does not match the signature-scheme schema."
            )
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise sqlite3.IntegrityError(
                "Foreign-key validation failed after adding signature_scheme."
            )
        connection.commit()
    except BaseException:
        if connection.in_transaction:
            connection.rollback()
        raise


def _migrate_file_records(connection):
    """Rebuild the known legacy table while preserving its existing rows."""
    if _is_migrated_file_records_schema(connection):
        return
    if _is_cloudinary_file_records_schema(connection):
        _add_signature_scheme_column(connection)
        return
    if not _is_legacy_file_records_schema(connection):
        raise RuntimeError(
            "The file_records schema is unexpected or only partially migrated."
        )

    temporary_table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
        "AND name = 'file_records_migration'"
    ).fetchone()
    if temporary_table is not None:
        raise RuntimeError(
            "A temporary file_records migration table already exists."
        )

    # Preserve every explicit index attached to file_records. Constraint-backed
    # primary-key and unique indexes are recreated from the table definition.
    index_statements = [
        row["sql"]
        for row in connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'index' AND tbl_name = 'file_records' AND sql IS NOT NULL
            ORDER BY name
            """
        ).fetchall()
    ]

    foreign_keys_disabled = False
    try:
        # This must be done before BEGIN; SQLite ignores the pragma in a txn.
        connection.execute("PRAGMA foreign_keys = OFF")
        foreign_keys_disabled = (
            connection.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        )
        if not foreign_keys_disabled:
            raise RuntimeError("Could not disable foreign keys for the migration.")

        connection.execute("BEGIN IMMEDIATE")
        connection.execute(_create_file_records_table_sql("file_records_migration"))
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
        for index_sql in index_statements:
            connection.execute(index_sql)

        if not _is_migrated_file_records_schema(connection):
            raise RuntimeError(
                "The rebuilt file_records table does not match the target schema."
            )

        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise sqlite3.IntegrityError(
                "Foreign-key validation failed after rebuilding file_records."
            )

        connection.commit()
    except BaseException:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        # Cleanup errors are intentionally allowed to propagate.
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise RuntimeError("Foreign-key enforcement could not be restored.")


def get_db_connection():
    """Open a database connection with foreign keys and named-row access."""
    connection = sqlite3.connect(DATABASE_PATH)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.row_factory = sqlite3.Row
    except Exception:
        connection.close()
        raise
    return connection


def init_db():
    """Create the CFIV metadata tables and index if they do not exist."""
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = get_db_connection()
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS public_keys (
                key_id TEXT PRIMARY KEY CHECK (length(key_id) = 64),
                public_key_pem BLOB NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_records (
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
            signature_scheme TEXT NOT NULL DEFAULT 'sha256-v1'
                CHECK (signature_scheme IN (
                    'sha256-v1', 'combined-sha256-sha3-v2'
                )),
                FOREIGN KEY (key_id) REFERENCES public_keys(key_id)
                    ON UPDATE RESTRICT
                    ON DELETE RESTRICT,
                CHECK (
                    (
                        storage_backend = 'local'
                        AND stored_name IS NOT NULL
                        AND cloudinary_file_public_id IS NULL
                        AND cloudinary_signature_public_id IS NULL
                    )
                    OR
                    (
                        storage_backend = 'cloudinary'
                        AND stored_name IS NULL
                        AND cloudinary_file_public_id IS NOT NULL
                        AND length(trim(cloudinary_file_public_id)) > 0
                        AND cloudinary_signature_public_id IS NOT NULL
                        AND length(trim(cloudinary_signature_public_id)) > 0
                    )
                )
            );

            CREATE INDEX IF NOT EXISTS idx_file_records_key_id
                ON file_records(key_id);

            CREATE TABLE IF NOT EXISTS verification_attempts (
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

            CREATE INDEX IF NOT EXISTS idx_verification_attempts_file_created
                ON verification_attempts(file_id, created_at);
            """
        )
        _migrate_file_records(connection)
    finally:
        connection.close()
