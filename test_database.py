
import sqlite3

from config import Config
from backend.database import init_db, get_db_connection

DATABASE_PATH = Config.DATABASE_PATH


def test_foreign_key():
    print("\n--- TESTING FOREIGN-KEY PROTECTION ---")

    connection = get_db_connection()

    try:
        connection.execute(
            """
            INSERT INTO file_records (
                file_id,
                original_name,
                stored_name,
                size_bytes,
                sha256,
                sha3_256,
                signature,
                key_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "test-file-id",
                "sample.txt",
                "test-stored-file",
                100,
                "a" * 64,
                "b" * 64,
                b"test-signature",
                "nonexistent-key-id",
                "2026-10-31T06:00:00Z"
            )
        )

        connection.commit()
        print("ERROR: Invalid key was accepted!")

    except sqlite3.IntegrityError:
        print("SUCCESS: Invalid key was rejected!")

    finally:
        connection.close()


def main():
    print("--- INITIALIZING DATABASE ---")

    init_db()
    print("Database initialized successfully!")

    print("\n--- CHECKING TABLES ---")

    connection = get_db_connection()

    try:
        tables = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            ORDER BY name
            """
        ).fetchall()

        for table in tables:
            print(table["name"])

        print("\n--- CHECKING INDEX ---")

        indexes = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index'
            AND name = 'idx_file_records_key_id'
            """
        ).fetchall()

        for index in indexes:
            print(index["name"])

        print("\n--- DATABASE LOCATION ---")
        print(DATABASE_PATH)

    finally:
        connection.close()

    test_foreign_key()


if __name__ == "__main__":
    main()
