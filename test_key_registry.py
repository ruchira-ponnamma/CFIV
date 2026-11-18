from pathlib import Path

from backend.key_registry import register_public_key
from backend.database import get_db_connection


PUBLIC_KEY_PATH = Path.home() / "CFIV-Keys" / "public_key.pem"


def main():
    print("--- REGISTERING PUBLIC KEY ---")

    key_id = register_public_key(PUBLIC_KEY_PATH)

    print("Public key registered successfully!")
    print("Key fingerprint:", key_id)

    print("\n--- VERIFYING DATABASE RECORD ---")

    connection = get_db_connection()

    try:
        row = connection.execute(
            """
            SELECT key_id, public_key_pem, created_at
            FROM public_keys
            WHERE key_id = ?
            """,
            (key_id,)
        ).fetchone()

        if row:
            print("Key ID found:", row["key_id"])
            print("Public key stored:", bool(row["public_key_pem"]))
            print("Created at:", row["created_at"])
        else:
            print("ERROR: Key record not found!")

    finally:
        connection.close()


if __name__ == "__main__":
    main()