"""Tests for listing registered keys using an isolated temporary database."""

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend import database, key_registry


class TrackingConnection:
    """Record whether the wrapped database connection is closed."""

    def __init__(self, connection):
        self.connection = connection
        self.closed = False

    def execute(self, *args, **kwargs):
        return self.connection.execute(*args, **kwargs)

    def close(self):
        self.closed = True
        self.connection.close()


class ListRegisteredPublicKeysTests(unittest.TestCase):
    """Test the public-key listing helper without accessing project data."""

    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.database_path = Path(temporary_directory.name) / "test.db"

        database_patch = patch.object(database, "DATABASE_PATH", self.database_path)
        database_patch.start()
        self.addCleanup(database_patch.stop)

        database.init_db()

    def add_key(self, key_id, created_at, pem_bytes=b"test public key PEM"):
        """Insert a key fixture directly into the temporary database."""
        connection = database.get_db_connection()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO public_keys (key_id, public_key_pem, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (key_id, pem_bytes, created_at),
                )
        finally:
            connection.close()

    def test_empty_registry_returns_empty_list(self):
        self.assertEqual(key_registry.list_registered_public_keys(), [])

    def test_one_registered_key_is_returned(self):
        key_id = "a" * 64
        created_at = "2026-11-01T10:00:00Z"
        self.add_key(key_id, created_at)

        self.assertEqual(
            key_registry.list_registered_public_keys(),
            [{"key_id": key_id, "created_at": created_at}],
        )

    def test_multiple_keys_are_returned_in_deterministic_order(self):
        later_key = "b" * 64
        earlier_tie_key_z = "z" * 64
        earlier_tie_key_a = "a" * 64
        self.add_key(later_key, "2026-11-02T10:00:00Z")
        self.add_key(earlier_tie_key_z, "2026-11-01T10:00:00Z")
        self.add_key(earlier_tie_key_a, "2026-11-01T10:00:00Z")

        rows = key_registry.list_registered_public_keys()

        self.assertEqual(
            [row["key_id"] for row in rows],
            [earlier_tie_key_a, earlier_tie_key_z, later_key],
        )

    def test_returned_fields_do_not_include_pem_data(self):
        self.add_key("c" * 64, "2026-11-01T10:00:00Z", b"secret PEM fixture")

        rows = key_registry.list_registered_public_keys()

        self.assertEqual(set(rows[0]), {"key_id", "created_at"})
        self.assertNotIn(b"secret PEM fixture", rows[0].values())

    def test_database_connection_is_closed(self):
        tracked_connections = []
        original_get_connection = key_registry.get_db_connection

        def get_tracked_connection():
            tracked = TrackingConnection(original_get_connection())
            tracked_connections.append(tracked)
            return tracked

        with patch.object(key_registry, "get_db_connection", get_tracked_connection):
            key_registry.list_registered_public_keys()

        self.assertEqual(len(tracked_connections), 1)
        self.assertTrue(tracked_connections[0].closed)

    def test_public_key_metadata_derives_safe_rsa_details(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = hashlib.sha256(der_bytes).hexdigest()
        created_at = "2026-11-18T10:00:00Z"
        self.add_key(key_id, created_at, pem_bytes)

        metadata = key_registry.list_registered_public_key_metadata()

        self.assertEqual(
            metadata,
            [{
                "key_id": key_id,
                "fingerprint": key_id,
                "created_at": created_at,
                "algorithm": "RSA",
                "key_size_bits": 2048,
            }],
        )
        self.assertNotIn(pem_bytes, metadata[0].values())

    def test_public_key_metadata_rejects_fingerprint_mismatch(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.add_key("f" * 64, "2026-11-18T10:00:00Z", pem_bytes)

        with self.assertRaisesRegex(ValueError, "fingerprint"):
            key_registry.list_registered_public_key_metadata()


if __name__ == "__main__":
    unittest.main()
