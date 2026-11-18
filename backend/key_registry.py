"""Helpers for registering trusted public keys in the CFIV database."""

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.database import get_db_connection


def register_public_key(public_key_path):
    """Register an RSA public key and return its SHA-256 fingerprint."""
    pem_bytes = Path(public_key_path).read_bytes()

    try:
        public_key = serialization.load_pem_public_key(pem_bytes)
    except (ValueError, TypeError) as error:
        raise ValueError("The file does not contain a valid public key PEM.") from error

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("The public key must be an RSA key.")

    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = hashlib.sha256(der_bytes).hexdigest()
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    connection = get_db_connection()
    try:
        with connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO public_keys (key_id, public_key_pem, created_at)
                VALUES (?, ?, ?)
                """,
                (key_id, pem_bytes, created_at),
            )
            row = connection.execute(
                "SELECT key_id FROM public_keys WHERE key_id = ?",
                (key_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("Public key registration did not create or find a row.")
            return row["key_id"]
    finally:
        connection.close()


def list_registered_public_keys():
    """Return registered key fingerprints and timestamps, without PEM data."""
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """
            SELECT key_id, created_at
            FROM public_keys
            ORDER BY created_at ASC, key_id ASC
            """
        ).fetchall()
        return [
            {"key_id": row["key_id"], "created_at": row["created_at"]}
            for row in rows
        ]
    finally:
        connection.close()


def list_registered_public_key_metadata():
    """Return safe display metadata derived from registered RSA public keys."""
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """
            SELECT key_id, public_key_pem, created_at
            FROM public_keys
            ORDER BY created_at ASC, key_id ASC
            """
        ).fetchall()
        metadata = []
        for row in rows:
            try:
                public_key = serialization.load_pem_public_key(row["public_key_pem"])
            except (TypeError, ValueError) as error:
                raise ValueError("A registered public key is invalid.") from error
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("A registered public key is not an RSA key.")

            der_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            fingerprint = hashlib.sha256(der_bytes).hexdigest()
            if fingerprint != row["key_id"]:
                raise ValueError("A registered public key fingerprint is invalid.")

            metadata.append(
                {
                    "key_id": row["key_id"],
                    "fingerprint": fingerprint,
                    "created_at": row["created_at"],
                    "algorithm": "RSA",
                    "key_size_bits": public_key.key_size,
                }
            )
        return metadata
    finally:
        connection.close()
