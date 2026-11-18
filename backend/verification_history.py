"""Helpers for recording CFIV verification attempts."""

from datetime import datetime, timezone
from uuid import uuid4

from backend.database import get_db_connection


_RESULT_FIELDS = (
    "sha256_match",
    "sha3_256_match",
    "signature_valid",
    "integrity_verified",
)


def record_verification_attempt(file_id, result):
    """Store one verification result and return its unique attempt ID."""
    if not isinstance(file_id, str) or not file_id.strip():
        raise ValueError("The file ID must be a non-empty string.")

    if not isinstance(result, dict):
        raise ValueError("The verification result must be a dictionary.")

    missing_fields = [field for field in _RESULT_FIELDS if field not in result]
    if missing_fields:
        raise ValueError(
            "The verification result is missing required fields: "
            + ", ".join(missing_fields)
        )

    for field in _RESULT_FIELDS:
        if not isinstance(result[field], bool):
            raise ValueError(f"The verification result field {field!r} must be boolean.")

    attempt_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    connection = get_db_connection()
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
                    int(result["sha256_match"]),
                    int(result["sha3_256_match"]),
                    int(result["signature_valid"]),
                    int(result["integrity_verified"]),
                ),
            )
        return attempt_id
    finally:
        connection.close()


def get_verification_attempt(attempt_id):
    """Return safe display details for one stored verification attempt."""
    connection = get_db_connection()
    try:
        row = connection.execute(
            """
            SELECT
                verification_attempts.attempt_id,
                verification_attempts.file_id,
                file_records.original_name,
                verification_attempts.created_at,
                verification_attempts.sha256_match,
                verification_attempts.sha3_256_match,
                verification_attempts.signature_valid,
                verification_attempts.integrity_verified
            FROM verification_attempts
            JOIN file_records
                ON file_records.file_id = verification_attempts.file_id
            WHERE verification_attempts.attempt_id = ?
            """,
            (attempt_id,),
        ).fetchone()
        if row is None:
            return None

        return {
            "attempt_id": row["attempt_id"],
            "file_id": row["file_id"],
            "original_name": row["original_name"],
            "created_at": row["created_at"],
            "sha256_match": bool(row["sha256_match"]),
            "sha3_256_match": bool(row["sha3_256_match"]),
            "signature_valid": bool(row["signature_valid"]),
            "integrity_verified": bool(row["integrity_verified"]),
        }
    finally:
        connection.close()
