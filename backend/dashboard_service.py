"""Read-only database queries for the CFIV dashboard."""

from backend.database import get_db_connection


_LATEST_ATTEMPTS_CTE = """
WITH ranked_attempts AS (
    SELECT
        file_id,
        integrity_verified,
        ROW_NUMBER() OVER (
            PARTITION BY file_id
            ORDER BY created_at DESC, attempt_id DESC
        ) AS attempt_rank
    FROM verification_attempts
), latest_attempts AS (
    SELECT file_id, integrity_verified
    FROM ranked_attempts
    WHERE attempt_rank = 1
)
"""

_FILE_STATUS_SQL = """
CASE
    WHEN latest_attempts.file_id IS NULL THEN 'Unverified'
    WHEN latest_attempts.integrity_verified = 1 THEN 'Verified'
    ELSE 'Tampered'
END
"""


def get_registered_files_with_status():
    """Return safe file metadata with each file's latest integrity status."""
    connection = get_db_connection()
    try:
        rows = connection.execute(
            _LATEST_ATTEMPTS_CTE
            + f"""
            SELECT
                file_records.file_id,
                file_records.original_name,
                file_records.created_at,
                file_records.size_bytes,
                {_FILE_STATUS_SQL} AS status
            FROM file_records
            LEFT JOIN latest_attempts
                ON latest_attempts.file_id = file_records.file_id
            ORDER BY file_records.created_at DESC, file_records.file_id DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_dashboard_data(recent_limit=5):
    """Return database-backed dashboard counts and recent file metadata."""
    if isinstance(recent_limit, bool) or not isinstance(recent_limit, int) or recent_limit <= 0:
        raise ValueError("recent_limit must be a positive integer.")

    connection = get_db_connection()
    try:
        file_counts = connection.execute(
            _LATEST_ATTEMPTS_CTE
            + """
            SELECT
                COUNT(file_records.file_id) AS total_files,
                COALESCE(SUM(CASE WHEN latest_attempts.integrity_verified = 1
                                  THEN 1 ELSE 0 END), 0) AS verified_files,
                COALESCE(SUM(CASE WHEN latest_attempts.integrity_verified = 0
                                  THEN 1 ELSE 0 END), 0) AS failed_files,
                COALESCE(SUM(CASE WHEN latest_attempts.file_id IS NULL
                                  THEN 1 ELSE 0 END), 0) AS unverified_files
            FROM file_records
            LEFT JOIN latest_attempts
                ON latest_attempts.file_id = file_records.file_id
            """
        ).fetchone()

        key_count = connection.execute(
            "SELECT COUNT(*) AS total_public_keys FROM public_keys"
        ).fetchone()["total_public_keys"]

        recent_rows = connection.execute(
            _LATEST_ATTEMPTS_CTE
            + f"""
            SELECT
                file_records.file_id,
                file_records.original_name,
                file_records.created_at,
                file_records.size_bytes,
                {_FILE_STATUS_SQL} AS status
            FROM file_records
            LEFT JOIN latest_attempts
                ON latest_attempts.file_id = file_records.file_id
            ORDER BY file_records.created_at DESC, file_records.file_id DESC
            LIMIT ?
            """,
            (recent_limit,),
        ).fetchall()

        return {
            "total_files": file_counts["total_files"],
            "total_public_keys": key_count,
            "verified_files": file_counts["verified_files"],
            "failed_files": file_counts["failed_files"],
            "unverified_files": file_counts["unverified_files"],
            "recent_files": [dict(row) for row in recent_rows],
        }
    finally:
        connection.close()
