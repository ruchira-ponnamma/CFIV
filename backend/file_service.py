"""File registration workflow for the CFIV application."""

import base64
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.cloud_storage import (
    CloudStorageError,
    delete_resource,
    normalize_original_extension,
    upload_file_and_signature,
)
from backend.database import get_db_connection
from backend.hashing import calculate_file_hashes
from backend.registration_diagnostics import (
    STAGE_DATABASE_INSERTION,
    STAGE_LOCAL_CLEANUP,
    log_registration_diagnostic,
    new_registration_correlation_id,
)
from backend.signatures import (
    COMBINED_SHA256_SHA3_V2_SCHEME,
    combined_sha256_sha3_digest,
    sign_hash,
    verify_signature_with_public_key,
)
from config import Config


def list_registered_files():
    """Return safe display metadata for registered files."""
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """
            SELECT file_id, original_name, created_at, size_bytes
            FROM file_records
            ORDER BY created_at DESC, file_id DESC
            """
        ).fetchall()
        return [
            {
                "file_id": row["file_id"],
                "original_name": row["original_name"],
                "created_at": row["created_at"],
                "size_bytes": row["size_bytes"],
            }
            for row in rows
        ]
    finally:
        connection.close()


def register_uploaded_file(
    uploaded_file,
    *,
    private_key_path,
    private_key_password,
    key_id,
    upload_folder=Config.UPLOAD_FOLDER,
    correlation_id=None,
):
    """Save, hash, sign, and register one Flask-uploaded file."""
    original_name = getattr(uploaded_file, "filename", None)
    if not isinstance(original_name, str) or not original_name.strip():
        raise ValueError("A file with a filename must be provided.")

    extension = normalize_original_extension(original_name)

    if not key_id:
        raise ValueError("A registered public key ID is required.")

    if isinstance(private_key_password, str):
        password_bytes = private_key_password.encode("utf-8")
    elif isinstance(private_key_password, bytes):
        password_bytes = private_key_password
    else:
        raise ValueError("The private-key password must be a string or bytes.")

    upload_root = Path(upload_folder)
    upload_root.mkdir(parents=True, exist_ok=True)
    upload_root = upload_root.resolve()

    stream = getattr(uploaded_file, "stream", None)
    if stream is None or not hasattr(stream, "read"):
        raise ValueError("The uploaded file does not have a readable stream.")

    saved_path = None
    connection = None
    cloud_resource_ids = ()
    record_committed = False
    correlation_id = correlation_id or new_registration_correlation_id()
    try:
        # Create the file exclusively so an existing file is never overwritten.
        while True:
            stored_name = f"{uuid4().hex}{extension}"
            file_path = (upload_root / stored_name).resolve()
            if file_path.parent != upload_root:
                raise ValueError("Generated upload path is outside the upload folder.")
            try:
                output_file = file_path.open("xb")
                saved_path = file_path
                break
            except FileExistsError:
                continue

        size_bytes = 0
        with output_file:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise ValueError("Uploaded file stream must return bytes.")
                size_bytes += len(chunk)
                if size_bytes > Config.MAX_FILE_SIZE:
                    raise ValueError("The uploaded file exceeds the 16 MB limit.")
                output_file.write(chunk)

        hashes = calculate_file_hashes(saved_path)
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        file_id = str(uuid4())

        connection = get_db_connection()
        with connection:
            key_row = connection.execute(
                "SELECT public_key_pem FROM public_keys WHERE key_id = ?",
                (key_id,),
            ).fetchone()
            if key_row is None:
                raise ValueError("The specified public key is not registered.")

            public_key = serialization.load_pem_public_key(key_row["public_key_pem"])
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("The registered public key must be an RSA key.")

            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            registered_key_id = hashlib.sha256(public_key_der).hexdigest()
            if registered_key_id != key_id:
                raise ValueError(
                    "The registered public key does not match the specified key ID."
                )

            signed_digest = combined_sha256_sha3_digest(
                hashes["sha256"], hashes["sha3_256"]
            )
            signature = sign_hash(
                signed_digest,
                private_key_path,
                password_bytes,
            )
            if not verify_signature_with_public_key(
                signed_digest, signature, public_key
            ):
                raise ValueError(
                    "The private key does not match the registered public key."
                )

            signature_artifact = (
                "CFIV-SIGNATURE-V1\n"
                f"scheme={COMBINED_SHA256_SHA3_V2_SCHEME}\n"
                f"signature={base64.b64encode(signature).decode('ascii')}\n"
            ).encode("utf-8")
            file_public_id, signature_public_id = upload_file_and_signature(
                saved_path, signature_artifact, correlation_id=correlation_id
            )
            cloud_resource_ids = (file_public_id, signature_public_id)

            # The staged local copy is only needed for the Cloudinary upload.
            # Remove it before committing metadata so a failed DB write cannot
            # leave a local orphan behind.
            try:
                saved_path.unlink()
            except OSError:
                log_registration_diagnostic(
                    correlation_id,
                    STAGE_LOCAL_CLEANUP,
                    "failure",
                    "filesystem_error",
                )
                raise
            saved_path = None
            log_registration_diagnostic(
                correlation_id, STAGE_LOCAL_CLEANUP, "success"
            )

            try:
                connection.execute(
                    """
                    INSERT INTO file_records (
                        file_id, original_name, stored_name, size_bytes,
                        sha256, sha3_256, signature, key_id, created_at,
                        storage_backend, cloudinary_file_public_id,
                        cloudinary_signature_public_id, signature_scheme
                    ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 'cloudinary', ?, ?, ?)
                    """,
                    (
                        file_id,
                        original_name,
                        size_bytes,
                        hashes["sha256"],
                        hashes["sha3_256"],
                        signature,
                        key_id,
                        created_at,
                        file_public_id,
                        signature_public_id,
                        COMBINED_SHA256_SHA3_V2_SCHEME,
                    ),
                )
                connection.commit()
            except sqlite3.Error:
                log_registration_diagnostic(
                    correlation_id,
                    STAGE_DATABASE_INSERTION,
                    "failure",
                    "database_error",
                )
                raise
            log_registration_diagnostic(
                correlation_id, STAGE_DATABASE_INSERTION, "success"
            )

        record_committed = True
        return {
            "file_id": file_id,
            "original_name": original_name,
            "size_bytes": size_bytes,
            "sha256": hashes["sha256"],
            "sha3_256": hashes["sha3_256"],
            "key_id": key_id,
            "created_at": created_at,
        }
    except Exception:
        cleanup_failed = False
        if cloud_resource_ids and not record_committed:
            for public_id in cloud_resource_ids:
                try:
                    delete_resource(public_id, correlation_id=correlation_id)
                except CloudStorageError:
                    cleanup_failed = True
        if saved_path is not None:
            try:
                saved_path.unlink(missing_ok=True)
            except OSError:
                cleanup_failed = True
                log_registration_diagnostic(
                    correlation_id,
                    STAGE_LOCAL_CLEANUP,
                    "failure",
                    "filesystem_error",
                )
            else:
                log_registration_diagnostic(
                    correlation_id, STAGE_LOCAL_CLEANUP, "success"
                )
        if cleanup_failed:
            raise RuntimeError(
                "Registration failed and created resources could not be fully removed."
            ) from None
        raise
    finally:
        if connection is not None:
            connection.close()
