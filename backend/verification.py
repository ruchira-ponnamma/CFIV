
"""File integrity verification helpers for CFIV."""

import base64
import binascii
import hashlib
import hmac
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.cloud_storage import download_original_file, download_signature_artifact
from backend.database import get_db_connection
from backend.hashing import calculate_file_hashes
from backend.signatures import (
    COMBINED_SHA256_SHA3_V2_SCHEME,
    SHA256_V1_SCHEME,
    combined_sha256_sha3_digest,
    verify_signature,
    verify_signature_with_public_key,
)
from backend.verification_history import record_verification_attempt
from config import Config


def _parse_signature_artifact(artifact):
    """Parse the exact UTF-8/LF signature artifact format used by CFIV."""
    if not isinstance(artifact, bytes):
        raise ValueError("The Cloudinary signature artifact is malformed.")
    try:
        text = artifact.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("The Cloudinary signature artifact is malformed.") from error

    if "\r" in text or not text.endswith("\n"):
        raise ValueError("The Cloudinary signature artifact is malformed.")
    lines = text[:-1].split("\n")
    if (
        len(lines) != 3
        or lines[0] != "CFIV-SIGNATURE-V1"
        or not lines[1].startswith("scheme=")
        or not lines[2].startswith("signature=")
    ):
        raise ValueError("The Cloudinary signature artifact is malformed.")

    scheme = lines[1][len("scheme="):]
    encoded_signature = lines[2][len("signature="):]
    try:
        scheme.encode("ascii")
        signature = base64.b64decode(encoded_signature, validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as error:
        raise ValueError("The Cloudinary signature artifact is malformed.") from error
    if (
        not scheme
        or not signature
        or base64.b64encode(signature).decode("ascii") != encoded_signature
    ):
        raise ValueError("The Cloudinary signature artifact is malformed.")
    return scheme, signature


def _build_verification_result(file_path, original_hashes, verifier):
    """Calculate hashes and combine them with a signature check."""
    current_hashes = calculate_file_hashes(file_path)

    sha256_match = hmac.compare_digest(
        current_hashes["sha256"], original_hashes["sha256"]
    )
    sha3_match = hmac.compare_digest(
        current_hashes["sha3_256"], original_hashes["sha3_256"]
    )
    signature_valid = verifier(current_hashes)

    return {
        "sha256_match": sha256_match,
        "sha3_256_match": sha3_match,
        "signature_valid": signature_valid,
        "integrity_verified": sha256_match and sha3_match and signature_valid,
        "current_hashes": current_hashes,
    }


def verify_file_integrity(
    file_path,
    original_hashes,
    signature,
    public_key_path
):
    """
    Verify file integrity using SHA-256, SHA3-256
    and RSA digital signature verification.

    Returns a dictionary containing individual
    verification results and the final status.
    """

    return _build_verification_result(
        file_path,
        original_hashes,
        lambda current_hashes: verify_signature(
            current_hashes["sha256"], signature, public_key_path
        ),
    )


def verify_registered_file(file_id):
    """Verify a stored upload using its database hashes, signature, and key."""
    connection = get_db_connection()
    try:
        file_record = connection.execute(
            """
            SELECT file_id, original_name, stored_name, sha256, sha3_256,
                   signature, signature_scheme, key_id, storage_backend,
                   cloudinary_file_public_id, cloudinary_signature_public_id
            FROM file_records
            WHERE file_id = ?
            """,
            (file_id,),
        ).fetchone()

        if file_record is None:
            raise LookupError(f"No file record found for file ID {file_id!r}.")

        key_record = connection.execute(
            "SELECT public_key_pem FROM public_keys WHERE key_id = ?",
            (file_record["key_id"],),
        ).fetchone()
        if key_record is None:
            raise LookupError(
                f"No registered public key found for key ID {file_record['key_id']!r}."
            )

        # Copy the needed values before closing the database connection.
        file_data = dict(file_record)
        public_key_pem = key_record["public_key_pem"]
    finally:
        connection.close()

    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as error:
        raise ValueError("The registered public key is malformed.") from error

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("The registered public key is not an RSA key.")

    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    calculated_key_id = hashlib.sha256(public_key_der).hexdigest()
    if not isinstance(file_data["key_id"], str) or not hmac.compare_digest(
        calculated_key_id, file_data["key_id"]
    ):
        raise ValueError("The registered public key fingerprint does not match its key ID.")

    signature_scheme = file_data["signature_scheme"]
    if signature_scheme not in {
        SHA256_V1_SCHEME,
        COMBINED_SHA256_SHA3_V2_SCHEME,
    }:
        raise ValueError("The registered file uses an unsupported signature scheme.")

    artifact_signature_matches = True

    def verifier(current_hashes):
        if not artifact_signature_matches:
            return False
        if signature_scheme == SHA256_V1_SCHEME:
            signed_digest = current_hashes["sha256"]
        else:
            signed_digest = combined_sha256_sha3_digest(
                current_hashes["sha256"], current_hashes["sha3_256"]
            )
        return verify_signature_with_public_key(
            signed_digest, file_data["signature"], public_key
        )

    original_hashes = {
        "sha256": file_data["sha256"],
        "sha3_256": file_data["sha3_256"],
    }
    storage_backend = file_data["storage_backend"]
    if storage_backend == "local":
        upload_root = Path(Config.UPLOAD_FOLDER).resolve()
        try:
            stored_path = (upload_root / file_data["stored_name"]).resolve(strict=True)
        except FileNotFoundError as error:
            raise FileNotFoundError("The stored upload file is missing.") from error
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            raise ValueError("The stored upload path is invalid.") from error

        if stored_path.parent != upload_root:
            raise ValueError("The stored upload path is outside the upload folder.")
        if not stored_path.is_file():
            raise FileNotFoundError("The stored upload file is missing or is not a file.")

        result = _build_verification_result(stored_path, original_hashes, verifier)
    elif storage_backend == "cloudinary":
        if not isinstance(file_data["signature"], bytes):
            raise ValueError("The registered signature data is malformed.")
        with TemporaryDirectory(prefix="cfiv-verify-") as temporary_directory:
            stored_path = Path(temporary_directory) / "download.bin"
            with stored_path.open("xb") as destination:
                download_original_file(
                    file_data["cloudinary_file_public_id"], destination
                )
            artifact = download_signature_artifact(
                file_data["cloudinary_signature_public_id"]
            )
            artifact_scheme, artifact_signature = _parse_signature_artifact(artifact)
            if artifact_scheme != signature_scheme:
                raise ValueError(
                    "The signature artifact scheme does not match the file record."
                )
            artifact_signature_matches = hmac.compare_digest(
                artifact_signature, file_data["signature"]
            )
            result = _build_verification_result(
                stored_path, original_hashes, verifier
            )
    else:
        raise ValueError("The registered file uses an unsupported storage backend.")

    result["file_id"] = file_data["file_id"]
    result["original_name"] = file_data["original_name"]
    result["attempt_id"] = record_verification_attempt(file_id, result)
    return result
