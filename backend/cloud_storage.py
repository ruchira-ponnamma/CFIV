"""Private raw-resource storage helpers for Cloudinary."""

import io
import os
import re
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4
from importlib.metadata import PackageNotFoundError, version

import cloudinary
from cloudinary import uploader, utils
from cloudinary.exceptions import Error as CloudinaryAPIError

import config as application_config  # Loads the project's .env before env reads.
from backend.registration_diagnostics import (
    STAGE_CLOUDINARY_CLEANUP,
    STAGE_CLOUDINARY_CONFIGURATION,
    STAGE_ORIGINAL_UPLOAD,
    STAGE_SIGNATURE_UPLOAD,
    log_cloudinary_request,
    log_registration_diagnostic,
    log_registration_exception,
)


_SUPPORTED_ORIGINAL_EXTENSIONS = frozenset(
    {".txt", ".csv", ".pdf", ".docx", ".xlsx", ".pptx", ".jpg", ".jpeg", ".png"}
)
_ORIGINAL_EXTENSION_PATTERN = re.compile(r"\.[a-z0-9]{1,10}\Z")
_STAGED_FILENAME_PATTERN = re.compile(r"[0-9a-f]{32}\.[a-z0-9]{1,10}\Z")
_PUBLIC_ID_PATTERN = re.compile(
    r"^cfiv/(?:files/[0-9a-f]{32}(?:\.bin|\.csv|\.docx|\.jpeg|\.jpg|\.pdf|\.png|\.pptx|\.txt|\.xlsx)|signatures/[0-9a-f]{32}\.txt)$"
)
_SIGNATURE_ARTIFACT_MAX_BYTES = 16 * 1024
_DOWNLOAD_CHUNK_SIZE = 64 * 1024
_UPLOAD_CHUNK_SIZE = 6 * 1024 * 1024
_DOWNLOAD_TIMEOUT_SECONDS = 30
_DOWNLOAD_URL_TTL_SECONDS = 60
_PINNED_CLOUDINARY_VERSION = "1.47.0"
_UPLOAD_DIAGNOSTICS_LOCK = threading.RLock()


class _UploadRequestDiagnosticConnector:
    """Transparent connector proxy that logs only response status and ID."""

    _cfiv_upload_diagnostics_connector = True

    def __init__(self, connector, correlation_id, stage):
        self._connector = connector
        self._correlation_id = correlation_id
        self._stage = stage

    def __getattr__(self, name):
        return getattr(self._connector, name)

    def request(self, *args, **kwargs):
        response = self._connector.request(*args, **kwargs)
        try:
            status = getattr(response, "status", None)
            headers = getattr(response, "headers", None)
            request_id = headers.get("x-request-id") if headers is not None else None
            log_cloudinary_request(
                self._correlation_id, self._stage, status, request_id
            )
        except Exception:
            # Diagnostic inspection must never change upload behavior.
            pass
        return response


@contextmanager
def _upload_request_diagnostics(correlation_id, stage):
    """Temporarily wrap the pinned SDK connector in local development only."""
    if os.environ.get("CFIV_ENV", "").strip().lower() != "development":
        yield
        return

    with _UPLOAD_DIAGNOSTICS_LOCK:
        try:
            sdk_version = version("cloudinary")
        except PackageNotFoundError:
            yield
            return

        connector = getattr(uploader, "_http", None)
        if (
            sdk_version != _PINNED_CLOUDINARY_VERSION
            or connector is None
            or not callable(getattr(connector, "request", None))
            or isinstance(connector, _UploadRequestDiagnosticConnector)
        ):
            yield
            return

        proxy = _UploadRequestDiagnosticConnector(connector, correlation_id, stage)
        try:
            uploader._http = proxy
            yield
        finally:
            uploader._http = connector


class CloudStorageError(RuntimeError):
    """A sanitized Cloudinary operation failure safe for application handling."""


class CloudStorageConfigurationError(CloudStorageError):
    """Cloudinary credentials are missing from the server environment."""


def _configure_cloudinary(correlation_id=None):
    """Configure the SDK from dotenv-loaded environment variables."""
    credentials = {
        "cloud_name": os.environ.get("CLOUDINARY_CLOUD_NAME"),
        "api_key": os.environ.get("CLOUDINARY_API_KEY"),
        "api_secret": os.environ.get("CLOUDINARY_API_SECRET"),
    }
    if any(not isinstance(value, str) or not value.strip() for value in credentials.values()):
        log_registration_diagnostic(
            correlation_id,
            STAGE_CLOUDINARY_CONFIGURATION,
            "failure",
            "configuration_error",
        )
        raise CloudStorageConfigurationError(
            "Cloudinary storage is not configured on this server."
        )

    try:
        cloudinary.config(**credentials, secure=True)
    except Exception:
        log_registration_diagnostic(
            correlation_id,
            STAGE_CLOUDINARY_CONFIGURATION,
            "failure",
            "configuration_error",
        )
        raise CloudStorageConfigurationError(
            "Cloudinary storage could not be configured on this server."
        ) from None
    log_registration_diagnostic(
        correlation_id, STAGE_CLOUDINARY_CONFIGURATION, "success"
    )


def normalize_original_extension(original_name):
    """Return a supported lowercase extension without trusting the supplied path."""
    if not isinstance(original_name, str) or not original_name:
        raise ValueError("Choose a file with a supported extension.")

    basename = original_name.replace("\\", "/").rsplit("/", 1)[-1]
    extension = Path(basename).suffix.lower()
    if (
        not _ORIGINAL_EXTENSION_PATTERN.fullmatch(extension)
        or extension not in _SUPPORTED_ORIGINAL_EXTENSIONS
    ):
        raise ValueError("Choose a file with a supported extension.")
    return extension


def _new_public_id(kind, extension=None):
    """Generate a Cloudinary public ID without using a user filename or path."""
    identifier = uuid4().hex
    if kind == "file":
        if (
            not isinstance(extension, str)
            or not _ORIGINAL_EXTENSION_PATTERN.fullmatch(extension)
            or extension not in _SUPPORTED_ORIGINAL_EXTENSIONS
        ):
            raise ValueError("The original file extension is invalid.")
        return f"cfiv/files/{identifier}{extension}"
    if kind == "signature":
        return f"cfiv/signatures/{identifier}.txt"
    raise ValueError("Unsupported Cloudinary resource kind.")


def _validate_public_id(public_id):
    if not isinstance(public_id, str) or not _PUBLIC_ID_PATTERN.fullmatch(public_id):
        raise ValueError("The Cloudinary resource identifier is invalid.")
    return public_id


def _destroy_resource(public_id):
    """Delete a known generated ID; never return provider response details."""
    _validate_public_id(public_id)
    result = uploader.destroy(
        public_id,
        resource_type="raw",
        type="authenticated",
        invalidate=True,
    )
    if not isinstance(result, dict) or result.get("result") not in {
        "ok", "deleted", "not found"
    }:
        raise CloudStorageError("Cloudinary resource cleanup could not be confirmed.")
    return result.get("result") != "not found"


def _upload_resource(
    source, *, kind, chunked, extension=None, correlation_id=None
):
    stage = STAGE_ORIGINAL_UPLOAD if kind == "file" else STAGE_SIGNATURE_UPLOAD
    try:
        _configure_cloudinary(correlation_id)
    except CloudStorageError:
        log_registration_diagnostic(
            correlation_id, stage, "failure", "configuration_error"
        )
        raise
    public_id = _new_public_id(kind, extension=extension)
    options = {
        "resource_type": "raw",
        "type": "authenticated",
        "public_id": public_id,
        "use_filename": False,
        "unique_filename": False,
        "overwrite": False,
        "discard_original_filename": True,
    }

    try:
        with _upload_request_diagnostics(correlation_id, stage):
            if chunked:
                result = uploader.upload_large(
                    source,
                    chunk_size=_UPLOAD_CHUNK_SIZE,
                    filename=source.name,
                    **options,
                )
            else:
                result = uploader.upload(source, **options)
    except (CloudinaryAPIError, OSError, ValueError) as error:
        log_registration_exception(correlation_id, stage, error)
        try:
            _destroy_resource(public_id)
        except (CloudinaryAPIError, CloudStorageError, OSError, ValueError):
            log_registration_diagnostic(
                correlation_id,
                STAGE_CLOUDINARY_CLEANUP,
                "failure",
                "cleanup_error",
            )
            raise CloudStorageError(
                "Cloudinary upload failed and cleanup could not be confirmed."
            ) from None
        log_registration_diagnostic(
            correlation_id, STAGE_CLOUDINARY_CLEANUP, "success"
        )
        raise CloudStorageError("Cloudinary upload failed.") from None

    except Exception as error:
        log_registration_exception(correlation_id, stage, error)
        try:
            _destroy_resource(public_id)
        except Exception:
            log_registration_diagnostic(
                correlation_id,
                STAGE_CLOUDINARY_CLEANUP,
                "failure",
                "cleanup_error",
            )
            raise CloudStorageError(
                "Cloudinary upload failed and cleanup could not be confirmed."
            ) from None
        log_registration_diagnostic(
            correlation_id, STAGE_CLOUDINARY_CLEANUP, "success"
        )
        raise CloudStorageError("Cloudinary upload failed.") from None

    if (
        not isinstance(result, dict)
        or result.get("public_id") != public_id
        or result.get("resource_type") != "raw"
        or result.get("type") != "authenticated"
    ):
        log_registration_diagnostic(
            correlation_id, stage, "failure", "cloudinary_error"
        )
        try:
            _destroy_resource(public_id)
        except (CloudinaryAPIError, CloudStorageError, OSError, ValueError):
            log_registration_diagnostic(
                correlation_id,
                STAGE_CLOUDINARY_CLEANUP,
                "failure",
                "cleanup_error",
            )
            raise CloudStorageError(
                "Cloudinary upload returned an invalid result and cleanup could not be confirmed."
            ) from None
        log_registration_diagnostic(
            correlation_id, STAGE_CLOUDINARY_CLEANUP, "success"
        )
        raise CloudStorageError("Cloudinary upload returned an invalid result.")

    # Return only the generated identifier. In particular, never return SDK URLs.
    log_registration_diagnostic(correlation_id, stage, "success")
    return public_id


def upload_original_file(source_path, *, correlation_id=None):
    """Upload a local staged file as an authenticated raw resource in chunks."""
    try:
        path = Path(source_path).resolve(strict=True)
        if not path.is_file():
            raise ValueError
        extension = path.suffix.lower()
        if (
            not _ORIGINAL_EXTENSION_PATTERN.fullmatch(extension)
            or extension not in _SUPPORTED_ORIGINAL_EXTENSIONS
            or not _STAGED_FILENAME_PATTERN.fullmatch(path.name)
        ):
            raise ValueError
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ValueError("A readable staged file is required for Cloudinary upload.") from None
    return _upload_resource(
        path,
        kind="file",
        chunked=True,
        extension=extension,
        correlation_id=correlation_id,
    )


def upload_signature_artifact(artifact, *, correlation_id=None):
    """Upload a small signature artifact as a separate authenticated raw resource."""
    if not isinstance(artifact, bytes) or not artifact:
        raise ValueError("A non-empty signature artifact is required.")
    if len(artifact) > _SIGNATURE_ARTIFACT_MAX_BYTES:
        raise ValueError("The signature artifact exceeds the allowed size.")
    return _upload_resource(
        io.BytesIO(artifact),
        kind="signature",
        chunked=False,
        correlation_id=correlation_id,
    )


def upload_file_and_signature(
    source_path, signature_artifact, *, correlation_id=None
):
    """Upload both resources, removing the original if its signature upload fails."""
    original_public_id = upload_original_file(
        source_path, correlation_id=correlation_id
    )
    try:
        signature_public_id = upload_signature_artifact(
            signature_artifact, correlation_id=correlation_id
        )
    except (CloudStorageError, ValueError):
        try:
            delete_resource(original_public_id, correlation_id=correlation_id)
        except CloudStorageError:
            log_registration_diagnostic(
                correlation_id,
                STAGE_CLOUDINARY_CLEANUP,
                "failure",
                "cleanup_error",
            )
            raise CloudStorageError(
                "Cloudinary upload failed and partial-upload cleanup could not be confirmed."
            ) from None
        log_registration_diagnostic(
            correlation_id, STAGE_CLOUDINARY_CLEANUP, "success"
        )
        raise CloudStorageError(
            "Cloudinary signature upload failed; the original upload was removed."
        ) from None
    return original_public_id, signature_public_id


def delete_resource(public_id, *, correlation_id=None):
    """Delete one generated authenticated raw resource by its stored public ID."""
    try:
        _configure_cloudinary(correlation_id)
        deleted = _destroy_resource(public_id)
    except Exception:
        log_registration_diagnostic(
            correlation_id,
            STAGE_CLOUDINARY_CLEANUP,
            "failure",
            "cleanup_error",
        )
        raise CloudStorageError("Cloudinary resource deletion failed.") from None
    log_registration_diagnostic(
        correlation_id, STAGE_CLOUDINARY_CLEANUP, "success"
    )
    return deleted


def _download_raw_to_stream(public_id, file_format, destination, max_bytes):
    _validate_public_id(public_id)
    if not all(callable(getattr(destination, method, None)) for method in ("write", "tell", "seek", "truncate")):
        raise ValueError("A seekable binary destination is required.")
    start_position = destination.tell()
    _configure_cloudinary()

    try:
        signed_url = utils.private_download_url(
            public_id,
            file_format,
            resource_type="raw",
            type="authenticated",
            expires_at=int(time.time()) + _DOWNLOAD_URL_TTL_SECONDS,
            attachment=True,
            secure=True,
        )
        transferred = 0
        with urllib.request.urlopen(
            signed_url, timeout=_DOWNLOAD_TIMEOUT_SECONDS
        ) as response:
            status = getattr(response, "status", response.getcode())
            if status != 200:
                raise CloudStorageError("Cloudinary resource retrieval failed.")
            while True:
                chunk = response.read(_DOWNLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                transferred += len(chunk)
                if transferred > max_bytes:
                    raise CloudStorageError("Cloudinary resource exceeds the allowed size.")
                destination.write(chunk)
        return transferred
    except CloudStorageError:
        _clear_partial_download(destination, start_position)
        raise
    except (CloudinaryAPIError, OSError, urllib.error.URLError, ValueError) as error:
        _clear_partial_download(destination, start_position)
        raise CloudStorageError("Cloudinary resource retrieval failed.") from None
    except Exception:
        # Do not allow unexpected HTTP/SDK exception text (or the signed URL
        # held in this frame) to reach Flask's error page or application logs.
        _clear_partial_download(destination, start_position)
        raise CloudStorageError("Cloudinary resource retrieval failed.") from None


def _clear_partial_download(destination, start_position):
    try:
        destination.seek(start_position)
        destination.truncate()
    except Exception:
        raise CloudStorageError(
            "Cloudinary retrieval failed and partial output could not be cleared."
        ) from None


def download_original_file(public_id, destination):
    """Stream an authenticated raw original into a caller-owned binary stream."""
    _validate_public_id(public_id)
    file_format = public_id.rsplit(".", 1)[1]
    return _download_raw_to_stream(
        public_id,
        file_format,
        destination,
        application_config.Config.MAX_FILE_SIZE,
    )


def download_signature_artifact(public_id):
    """Retrieve a bounded signature artifact as bytes from its generated ID."""
    destination = io.BytesIO()
    _download_raw_to_stream(
        public_id,
        "txt",
        destination,
        _SIGNATURE_ARTIFACT_MAX_BYTES,
    )
    return destination.getvalue()
