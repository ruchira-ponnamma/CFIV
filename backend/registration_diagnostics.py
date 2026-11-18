"""Allow-listed development-only diagnostics for registration stages."""

import logging
import os
import re
from uuid import uuid4

from cloudinary.exceptions import (
    AlreadyExists,
    AuthorizationRequired,
    BadRequest,
    Error as CloudinaryAPIError,
    GeneralError,
    Locked,
    NotAcceptable,
    NotAllowed,
    NotFound,
    RateLimited,
)
from urllib3.exceptions import HTTPError as Urllib3HTTPError


logger = logging.getLogger("cfiv.registration")
_HANDLER_MARKER = "_cfiv_registration_diagnostics_handler"

STAGE_CLOUDINARY_CONFIGURATION = "cloudinary_configuration"
STAGE_ORIGINAL_UPLOAD = "original_file_upload"
STAGE_SIGNATURE_UPLOAD = "signature_artifact_upload"
STAGE_CLOUDINARY_CLEANUP = "cloudinary_cleanup"
STAGE_DATABASE_INSERTION = "database_insertion"
STAGE_LOCAL_CLEANUP = "local_staging_file_cleanup"

_STAGES = {
    STAGE_CLOUDINARY_CONFIGURATION,
    STAGE_ORIGINAL_UPLOAD,
    STAGE_SIGNATURE_UPLOAD,
    STAGE_CLOUDINARY_CLEANUP,
    STAGE_DATABASE_INSERTION,
    STAGE_LOCAL_CLEANUP,
}
_STATUSES = {"success", "failure"}
_ERROR_CATEGORIES = {
    "configuration_error",
    "cloudinary_error",
    "cleanup_error",
    "database_error",
    "filesystem_error",
    "local_io_error",
    "network_error",
    "provider_authentication_error",
    "provider_conflict_error",
    "provider_not_found_error",
    "provider_permission_error",
    "provider_rate_limit_error",
    "provider_request_error",
    "provider_server_error",
    "provider_validation_error",
    "sdk_validation_error",
    "unexpected_error",
}
_CORRELATION_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_STATUS_BY_EXCEPTION_CLASS = {
    BadRequest: 400,
    AuthorizationRequired: 401,
    NotAllowed: 403,
    NotFound: 404,
    NotAcceptable: 406,
    AlreadyExists: 409,
    Locked: 423,
}
_CATEGORY_BY_EXCEPTION_CLASS = {
    BadRequest: "provider_validation_error",
    AuthorizationRequired: "provider_authentication_error",
    NotAllowed: "provider_permission_error",
    NotFound: "provider_not_found_error",
    NotAcceptable: "provider_request_error",
    AlreadyExists: "provider_conflict_error",
    RateLimited: "provider_rate_limit_error",
    Locked: "provider_request_error",
}


def new_registration_correlation_id():
    """Return a random, non-sensitive identifier for one registration attempt."""
    return uuid4().hex


def classify_registration_exception(error):
    """Map installed-SDK exception types to safe categories and reliable status."""
    if isinstance(error, Urllib3HTTPError):
        return "network_error", None
    if isinstance(error, (TimeoutError, ConnectionError, BrokenPipeError)):
        return "network_error", None
    if isinstance(error, (FileNotFoundError, PermissionError)):
        return "local_io_error", None
    if isinstance(error, OSError):
        return "local_io_error", None
    if isinstance(error, ValueError):
        return "sdk_validation_error", None

    error_class = type(error)
    category = _CATEGORY_BY_EXCEPTION_CLASS.get(error_class)
    if category is not None:
        return category, _STATUS_BY_EXCEPTION_CLASS.get(error_class)

    if error_class is GeneralError:
        context = error.__cause__ or error.__context__
        had_context = context is not None
        while context is not None:
            if isinstance(context, (Urllib3HTTPError, OSError)):
                return "network_error", None
            context = context.__cause__ or context.__context__
        if had_context:
            return "unknown_error", None
        # GeneralError also represents both HTTP 500 and 503; omit status.
        return "provider_server_error", None

    if error_class is CloudinaryAPIError:
        return "unknown_error", None
    return "unknown_error", None


def log_registration_diagnostic(
    correlation_id, stage, status, error_category=None, http_status=None
):
    """Log only fixed categories, and only in explicit local development."""
    if os.environ.get("CFIV_ENV", "").strip().lower() != "development":
        logger.disabled = True
        logger.setLevel(logging.WARNING)
        return
    _configure_diagnostic_logger()
    if not isinstance(stage, str) or stage not in _STAGES:
        return
    if not isinstance(status, str) or status not in _STATUSES:
        return
    if not isinstance(error_category, str) and error_category is not None:
        error_category = "unexpected_error"
    elif error_category is not None and error_category not in _ERROR_CATEGORIES:
        error_category = "unexpected_error"
    if http_status not in _STATUS_BY_EXCEPTION_CLASS.values() and http_status is not None:
        http_status = None
    if (
        not isinstance(correlation_id, str)
        or not _CORRELATION_ID_PATTERN.fullmatch(correlation_id)
    ):
        correlation_id = "invalid-correlation-id"

    message = (
        "registration_diagnostic correlation_id=%s stage=%s status=%s "
        "error_category=%s"
    )
    values = (correlation_id, stage, status, error_category or "none")
    if http_status is not None:
        message += " http_status=%s"
        values += (http_status,)
    logger.info(message, *values)


def log_registration_exception(correlation_id, stage, error):
    """Log only a classified exception category and SDK-mapped HTTP status."""
    category, http_status = classify_registration_exception(error)
    log_registration_diagnostic(
        correlation_id,
        stage,
        "failure",
        category,
        http_status=http_status,
    )


def log_cloudinary_request(correlation_id, stage, http_status, request_id=None):
    """Log only safe response identifiers from a development upload request."""
    if os.environ.get("CFIV_ENV", "").strip().lower() != "development":
        return
    if stage not in {STAGE_ORIGINAL_UPLOAD, STAGE_SIGNATURE_UPLOAD}:
        return
    if type(http_status) is not int or not 100 <= http_status <= 599:
        return
    if (
        not isinstance(correlation_id, str)
        or not _CORRELATION_ID_PATTERN.fullmatch(correlation_id)
    ):
        correlation_id = "invalid-correlation-id"
    if not isinstance(request_id, str) or not _REQUEST_ID_PATTERN.fullmatch(request_id):
        request_id = None

    _configure_diagnostic_logger()
    message = (
        "cloudinary_request correlation_id=%s stage=%s http_status=%s"
    )
    values = (correlation_id, stage, http_status)
    if request_id is not None:
        message += " request_id=%s"
        values += (request_id,)
    logger.info(message, *values)


def _configure_diagnostic_logger():
    """Send development diagnostics to the terminal without duplicate output."""
    logger.disabled = False
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if any(getattr(handler, _HANDLER_MARKER, False) for handler in logger.handlers):
        return

    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    setattr(handler, _HANDLER_MARKER, True)
    logger.addHandler(handler)
