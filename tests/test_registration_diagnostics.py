"""Tests for allow-listed, development-only registration diagnostics."""

import io
import logging
import os
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from cloudinary.exceptions import (
    AlreadyExists,
    AuthorizationRequired,
    BadRequest,
    GeneralError,
    Locked,
    NotAcceptable,
    NotAllowed,
    NotFound,
    RateLimited,
)
from cloudinary.api_client.execute_request import EXCEPTION_CODES

from backend import registration_diagnostics
from backend.registration_diagnostics import (
    STAGE_CLOUDINARY_CLEANUP,
    STAGE_CLOUDINARY_CONFIGURATION,
    STAGE_DATABASE_INSERTION,
    STAGE_LOCAL_CLEANUP,
    STAGE_ORIGINAL_UPLOAD,
    STAGE_SIGNATURE_UPLOAD,
    log_registration_diagnostic,
    log_registration_exception,
    new_registration_correlation_id,
    classify_registration_exception,
)


class RegistrationDiagnosticsTests(unittest.TestCase):
    def test_status_mapping_matches_installed_cloudinary_sdk(self):
        for exception_class, expected_status in registration_diagnostics._STATUS_BY_EXCEPTION_CLASS.items():
            with self.subTest(exception_class=exception_class.__name__):
                actual_statuses = [
                    status
                    for status, mapped_class in EXCEPTION_CODES.items()
                    if mapped_class is exception_class
                ]
                self.assertEqual(actual_statuses, [expected_status])

        for exception_class in (RateLimited, GeneralError):
            actual_statuses = [
                status
                for status, mapped_class in EXCEPTION_CODES.items()
                if mapped_class is exception_class
            ]
            self.assertGreater(len(actual_statuses), 1)
            self.assertIsNone(
                classify_registration_exception(
                    exception_class("opaque message")
                )[1]
            )

    def test_installed_cloudinary_exceptions_map_to_allowlisted_categories(self):
        known_errors = (
            (AuthorizationRequired("hidden provider details"), "provider_authentication_error", 401),
            (NotAllowed("hidden provider details"), "provider_permission_error", 403),
            (RateLimited("hidden provider details"), "provider_rate_limit_error", None),
            (GeneralError("hidden provider details"), "provider_server_error", None),
            (BadRequest("hidden provider details"), "provider_validation_error", 400),
            (NotFound("hidden provider details"), "provider_not_found_error", 404),
            (NotAcceptable("hidden provider details"), "provider_request_error", 406),
            (AlreadyExists("hidden provider details"), "provider_conflict_error", 409),
            (Locked("hidden provider details"), "provider_request_error", 423),
            (ValueError("sensitive local SDK detail"), "sdk_validation_error", None),
            (PermissionError("sensitive local path"), "local_io_error", None),
            (RuntimeError("sensitive unknown detail"), "unknown_error", None),
        )

        for error, expected_category, expected_status in known_errors:
            with self.subTest(error_type=type(error).__name__):
                self.assertEqual(
                    classify_registration_exception(error),
                    (expected_category, expected_status),
                )

    def test_general_error_with_sdk_network_context_is_classified_as_network(self):
        error = GeneralError("opaque provider text")
        error.__cause__ = TimeoutError("network detail")

        self.assertEqual(
            classify_registration_exception(error), ("network_error", None)
        )

    def test_exception_logging_omits_messages_and_only_logs_reliable_status(self):
        correlation_id = "d" * 32
        error = AuthorizationRequired(
            "api_secret=not-for-logs signed_url=https://private.invalid token=hidden"
        )

        with patch.dict(os.environ, {"CFIV_ENV": "development"}):
            with self.assertLogs("cfiv.registration", level="INFO") as captured:
                log_registration_exception(
                    correlation_id, STAGE_ORIGINAL_UPLOAD, error
                )

        output = "\n".join(captured.output)
        self.assertIn("error_category=provider_authentication_error", output)
        self.assertIn("http_status=401", output)
        for forbidden in ("api_secret", "private.invalid", "token=hidden"):
            self.assertNotIn(forbidden, output)

        ambiguous_error = RateLimited("private provider detail")
        with patch.dict(os.environ, {"CFIV_ENV": "development"}):
            with self.assertLogs("cfiv.registration", level="INFO") as captured:
                log_registration_exception(
                    correlation_id, STAGE_ORIGINAL_UPLOAD, ambiguous_error
                )
        self.assertNotIn("http_status=", "\n".join(captured.output))

    def test_development_info_logs_reach_terminal_once_and_are_disabled_elsewhere(self):
        logger = logging.getLogger("cfiv.registration")
        previous_handlers = logger.handlers[:]
        previous_level = logger.level
        previous_propagate = logger.propagate
        previous_disabled = logger.disabled
        logger.handlers = []
        try:
            terminal = io.StringIO()
            with patch.dict(os.environ, {"CFIV_ENV": "development"}):
                with redirect_stderr(terminal):
                    for _ in range(2):
                        log_registration_diagnostic(
                            "c" * 32,
                            STAGE_ORIGINAL_UPLOAD,
                            "failure",
                            "cloudinary_error",
                        )
                    diagnostic_handlers = [
                        handler
                        for handler in logger.handlers
                        if getattr(
                            handler,
                            registration_diagnostics._HANDLER_MARKER,
                            False,
                        )
                    ]
                self.assertEqual(len(diagnostic_handlers), 1)
                self.assertEqual(terminal.getvalue().count("registration_diagnostic"), 2)
                self.assertIn("stage=original_file_upload", terminal.getvalue())
                self.assertEqual(logger.level, logging.INFO)
                self.assertFalse(logger.propagate)
                self.assertFalse(logger.disabled)

            terminal = io.StringIO()
            with patch.dict(os.environ, {"CFIV_ENV": "production"}):
                with redirect_stderr(terminal):
                    log_registration_diagnostic(
                        "c" * 32,
                        STAGE_ORIGINAL_UPLOAD,
                        "failure",
                        "cloudinary_error",
                    )
                self.assertEqual(terminal.getvalue(), "")
                self.assertTrue(logger.disabled)
        finally:
            logger.handlers = previous_handlers
            logger.setLevel(previous_level)
            logger.propagate = previous_propagate
            logger.disabled = previous_disabled

    def test_all_fixed_stages_log_only_safe_fields_in_development(self):
        correlation_id = new_registration_correlation_id()
        stages = (
            STAGE_CLOUDINARY_CONFIGURATION,
            STAGE_ORIGINAL_UPLOAD,
            STAGE_SIGNATURE_UPLOAD,
            STAGE_CLOUDINARY_CLEANUP,
            STAGE_DATABASE_INSERTION,
            STAGE_LOCAL_CLEANUP,
        )
        sensitive_detail = "api_secret=secret password=private /sensitive/path"

        with patch.dict(os.environ, {"CFIV_ENV": "development"}):
            with self.assertLogs("cfiv.registration", level="INFO") as captured:
                for stage in stages:
                    log_registration_diagnostic(
                        correlation_id,
                        stage,
                        "failure",
                        "cloudinary_error",
                    )
                log_registration_diagnostic(
                    sensitive_detail,
                    STAGE_ORIGINAL_UPLOAD,
                    "failure",
                    sensitive_detail,
                )

        output = "\n".join(captured.output)
        self.assertEqual(len(captured.records), len(stages) + 1)
        for stage in stages:
            self.assertIn(f"stage={stage}", output)
        self.assertIn(f"correlation_id={correlation_id}", output)
        self.assertIn("status=failure", output)
        self.assertIn("error_category=unexpected_error", output)
        for forbidden in ("api_secret", "password=", "/sensitive/path", "private"):
            self.assertNotIn(forbidden, output)

    def test_non_development_environment_disables_diagnostics(self):
        with patch.dict(os.environ, {"CFIV_ENV": "production"}):
            with self.assertNoLogs("cfiv.registration", level="INFO"):
                log_registration_diagnostic(
                    "a" * 32,
                    STAGE_DATABASE_INSERTION,
                    "failure",
                    "database_error",
                )

    def test_correlation_id_is_random_and_non_sensitive(self):
        first_id = new_registration_correlation_id()
        second_id = new_registration_correlation_id()

        self.assertEqual(len(first_id), 32)
        self.assertEqual(len(second_id), 32)
        self.assertNotEqual(first_id, second_id)
        self.assertTrue(all(character in "0123456789abcdef" for character in first_id))


if __name__ == "__main__":
    unittest.main()
