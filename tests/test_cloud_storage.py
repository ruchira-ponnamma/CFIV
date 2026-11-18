"""Isolated tests for the Cloudinary raw-resource storage service."""

import io
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from cloudinary.exceptions import Error as CloudinaryAPIError

from backend import cloud_storage


class FakeDownloadResponse:
    def __init__(self, payload, status=200):
        self.payload = io.BytesIO(payload)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.payload.close()

    def read(self, size=-1):
        return self.payload.read(size)

    def getcode(self):
        return self.status


class DiagnosticHTTPResponse:
    """Response mock that fails if diagnostic code touches its body."""

    def __init__(self, status, request_id=None):
        self.status = status
        self.headers = {}
        if request_id is not None:
            self.headers["x-request-id"] = request_id

    @property
    def data(self):
        raise AssertionError("Diagnostic wrapper must not inspect response bodies")


class CloudStorageTests(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(
            os.environ,
            {
                "CLOUDINARY_CLOUD_NAME": "test-cloud-name",
                "CLOUDINARY_API_KEY": "test-api-key",
                "CLOUDINARY_API_SECRET": "test-api-secret",
            },
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

        self.config_patch = patch("backend.cloud_storage.cloudinary.config")
        self.cloudinary_config = self.config_patch.start()
        self.addCleanup(self.config_patch.stop)

    @staticmethod
    def upload_result(public_id):
        return {
            "public_id": public_id,
            "resource_type": "raw",
            "type": "authenticated",
        }

    def test_original_upload_uses_generated_id_and_private_raw_chunk_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / f"{cloud_storage.uuid4().hex}.txt"
            source.write_bytes(b"file payload")
            uploader_patch = patch("backend.cloud_storage.uploader.upload_large")
            upload = uploader_patch.start()
            self.addCleanup(uploader_patch.stop)
            upload.side_effect = lambda path, **options: self.upload_result(
                options["public_id"]
            )

            public_id = cloud_storage.upload_original_file(source)

        self.assertRegex(public_id, r"^cfiv/files/[0-9a-f]{32}\.txt$")
        upload.assert_called_once()
        args, options = upload.call_args
        self.assertEqual(options["filename"], source.name)
        self.assertEqual(args[0].name, source.name)
        self.assertEqual(options["public_id"], public_id)
        self.assertEqual(options["resource_type"], "raw")
        self.assertEqual(options["type"], "authenticated")
        self.assertEqual(options["public_id"], public_id)
        self.assertEqual(options["chunk_size"], 6 * 1024 * 1024)
        self.assertFalse(options["use_filename"])
        self.assertFalse(options["unique_filename"])
        self.assertFalse(options["overwrite"])
        self.assertTrue(options["discard_original_filename"])
        self.assertNotIn("url", options)
        self.cloudinary_config.assert_called_once_with(
            cloud_name="test-cloud-name",
            api_key="test-api-key",
            api_secret="test-api-secret",
            secure=True,
        )

    def test_original_public_ids_use_only_validated_extensions(self):
        for extension in cloud_storage._SUPPORTED_ORIGINAL_EXTENSIONS:
            with self.subTest(extension=extension):
                public_id = cloud_storage._new_public_id("file", extension)
                self.assertRegex(
                    public_id,
                    rf"^cfiv/files/[0-9a-f]{{32}}{re.escape(extension)}$",
                )
                self.assertTrue(cloud_storage._validate_public_id(public_id))

        with self.assertRaises(ValueError):
            cloud_storage._new_public_id("file", ".exe")
        with self.assertRaises(ValueError):
            cloud_storage._validate_public_id(
                f"cfiv/files/{'a' * 32}.exe"
            )

    def test_signature_upload_uses_separate_authenticated_raw_resource(self):
        upload_patch = patch("backend.cloud_storage.uploader.upload")
        upload = upload_patch.start()
        self.addCleanup(upload_patch.stop)
        upload.side_effect = lambda stream, **options: self.upload_result(
            options["public_id"]
        )

        public_id = cloud_storage.upload_signature_artifact(b"scheme=sha256-v1\n")

        self.assertRegex(public_id, r"^cfiv/signatures/[0-9a-f]{32}\.txt$")
        stream, options = upload.call_args.args[0], upload.call_args.kwargs
        self.assertEqual(stream.read(), b"scheme=sha256-v1\n")
        self.assertEqual(options["resource_type"], "raw")
        self.assertEqual(options["type"], "authenticated")
        self.assertEqual(options["public_id"], public_id)

    def test_downloads_original_to_stream_and_returns_signature_bytes(self):
        url_patch = patch(
            "backend.cloud_storage.utils.private_download_url",
            return_value="https://signed.invalid/resource?token=private-test-token",
        )
        make_url = url_patch.start()
        self.addCleanup(url_patch.stop)
        response = FakeDownloadResponse(b"cloud file bytes")
        urlopen_patch = patch("backend.cloud_storage.urllib.request.urlopen", return_value=response)
        urlopen = urlopen_patch.start()
        self.addCleanup(urlopen_patch.stop)

        output = io.BytesIO()
        size = cloud_storage.download_original_file(
            "cfiv/files/0123456789abcdef0123456789abcdef.bin", output
        )
        self.assertEqual(size, len(b"cloud file bytes"))
        self.assertEqual(output.getvalue(), b"cloud file bytes")

        signature_response = FakeDownloadResponse(b"signature artifact")
        urlopen.return_value = signature_response
        signature = cloud_storage.download_signature_artifact(
            "cfiv/signatures/0123456789abcdef0123456789abcdef.txt"
        )
        self.assertEqual(signature, b"signature artifact")
        self.assertEqual(make_url.call_count, 2)
        make_url.assert_has_calls(
            [
                call(
                    "cfiv/files/0123456789abcdef0123456789abcdef.bin",
                    "bin",
                    resource_type="raw",
                    type="authenticated",
                    expires_at=unittest.mock.ANY,
                    attachment=True,
                    secure=True,
                ),
                call(
                    "cfiv/signatures/0123456789abcdef0123456789abcdef.txt",
                    "txt",
                    resource_type="raw",
                    type="authenticated",
                    expires_at=unittest.mock.ANY,
                    attachment=True,
                    secure=True,
                ),
            ]
        )

    def test_download_uses_public_id_extension_and_legacy_bin_still_works(self):
        url_patch = patch(
            "backend.cloud_storage.utils.private_download_url",
            return_value="https://signed.invalid/resource",
        )
        make_url = url_patch.start()
        self.addCleanup(url_patch.stop)
        urlopen_patch = patch(
            "backend.cloud_storage.urllib.request.urlopen",
            side_effect=(
                FakeDownloadResponse(b"downloaded pdf"),
                FakeDownloadResponse(b"downloaded legacy bin"),
            ),
        )
        urlopen = urlopen_patch.start()
        self.addCleanup(urlopen_patch.stop)

        pdf_output = io.BytesIO()
        legacy_output = io.BytesIO()
        cloud_storage.download_original_file(f"cfiv/files/{'a' * 32}.pdf", pdf_output)
        cloud_storage.download_original_file(
            f"cfiv/files/{'b' * 32}.bin", legacy_output
        )

        self.assertEqual(make_url.call_args_list[0].args[:2],
                         (f"cfiv/files/{'a' * 32}.pdf", "pdf"))
        self.assertEqual(make_url.call_args_list[1].args[:2],
                         (f"cfiv/files/{'b' * 32}.bin", "bin"))
        self.assertEqual(pdf_output.getvalue(), b"downloaded pdf")
        self.assertEqual(legacy_output.getvalue(), b"downloaded legacy bin")
        self.assertEqual(urlopen.call_count, 2)

    def test_delete_uses_raw_authenticated_type(self):
        destroy_patch = patch(
            "backend.cloud_storage.uploader.destroy", return_value={"result": "ok"}
        )
        destroy = destroy_patch.start()
        self.addCleanup(destroy_patch.stop)

        deleted = cloud_storage.delete_resource(
            "cfiv/files/0123456789abcdef0123456789abcdef.bin"
        )

        self.assertTrue(deleted)
        destroy.assert_called_once_with(
            "cfiv/files/0123456789abcdef0123456789abcdef.bin",
            resource_type="raw",
            type="authenticated",
            invalidate=True,
        )

    def test_upload_api_failure_is_sanitized_and_cleanup_is_attempted(self):
        upload_patch = patch(
            "backend.cloud_storage.uploader.upload_large",
            side_effect=CloudinaryAPIError("api_secret=test-api-secret"),
        )
        upload = upload_patch.start()
        self.addCleanup(upload_patch.stop)
        destroy_patch = patch(
            "backend.cloud_storage.uploader.destroy", return_value={"result": "not found"}
        )
        destroy = destroy_patch.start()
        self.addCleanup(destroy_patch.stop)

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / f"{cloud_storage.uuid4().hex}.txt"
            source.write_bytes(b"payload")
            with self.assertNoLogs(level="WARNING"):
                with self.assertRaises(cloud_storage.CloudStorageError) as raised:
                    cloud_storage.upload_original_file(source)

        self.assertNotIn("test-api-secret", str(raised.exception))
        self.assertNotIn("api_secret", str(raised.exception))
        upload.assert_called_once()
        destroy.assert_called_once()

    def test_upload_diagnostics_log_fixed_stage_without_provider_details(self):
        upload_patch = patch(
            "backend.cloud_storage.uploader.upload_large",
            side_effect=CloudinaryAPIError(
                "api_secret=do-not-log signed_url=https://private.invalid/file"
            ),
        )
        upload = upload_patch.start()
        self.addCleanup(upload_patch.stop)
        destroy_patch = patch(
            "backend.cloud_storage.uploader.destroy",
            return_value={"result": "not found"},
        )
        destroy_patch.start()
        self.addCleanup(destroy_patch.stop)

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / f"{cloud_storage.uuid4().hex}.txt"
            source.write_bytes(b"payload")
            with patch.dict(os.environ, {"CFIV_ENV": "development"}):
                with self.assertLogs("cfiv.registration", level="INFO") as captured:
                    with self.assertRaises(cloud_storage.CloudStorageError):
                        cloud_storage.upload_original_file(
                            source, correlation_id="a" * 32
                        )

        output = "\n".join(captured.output)
        self.assertIn("correlation_id=" + "a" * 32, output)
        self.assertIn("stage=original_file_upload status=failure", output)
        self.assertIn("stage=cloudinary_cleanup status=success", output)
        self.assertNotIn("do-not-log", output)
        self.assertNotIn("private.invalid", output)
        upload.assert_called_once()

    def test_signature_upload_failure_cleans_up_previously_uploaded_original(self):
        upload_large_patch = patch("backend.cloud_storage.uploader.upload_large")
        upload_large = upload_large_patch.start()
        self.addCleanup(upload_large_patch.stop)
        upload_large.side_effect = lambda path, **options: self.upload_result(
            options["public_id"]
        )
        upload_patch = patch(
            "backend.cloud_storage.uploader.upload",
            side_effect=CloudinaryAPIError("secret token should be hidden"),
        )
        upload = upload_patch.start()
        self.addCleanup(upload_patch.stop)
        destroy_patch = patch(
            "backend.cloud_storage.uploader.destroy", return_value={"result": "ok"}
        )
        destroy = destroy_patch.start()
        self.addCleanup(destroy_patch.stop)

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / f"{cloud_storage.uuid4().hex}.txt"
            source.write_bytes(b"payload")
            with self.assertRaises(cloud_storage.CloudStorageError) as raised:
                cloud_storage.upload_file_and_signature(source, b"signature")

        self.assertNotIn("secret token", str(raised.exception))
        self.assertEqual(upload_large.call_count, 1)
        upload.assert_called_once()
        self.assertEqual(destroy.call_count, 2)

    def test_download_failure_clears_partial_output_and_hides_signed_url(self):
        url_patch = patch(
            "backend.cloud_storage.utils.private_download_url",
            return_value="https://secret.invalid/?api_secret=hidden",
        )
        url_patch.start()
        self.addCleanup(url_patch.stop)
        urlopen_patch = patch(
            "backend.cloud_storage.urllib.request.urlopen",
            side_effect=OSError("https://secret.invalid/?api_secret=hidden"),
        )
        urlopen_patch.start()
        self.addCleanup(urlopen_patch.stop)
        output = io.BytesIO(b"prefix")
        output.seek(len(b"prefix"))

        with self.assertNoLogs(level="WARNING"):
            with self.assertRaises(cloud_storage.CloudStorageError) as raised:
                cloud_storage.download_original_file(
                    "cfiv/files/0123456789abcdef0123456789abcdef.bin", output
                )

        self.assertEqual(output.getvalue(), b"prefix")
        self.assertNotIn("secret.invalid", str(raised.exception))
        self.assertNotIn("api_secret", str(raised.exception))

    def test_unexpected_download_error_is_sanitized_and_clears_partial_output(self):
        url_patch = patch(
            "backend.cloud_storage.utils.private_download_url",
            return_value="https://secret.invalid/?api_secret=hidden",
        )
        url_patch.start()
        self.addCleanup(url_patch.stop)
        urlopen_patch = patch(
            "backend.cloud_storage.urllib.request.urlopen",
            side_effect=RuntimeError("unexpected provider detail"),
        )
        urlopen_patch.start()
        self.addCleanup(urlopen_patch.stop)
        output = io.BytesIO(b"prefix")
        output.seek(len(b"prefix"))

        with self.assertNoLogs(level="WARNING"):
            with self.assertRaises(cloud_storage.CloudStorageError) as raised:
                cloud_storage.download_original_file(
                    "cfiv/files/0123456789abcdef0123456789abcdef.bin", output
                )

        self.assertEqual(output.getvalue(), b"prefix")
        self.assertNotIn("unexpected provider detail", str(raised.exception))
        self.assertNotIn("secret.invalid", str(raised.exception))
        self.assertNotIn("api_secret", str(raised.exception))

    def test_missing_configuration_fails_before_sdk_operation(self):
        env_patch = patch.dict(
            os.environ, {"CFIV_ENV": "development"}, clear=True
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        upload_patch = patch("backend.cloud_storage.uploader.upload_large")
        upload = upload_patch.start()
        self.addCleanup(upload_patch.stop)

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / f"{cloud_storage.uuid4().hex}.txt"
            source.write_bytes(b"payload")
            with self.assertLogs("cfiv.registration", level="INFO") as captured:
                with self.assertRaises(cloud_storage.CloudStorageConfigurationError) as raised:
                    cloud_storage.upload_original_file(
                        source, correlation_id="b" * 32
                    )

        self.assertNotIn("test-api-secret", str(raised.exception))
        diagnostic_output = "\n".join(captured.output)
        self.assertIn("stage=cloudinary_configuration status=failure", diagnostic_output)
        self.assertIn("stage=original_file_upload status=failure", diagnostic_output)
        upload.assert_not_called()

    def test_only_generated_resource_ids_are_accepted_for_retrieval_or_deletion(self):
        for public_id in ("../secret", "user/file.txt", "cfiv/files/not-a-uuid.bin"):
            with self.subTest(public_id=public_id):
                with self.assertRaises(ValueError):
                    cloud_storage.download_signature_artifact(public_id)

    def test_request_diagnostics_capture_bad_request_id_without_body_access(self):
        connector = Mock()
        connector.request.return_value = DiagnosticHTTPResponse(400, "req-400-abc")
        with patch.object(cloud_storage.uploader, "_http", connector), patch.dict(
            os.environ, {"CFIV_ENV": "development"}
        ), patch(
            "backend.cloud_storage.version", return_value="1.47.0"
        ):
            with self.assertLogs("cfiv.registration", level="INFO") as captured:
                with cloud_storage._upload_request_diagnostics(
                    "c" * 32, "original_file_upload"
                ):
                    response = cloud_storage.uploader._http.request(
                        "POST", "https://sdk.invalid", fields={"private": "never logged"}
                    )
                self.assertIs(cloud_storage.uploader._http, connector)

        self.assertEqual(response.status, 400)
        connector.request.assert_called_once_with(
            "POST", "https://sdk.invalid", fields={"private": "never logged"}
        )
        output = "\n".join(captured.output)
        self.assertIn("correlation_id=" + "c" * 32, output)
        self.assertIn("stage=original_file_upload http_status=400", output)
        self.assertIn("request_id=req-400-abc", output)
        self.assertNotIn("never logged", output)
        self.assertNotIn("sdk.invalid", output)

    def test_request_diagnostics_capture_success_status_and_id(self):
        connector = Mock()
        connector.request.return_value = DiagnosticHTTPResponse(200, "req-200-xyz")
        with patch.object(cloud_storage.uploader, "_http", connector), patch.dict(
            os.environ, {"CFIV_ENV": "development"}
        ), patch("backend.cloud_storage.version", return_value="1.47.0"):
            with self.assertLogs("cfiv.registration", level="INFO") as captured:
                with cloud_storage._upload_request_diagnostics(
                    "d" * 32, "signature_artifact_upload"
                ):
                    cloud_storage.uploader._http.request("POST", "endpoint")
            self.assertIs(cloud_storage.uploader._http, connector)

        output = "\n".join(captured.output)
        self.assertIn("stage=signature_artifact_upload http_status=200", output)
        self.assertIn("request_id=req-200-xyz", output)

    def test_request_diagnostics_allow_missing_request_id(self):
        connector = Mock()
        connector.request.return_value = DiagnosticHTTPResponse(400)
        with patch.object(cloud_storage.uploader, "_http", connector), patch.dict(
            os.environ, {"CFIV_ENV": "development"}
        ), patch("backend.cloud_storage.version", return_value="1.47.0"):
            with self.assertLogs("cfiv.registration", level="INFO") as captured:
                with cloud_storage._upload_request_diagnostics(
                    "e" * 32, "original_file_upload"
                ):
                    cloud_storage.uploader._http.request("POST", "endpoint")

        output = "\n".join(captured.output)
        self.assertIn("http_status=400", output)
        self.assertNotIn("request_id=", output)

    def test_request_exception_is_unchanged_and_connector_is_restored(self):
        connector = Mock()
        request_error = RuntimeError("private response details")
        connector.request.side_effect = request_error
        with patch.object(cloud_storage.uploader, "_http", connector), patch.dict(
            os.environ, {"CFIV_ENV": "development"}
        ), patch("backend.cloud_storage.version", return_value="1.47.0"):
            with self.assertRaisesRegex(RuntimeError, "private response details") as raised:
                with cloud_storage._upload_request_diagnostics(
                    "f" * 32, "original_file_upload"
                ):
                    cloud_storage.uploader._http.request("POST", "endpoint")
            self.assertIs(cloud_storage.uploader._http, connector)

        self.assertIs(raised.exception, request_error)

    def test_request_diagnostic_wrapper_is_not_installed_outside_development(self):
        connector = Mock()
        with patch.object(cloud_storage.uploader, "_http", connector), patch.dict(
            os.environ, {"CFIV_ENV": "production"}
        ):
            with cloud_storage._upload_request_diagnostics(
                "1" * 32, "original_file_upload"
            ):
                self.assertIs(cloud_storage.uploader._http, connector)
            self.assertIs(cloud_storage.uploader._http, connector)
        connector.request.assert_not_called()

    def test_repeated_and_nested_diagnostics_do_not_stack_connectors(self):
        connector = Mock()
        connector.request.return_value = DiagnosticHTTPResponse(200, "req-repeat")
        with patch.object(cloud_storage.uploader, "_http", connector), patch.dict(
            os.environ, {"CFIV_ENV": "development"}
        ), patch("backend.cloud_storage.version", return_value="1.47.0"):
            with self.assertLogs("cfiv.registration", level="INFO") as captured:
                for correlation_id in ("2" * 32, "3" * 32):
                    with cloud_storage._upload_request_diagnostics(
                        correlation_id, "original_file_upload"
                    ):
                        outer_proxy = cloud_storage.uploader._http
                        with cloud_storage._upload_request_diagnostics(
                            correlation_id, "original_file_upload"
                        ):
                            self.assertIs(cloud_storage.uploader._http, outer_proxy)
                            cloud_storage.uploader._http.request("POST", "endpoint")
                    self.assertIs(cloud_storage.uploader._http, connector)

            self.assertIs(cloud_storage.uploader._http, connector)

        output = "\n".join(captured.output)
        self.assertEqual(output.count("cloudinary_request "), 2)
        self.assertIn("correlation_id=" + "2" * 32, output)
        self.assertIn("correlation_id=" + "3" * 32, output)

    def test_diagnostics_skip_unexpected_sdk_interface(self):
        connector = Mock()
        with patch.object(cloud_storage.uploader, "_http", connector), patch.dict(
            os.environ, {"CFIV_ENV": "development"}
        ), patch("backend.cloud_storage.version", return_value="1.48.0"):
            with cloud_storage._upload_request_diagnostics(
                "4" * 32, "original_file_upload"
            ):
                self.assertIs(cloud_storage.uploader._http, connector)


if __name__ == "__main__":
    unittest.main()
