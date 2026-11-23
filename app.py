
import hmac
import secrets
import sqlite3

from cryptography.exceptions import UnsupportedAlgorithm
from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge

from backend.cloud_storage import CloudStorageError, normalize_original_extension
from backend.database import init_db
from backend.dashboard_service import get_dashboard_data, get_registered_files_with_status
from backend.file_service import list_registered_files, register_uploaded_file
from backend.key_registry import (
    list_registered_public_key_metadata,
    list_registered_public_keys,
)
from backend.registration_diagnostics import new_registration_correlation_id
from backend.verification import verify_registered_file, verify_uploaded_copy
from backend.verification_history import get_verification_attempt
from config import Config, validate_config


# Check required security settings before creating the Flask application.
validate_config()


class CFIVFlask(Flask):
    """Prevent Flask CLI flags from enabling debug outside local dev config."""

    @property
    def debug(self):
        return self.config["DEBUG"]

    @debug.setter
    def debug(self, value):
        self.config["DEBUG"] = bool(value) and bool(Config.DEBUG)


# Create the Flask application
app = CFIVFlask(
    __name__,
    template_folder="frontend/templates",
    static_folder="frontend/static"
)

# Load application configuration
app.config.from_object(Config)

# Create the database tables and index before serving requests.
init_db()


def _render_register_page(error_message=None, status=200, registered_keys=None):
    """Render registration with a fresh CSRF token and current safe key list."""
    csrf_token = secrets.token_urlsafe(32)
    session["_csrf_token"] = csrf_token
    if registered_keys is None:
        registered_keys = list_registered_public_keys()
    return (
        render_template(
            "register.html",
            registered_keys=registered_keys,
            csrf_token=csrf_token,
            error_message=error_message,
        ),
        status,
    )


# Home page route
@app.route("/")
def home():
    dashboard_data = get_dashboard_data()
    return render_template("index.html", **dashboard_data)


@app.route("/my-files", methods=["GET"])
def my_files_page():
    """Display registered files and their latest stored verification status."""
    csrf_token = secrets.token_urlsafe(32)
    session["_verify_csrf_token"] = csrf_token

    try:
        registered_files = get_registered_files_with_status()
    except sqlite3.Error:
        return render_template(
            "my_files.html",
            registered_files=[],
            csrf_token=csrf_token,
            error_message="CFIV could not retrieve your files. Please try again.",
        ), 500

    return render_template(
        "my_files.html",
        registered_files=registered_files,
        csrf_token=csrf_token,
        error_message=None,
    )


@app.route("/security", methods=["GET"])
def security_page():
    """Display safe metadata for registered public keys and security practices."""
    try:
        registered_keys = list_registered_public_key_metadata()
    except (sqlite3.Error, ValueError, TypeError, UnsupportedAlgorithm):
        return render_template(
            "security.html",
            registered_keys=[],
            error_message="CFIV could not retrieve registered key details. Please try again.",
        ), 500

    return render_template(
        "security.html",
        registered_keys=registered_keys,
        error_message=None,
    )


def _render_verify_page(
    *, error_message=None, status=200, registered_files=None, verification_attempt=None
):
    """Render the verification page with a fresh verification CSRF token."""
    csrf_token = secrets.token_urlsafe(32)
    session["_verify_csrf_token"] = csrf_token

    if registered_files is None:
        try:
            registered_files = list_registered_files()
        except sqlite3.Error:
            return Response(
                "CFIV could not retrieve registered files. Please try again.",
                status=500,
                mimetype="text/plain",
            )

    return render_template(
        "verify.html",
        registered_files=registered_files,
        csrf_token=csrf_token,
        verification_attempt=verification_attempt,
        error_message=error_message,
    ), status


@app.route("/verify", methods=["GET", "POST"])
def verify_page():
    """Select a registered file, verify it once, and display its stored result."""
    if request.method == "GET":
        try:
            registered_files = list_registered_files()
        except sqlite3.Error:
            # Create the token even when the listing query fails.
            csrf_token = secrets.token_urlsafe(32)
            session["_verify_csrf_token"] = csrf_token
            return Response(
                "CFIV could not retrieve registered files. Please try again.",
                status=500,
                mimetype="text/plain",
            )

        csrf_token = secrets.token_urlsafe(32)
        session["_verify_csrf_token"] = csrf_token
        uploaded_copy_csrf_token = secrets.token_urlsafe(32)
        session["_uploaded_copy_verify_csrf_token"] = uploaded_copy_csrf_token
        attempt_id = request.args.get("attempt_id")
        verification_attempt = None
        if attempt_id is not None:
            try:
                verification_attempt = get_verification_attempt(attempt_id)
            except sqlite3.Error:
                return Response(
                    "CFIV could not retrieve the verification result. Please try again.",
                    status=500,
                    mimetype="text/plain",
                )
            if verification_attempt is None:
                return Response(
                    "The requested verification result was not found.",
                    status=404,
                    mimetype="text/plain",
                )

        return render_template(
            "verify.html",
            registered_files=registered_files,
            csrf_token=csrf_token,
            uploaded_copy_csrf_token=uploaded_copy_csrf_token,
            verification_attempt=verification_attempt,
            error_message=None,
        )

    expected_token = session.pop("_verify_csrf_token", None)
    submitted_token = request.form.get("csrf_token", "")
    if (
        not isinstance(expected_token, str)
        or not isinstance(submitted_token, str)
        or not hmac.compare_digest(expected_token, submitted_token)
    ):
        return _render_verify_page(
            error_message="Your verification form expired. Please try again.",
            status=400,
        )

    file_id = request.form.get("file_id", "")
    if not isinstance(file_id, str) or not file_id.strip():
        return _render_verify_page(
            error_message="Select a registered file to verify.",
            status=400,
        )

    registered_files = None
    try:
        registered_files = list_registered_files()
        if file_id not in {file_record["file_id"] for file_record in registered_files}:
            return _render_verify_page(
                error_message="The selected registered file was not found.",
                status=404,
                registered_files=registered_files,
            )

        result = verify_registered_file(file_id)
    except LookupError:
        return _render_verify_page(
            error_message="The selected registered file or its key was not found.",
            status=404,
            registered_files=registered_files,
        )
    except FileNotFoundError:
        return _render_verify_page(
            error_message="The stored file is unavailable for verification.",
            status=404,
            registered_files=registered_files,
        )
    except ValueError:
        return _render_verify_page(
            error_message="The file record or verification configuration is invalid.",
            status=400,
            registered_files=registered_files,
        )
    except (OSError, sqlite3.Error, UnsupportedAlgorithm):
        return _render_verify_page(
            error_message="CFIV could not complete verification. Please try again.",
            status=500,
            registered_files=registered_files,
        )
    except RuntimeError:
        return _render_verify_page(
            error_message="CFIV could not complete verification. Please try again.",
            status=500,
            registered_files=registered_files,
        )

    return redirect(url_for("verify_page", attempt_id=result["attempt_id"]))


@app.route("/verify-uploaded-copy", methods=["POST"])
def verify_uploaded_copy_route():
    """Verify a locally submitted copy against an existing registration."""
    expected_token = session.pop("_uploaded_copy_verify_csrf_token", None)
    submitted_token = request.form.get("csrf_token", "")
    if (
        not isinstance(expected_token, str)
        or not isinstance(submitted_token, str)
        or not hmac.compare_digest(expected_token, submitted_token)
    ):
        session["_uploaded_copy_verify_csrf_token"] = secrets.token_urlsafe(32)
        return Response(
            "Your uploaded-copy verification form expired. Please reload and try again.",
            status=400,
            mimetype="text/plain",
        )

    file_id = request.form.get("file_id", "")
    uploaded_file = request.files.get("uploaded_file")
    filename = getattr(uploaded_file, "filename", None)
    stream = getattr(uploaded_file, "stream", None)
    if not isinstance(file_id, str) or not file_id.strip():
        session["_uploaded_copy_verify_csrf_token"] = secrets.token_urlsafe(32)
        return Response(
            "Select a registered file and a local copy to verify.",
            status=400,
            mimetype="text/plain",
        )
    if (
        not isinstance(filename, str)
        or not filename.strip()
        or stream is None
        or not callable(getattr(stream, "read", None))
    ):
        session["_uploaded_copy_verify_csrf_token"] = secrets.token_urlsafe(32)
        return Response(
            "Choose a readable local file to verify.",
            status=400,
            mimetype="text/plain",
        )

    try:
        normalize_original_extension(filename)
    except ValueError:
        session["_uploaded_copy_verify_csrf_token"] = secrets.token_urlsafe(32)
        return Response(
            "The selected file type is not supported for verification.",
            status=400,
            mimetype="text/plain",
        )

    try:
        result = verify_uploaded_copy(file_id, uploaded_file)
    except LookupError:
        session["_uploaded_copy_verify_csrf_token"] = secrets.token_urlsafe(32)
        return Response(
            "The selected registered file or its key was not found.",
            status=404,
            mimetype="text/plain",
        )
    except FileNotFoundError:
        session["_uploaded_copy_verify_csrf_token"] = secrets.token_urlsafe(32)
        return Response(
            "The submitted file is unavailable for verification.",
            status=400,
            mimetype="text/plain",
        )
    except ValueError as error:
        session["_uploaded_copy_verify_csrf_token"] = secrets.token_urlsafe(32)
        if str(error) == "The uploaded file exceeds the 16 MB limit.":
            message = "The selected file exceeds the 16 MiB file-size limit."
        else:
            message = "The file record or submitted file is invalid."
        return Response(message, status=400, mimetype="text/plain")
    except (OSError, sqlite3.Error, UnsupportedAlgorithm, RuntimeError):
        session["_uploaded_copy_verify_csrf_token"] = secrets.token_urlsafe(32)
        return Response(
            "CFIV could not complete uploaded-copy verification. Please try again.",
            status=500,
            mimetype="text/plain",
        )

    return redirect(url_for("verify_page", attempt_id=result["attempt_id"]))


@app.route("/register", methods=["GET", "POST"])
def register_file():
    if request.method == "GET":
        return _render_register_page()

    expected_token = session.pop("_csrf_token", None)
    submitted_token = request.form.get("csrf_token", "")
    if (
        not isinstance(expected_token, str)
        or not isinstance(submitted_token, str)
        or not hmac.compare_digest(expected_token, submitted_token)
    ):
        return _render_register_page(
            "Your form session expired. Please try again.", status=400
        )

    correlation_id = new_registration_correlation_id()
    uploaded_file = request.files.get("upload_file")
    key_id = request.form.get("key_id", "")
    password = request.form.get("private_key_password", "")
    filename = getattr(uploaded_file, "filename", None)

    if not isinstance(filename, str) or not filename.strip():
        return _render_register_page("Choose a file to register.", status=400)
    if not isinstance(key_id, str) or not key_id.strip():
        return _render_register_page("Choose a registered public key.", status=400)
    if not isinstance(password, str) or not password:
        return _render_register_page("Enter the private-key password.", status=400)

    try:
        registered_keys = list_registered_public_keys()
        if key_id not in {key["key_id"] for key in registered_keys}:
            return _render_register_page(
                "Choose a currently registered public key.", status=400,
                registered_keys=registered_keys,
            )

        register_uploaded_file(
            uploaded_file,
            private_key_path=Config.PRIVATE_KEY_PATH,
            private_key_password=password,
            key_id=key_id,
            correlation_id=correlation_id,
        )
    except ValueError as error:
        if str(error) == "The uploaded file exceeds the 16 MB limit.":
            message = "The selected file exceeds the 16 MiB file-size limit."
        else:
            message = (
                "The file could not be registered. Check the selected file, "
                "registered key, and private-key password."
            )
        return _render_register_page(message, status=400)
    except OSError:
        return _render_register_page(
            "CFIV could not access the private key or upload storage.", status=500
        )
    except sqlite3.Error:
        return _render_register_page(
            "CFIV could not save the registration. Please try again.",
            status=500,
            registered_keys=[],
        )
    except CloudStorageError:
        return _render_register_page(
            "CFIV could not securely store the file. Please try again.",
            status=500,
        )
    except RuntimeError as error:
        if str(error) == (
            "Registration failed and created resources could not be fully removed."
        ):
            return _render_register_page(
                "Registration failed and cleanup could not be confirmed.",
                status=500,
            )
        if str(error) != "Registration failed and the saved upload could not be removed.":
            raise
        return _render_register_page(
            "Registration failed and temporary file cleanup could not be confirmed.",
            status=500,
        )

    flash("File registered successfully.", "success")
    return redirect(url_for("home"))


@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(error):
    """Return a safe size message without parsing the oversized request again."""
    if request.endpoint == "register_file" and request.method == "POST":
        return _render_register_page(
            "The upload exceeds the allowed size. Files are limited to 16 MiB; "
            "the complete request limit is 17 MiB including multipart overhead.",
            status=413,
        )

    return Response(
        "The upload exceeds the allowed size. Files are limited to 16 MiB; "
        "the complete request limit is 17 MiB including multipart overhead.",
        status=413,
        mimetype="text/plain",
    )


# Run the application
if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"], host="127.0.0.1")
