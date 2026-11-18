
import os
from pathlib import Path

from dotenv import load_dotenv


# Get the root directory of the CFIV project
BASE_DIR = Path(__file__).resolve().parent

# Load local environment values before reading application configuration.
# Existing process environment variables take precedence over values in .env.
load_dotenv(BASE_DIR / ".env")

# Maximum size of the uploaded file itself (16 MiB).
MAX_FILE_SIZE = 16 * 1024 * 1024


class Config:
    # Application settings
    # Allow extra request bytes for multipart form headers and boundaries.
    MAX_CONTENT_LENGTH = 17 * 1024 * 1024
    MAX_FILE_SIZE = MAX_FILE_SIZE

    # Debugger access is opt-in and limited to explicit local-development mode.
    # Unset or production environments always keep Flask's debugger disabled.
    _environment = os.environ.get("CFIV_ENV", "production").strip().lower()
    _debug_requested = os.environ.get("CFIV_DEBUG", "").strip().lower() in {
        "1", "true", "yes", "on"
    }
    DEBUG = _environment == "development" and _debug_requested

    # File storage location
    UPLOAD_FOLDER = BASE_DIR / "storage" / "uploads"

    # SQLite database location
    DATABASE_PATH = BASE_DIR / "instance" / "cfiv.db"

    # Private signing key remains outside the project directory by default.
    _private_key_path = os.environ.get("CFIV_PRIVATE_KEY_PATH")
    PRIVATE_KEY_PATH = Path(_private_key_path) if _private_key_path else (
        Path.home() / "CFIV-Keys" / "private_key.pem"
    )

    # Secret key must be supplied through the environment.
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")


def validate_config():
    """Raise a clear error if required Flask security configuration is missing."""
    if not Config.SECRET_KEY:
        raise RuntimeError(
            "FLASK_SECRET_KEY must be configured before starting the Flask app."
        )
