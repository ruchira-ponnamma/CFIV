
import hashlib
from pathlib import Path


def calculate_file_hashes(file_path):
    """
    Calculate SHA-256 and SHA3-256 hashes
    for a given file.

    Args:
        file_path: Path to the file.

    Returns:
        Dictionary containing both hash values.
    """

    sha256_hash = hashlib.sha256()
    sha3_hash = hashlib.sha3_256()

    # Open the file in binary read mode
    with open(file_path, "rb") as file:

        # Read the file in chunks
        while chunk := file.read(4096):

            sha256_hash.update(chunk)
            sha3_hash.update(chunk)

    return {
        "sha256": sha256_hash.hexdigest(),
        "sha3_256": sha3_hash.hexdigest()
    }
