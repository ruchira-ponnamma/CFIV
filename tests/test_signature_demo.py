
from getpass import getpass
from pathlib import Path

from backend.hashing import calculate_file_hashes
from backend.signatures import sign_hash, verify_signature


KEY_DIRECTORY = Path.home() / "CFIV-Keys"

PRIVATE_KEY = KEY_DIRECTORY / "private_key.pem"
PUBLIC_KEY = KEY_DIRECTORY / "public_key.pem"

SAMPLE_FILE = Path("storage/uploads/sample.txt")


def main():

    if not PRIVATE_KEY.exists() or not PUBLIC_KEY.exists():
        print("RSA key files not found.")
        return

    if not SAMPLE_FILE.exists():
        print("Sample file not found.")
        return

    password = getpass("Enter your private key password: ")

    # Calculate the original file hash
    hashes = calculate_file_hashes(SAMPLE_FILE)
    original_hash = hashes["sha256"]

    print("\n--- SIGNING ---")

    signature = sign_hash(
        original_hash,
        PRIVATE_KEY,
        password.encode("utf-8")
    )

    print("Digital signature generated successfully!")
    print("Signature length:", len(signature), "bytes")

    print("\n--- SIGNATURE VERIFICATION ---")

    is_valid = verify_signature(
        original_hash,
        signature,
        PUBLIC_KEY
    )

    print("Signature valid:", is_valid)

    print("\n--- TESTING MODIFICATION ---")

    modified_hash = "0" * 64

    is_valid_after_modification = verify_signature(
        modified_hash,
        signature,
        PUBLIC_KEY
    )

    print("Signature valid after hash modification:",
          is_valid_after_modification)


if __name__ == "__main__":
    main()
