
from getpass import getpass
from pathlib import Path

from backend.signatures import generate_key_pair


def main():
    key_directory = Path.home() / "CFIV-Keys"

    print("CFIV - RSA Key Generation")
    print("-------------------------")

    password = getpass("Enter a password for your private key: ")
    confirm_password = getpass("Confirm your password: ")

    if not password:
        print("Error: Password cannot be empty.")
        return

    if password != confirm_password:
        print("Error: Passwords do not match.")
        return

    try:
        private_path, public_path = generate_key_pair(
            key_directory,
            password.encode("utf-8")
        )

        print("\nRSA 2048-bit key pair generated successfully!")
        print(f"Private key: {private_path}")
        print(f"Public key: {public_path}")

    except FileExistsError as error:
        print(f"\nError: {error}")
        print("Existing keys have not been changed.")


if __name__ == "__main__":
    main()
