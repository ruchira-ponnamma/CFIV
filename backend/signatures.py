
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils


SHA256_V1_SCHEME = "sha256-v1"
COMBINED_SHA256_SHA3_V2_SCHEME = "combined-sha256-sha3-v2"
DOMAIN_SEPARATOR = b"CFIV\x00combined-sha256-sha3-v2\x00"


def combined_sha256_sha3_digest(sha256_hex, sha3_256_hex):
    """Return the SHA-256 digest of CFIV's ordered, domain-separated v2 input."""
    try:
        sha256_bytes = bytes.fromhex(sha256_hex)
        sha3_256_bytes = bytes.fromhex(sha3_256_hex)
    except (TypeError, ValueError) as error:
        raise ValueError("Expected hexadecimal SHA-256 and SHA3-256 digests.") from error

    if len(sha256_bytes) != 32 or len(sha3_256_bytes) != 32:
        raise ValueError("Expected 32-byte SHA-256 and SHA3-256 digests.")

    combined_input = DOMAIN_SEPARATOR + sha256_bytes + sha3_256_bytes
    return hashlib.sha256(combined_input).hexdigest()


def generate_key_pair(key_directory, password):
    """Generate an encrypted RSA 2048-bit key pair."""

    key_directory = Path(key_directory)
    key_directory.mkdir(parents=True, exist_ok=True)

    private_key_path = key_directory / "private_key.pem"
    public_key_path = key_directory / "public_key.pem"

    if private_key_path.exists() or public_key_path.exists():
        raise FileExistsError(
            "A key file already exists. Refusing to overwrite it."
        )

    if not password:
        raise ValueError("A password is required.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password
        )
    )

    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_path.write_bytes(private_key_pem)
    public_key_path.write_bytes(public_key_pem)

    return private_key_path, public_key_path


def load_private_key(private_key_path, password):
    """Load the encrypted RSA private key."""

    with open(private_key_path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=password
        )


def load_public_key(public_key_path):
    """Load the RSA public key."""

    with open(public_key_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


def sign_hash(hash_hex, private_key_path, password):
    """Sign a SHA-256 hexadecimal digest using RSA-PSS."""

    digest = bytes.fromhex(hash_hex)

    if len(digest) != 32:
        raise ValueError("Expected a 32-byte SHA-256 digest.")

    private_key = load_private_key(private_key_path, password)

    return private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )


def verify_signature(hash_hex, signature, public_key_path):
    """Verify an RSA-PSS signature against a SHA-256 digest."""
    public_key = load_public_key(public_key_path)
    return verify_signature_with_public_key(hash_hex, signature, public_key)


def verify_signature_with_public_key(hash_hex, signature, public_key):
    """Verify an RSA-PSS signature with a loaded RSA public key."""

    digest = bytes.fromhex(hash_hex)

    if len(digest) != 32:
        raise ValueError("Expected a 32-byte SHA-256 digest.")

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("The public key must be an RSA key.")

    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )

        return True

    except InvalidSignature:
        return False
