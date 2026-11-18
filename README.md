# Cloud File Integrity Verification System (CFIV)

A Flask-based web application that helps verify the integrity and authenticity of files using cryptographic hashing and RSA digital signatures, with Cloudinary integration for secure cloud storage.

## Overview

The Cloud File Integrity Verification System (CFIV) is designed to detect unauthorized modifications to registered files.

It generates cryptographic hashes for uploaded files, creates a digital signature using an RSA private key, and stores the file and its signature artifact in cloud storage. During verification, the system recalculates the file hashes and validates the digital signature against the registered public key.

This helps identify whether a file has been altered after registration.

## Key Features

- **Dual Hashing:** Generates SHA-256 and SHA3-256 hashes for uploaded files.
- **Combined Digest:** Uses a domain-separated combined digest derived from both hash values.
- **Digital Signatures:** Uses RSA 2048-bit keys and RSA-PSS with SHA-256 for signing and verification.
- **Encrypted Private Keys:** Protects private keys using password-based encryption.
- **Cloud Storage:** Integrates Cloudinary to store original files and signature artifacts as authenticated raw resources.
- **File Verification:** Recalculates hashes and verifies digital signatures to detect file modifications.
- **Public Key Registry:** Registers public keys and identifies them using SHA-256 fingerprints.
- **Verification History:** Records verification attempts and their results.
- **File Management:** Provides a page to view registered files and their latest verification status.
- **Security Dashboard:** Displays registered public-key metadata and relevant security information.
- **Input Validation:** Enforces supported file extensions and a 16 MiB upload limit.

## Technology Stack

| Category | Technologies |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML5, CSS3, JavaScript |
| Database | SQLite |
| Cloud Storage | Cloudinary |
| Cryptography | SHA-256, SHA3-256, RSA 2048, RSA-PSS |
| Testing | Python unittest |
| Version Control | Git, GitHub |

## How It Works

1. **Key Generation:** An RSA 2048-bit public/private key pair is generated. The private key is encrypted with a password and kept outside the project directory.
2. **Public Key Registration:** The public key is registered in the application's database.
3. **File Registration:** The user uploads a supported file and provides the private-key password.
4. **Hash Generation:** CFIV calculates SHA-256 and SHA3-256 hashes and derives a combined digest.
5. **Digital Signing:** The combined digest is signed using the RSA private key and RSA-PSS.
6. **Cloud Storage:** The original file and signature artifact are uploaded to Cloudinary.
7. **File Verification:** CFIV retrieves the stored file and signature artifact, recalculates the hashes, and verifies the signature using the registered public key.
8. **Result Recording:** The verification outcome is recorded and displayed in the application.

## Project Structure

```text
CFIV/
│
├── backend/
│   ├── cloud_storage.py
│   ├── dashboard_service.py
│   ├── database.py
│   ├── file_service.py
│   ├── hashing.py
│   ├── key_registry.py
│   ├── signatures.py
│   ├── verification.py
│   └── verification_history.py
│
├── frontend/
│   ├── static/
│   │   ├── css/
│   │   └── js/
│   └── templates/
│
├── instance/
├── storage/
│   └── uploads/
│
├── tests/
├── app.py
├── config.py
├── generate_keys.py
├── requirements.txt
├── .env.example
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.12 or compatible Python 3 version
- Git
- A Cloudinary account

### 1. Clone the repository

```bash
git clone https://github.com/ruchira-ponnamma/CFIV.git
cd CFIV
```

### 2. Create and activate a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root using `.env.example` as a reference.

Configure the following values:

```env
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret

FLASK_SECRET_KEY=your_generated_secret_key
CFIV_PRIVATE_KEY_PATH=your_private_key_path
```

Generate a strong Flask secret key and replace the placeholder. Configure your Cloudinary credentials using your own account.

If `CFIV_PRIVATE_KEY_PATH` is omitted, CFIV uses the default private-key location under `~/CFIV-Keys/private_key.pem`.

**Never commit your actual `.env` file, Cloudinary credentials, or private key to GitHub.**

### 5. Generate RSA keys

Run:

```bash
python generate_keys.py
```

Follow the prompts to create and encrypt your RSA private key.

The generated key pair is stored outside the project directory in `CFIV-Keys`.

### 6. Register the public key

Run:

```bash
python test_key_registry.py
```

This registers the generated public key in the application's database.

### 7. Run the application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

## Running Tests

Run the automated test suite using:

```bash
python -m unittest discover -s tests -v
```

The test suite covers hashing, digital signatures, database operations, file registration, cloud storage, verification, key registration, application routes, and verification history.

## Supported File Types

CFIV currently accepts:

- PDF
- TXT
- CSV
- DOCX
- XLSX
- PPTX
- JPG / JPEG
- PNG

**Maximum file size:** 16 MiB.

## Security Considerations

- Private keys are encrypted with password-based protection.
- Private key files are stored outside the project directory by default.
- Public-key fingerprints are used to identify registered keys.
- Cloudinary resources are uploaded as authenticated raw resources.
- Sensitive configuration values are loaded from environment variables.
- Uploads are validated before processing.
- The application uses CSRF tokens for registration and verification forms.
- Debug mode is disabled by default.

## Current Scope and Limitations

- Verification currently retrieves the stored file to recalculate its hashes; it does not perform partial remote verification.
- Periodic automated integrity monitoring is not currently implemented.
- Blockchain integration and Merkle-tree-based verification are outside the current implementation.

## Future Enhancements

- Automated periodic integrity verification.
- Merkle tree-based integrity proofs.
- Blockchain-based integrity records.
- Extended monitoring and reporting capabilities.

