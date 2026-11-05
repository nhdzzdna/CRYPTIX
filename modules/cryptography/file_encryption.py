"""
modules/cryptography/file_encryption.py
────────────────────────────────────────
AES-256-GCM file encryption / decryption.

Each file gets a fresh 12-byte nonce.  The GCM authentication tag (16 bytes)
is stored separately in the database so the encrypted blob on disk can be
verified before decryption.

Storage:
  Encrypted blob → storage/encrypted_files/<stored_name>
  nonce + tag    → database vault_files table (hex strings)
"""

import os
import sys
import hashlib
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(plaintext_bytes: bytes, file_key: bytes) -> dict:
    """
    Encrypt *plaintext_bytes* with AES-256-GCM.

    Parameters
    ----------
    plaintext_bytes : bytes  Raw file content.
    file_key        : bytes  32-byte derived key (from key_management).

    Returns
    -------
    dict with keys:
      ``ciphertext``  bytes — encrypted payload (includes GCM tag appended)
      ``nonce_hex``   str   — hex-encoded 12-byte nonce
      ``tag_hex``     str   — hex-encoded 16-byte GCM auth tag
      ``sha256_hex``  str   — SHA-256 of the original plaintext
    """
    if len(file_key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")

    nonce = os.urandom(12)          # 96-bit nonce recommended for GCM
    aesgcm = AESGCM(file_key)
    # encrypt() appends the 16-byte tag to the ciphertext automatically
    ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    sha256_hex = hashlib.sha256(plaintext_bytes).hexdigest()

    return {
        "ciphertext": ct_with_tag,   # store the full blob (ct + tag)
        "nonce_hex": nonce.hex(),
        "tag_hex": tag.hex(),
        "sha256_hex": sha256_hex,
    }


def decrypt_file(ciphertext_with_tag: bytes, nonce_hex: str, file_key: bytes) -> bytes:
    """
    Decrypt *ciphertext_with_tag* (ciphertext ‖ 16-byte GCM tag).

    Raises cryptography.exceptions.InvalidTag if the ciphertext was tampered.

    Parameters
    ----------
    ciphertext_with_tag : bytes  Full blob from disk.
    nonce_hex           : str    Hex nonce stored in DB.
    file_key            : bytes  32-byte derived key.

    Returns
    -------
    bytes  Decrypted plaintext.
    """
    nonce = bytes.fromhex(nonce_hex)
    aesgcm = AESGCM(file_key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


def save_encrypted_file(ciphertext: bytes, stored_name: str) -> str:
    """Write encrypted blob to storage/encrypted_files/ and return the path."""
    dest = os.path.join(config.ENCRYPTED_FILES_DIR, stored_name)
    os.makedirs(config.ENCRYPTED_FILES_DIR, exist_ok=True)
    with open(dest, "wb") as f:
        f.write(ciphertext)
    return dest


def load_encrypted_file(stored_name: str) -> bytes:
    """Read encrypted blob from storage/encrypted_files/."""
    path = os.path.join(config.ENCRYPTED_FILES_DIR, stored_name)
    with open(path, "rb") as f:
        return f.read()


def generate_stored_name(original_filename: str) -> str:
    """Generate a UUID-based safe storage filename, preserving extension."""
    ext = os.path.splitext(original_filename)[1].lower()
    return f"{uuid.uuid4().hex}{ext}.enc"
