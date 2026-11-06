"""
modules/cryptography/key_management.py
───────────────────────────────────────
Master key derivation and per-purpose key derivation.

Design:
  • Master key = PBKDF2-HMAC-SHA256(password, salt, 600 000 iterations) → 32 bytes
    Stored ONLY in Flask session during login, never written to disk.

  • Per-purpose keys = HKDF-SHA256(master_key, salt=label, length=32)
    Each module (file encryption, DB encryption, stego, super-enc sub-ciphers)
    calls derive_purpose_key() with a distinct label from config.py so all
    derived keys are cryptographically independent.
"""

import hashlib
import os

import config

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _hashes


def derive_master_key(password: str, salt_hex: str) -> bytes:
    """
    Derive a 32-byte master key from the user's password and their stored salt.

    This mirrors the stored hash computation but returns raw bytes instead of
    a hex string.  The master key must be kept in session only.

    Parameters
    ----------
    password : str
    salt_hex : str  Hex-encoded salt stored in the users table.

    Returns
    -------
    bytes  32-byte master key.
    """
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac(
        config.PBKDF2_HASH_ALGO,
        password.encode("utf-8"),
        salt,
        config.PBKDF2_ITERATIONS,
        dklen=32,
    )


def derive_purpose_key(master_key: bytes, label: bytes, length: int = 32) -> bytes:
    """
    Derive a purpose-specific key from *master_key* using HKDF-SHA256.

    Parameters
    ----------
    master_key : bytes  32-byte master key from derive_master_key().
    label      : bytes  Unique context label (e.g. config.HKDF_SALT_FILE_ENC).
    length     : int    Output key length in bytes (default 32).

    Returns
    -------
    bytes  Derived key of *length* bytes.
    """
    hkdf = HKDF(
        algorithm=_hashes.SHA256(),
        length=length,
        salt=label,
        info=b"cryptix-key-derivation",
    )
    return hkdf.derive(master_key)


def get_file_encryption_key(master_key: bytes) -> bytes:
    """Return the 32-byte key used for AES-256-GCM file encryption."""
    return derive_purpose_key(master_key, config.HKDF_SALT_FILE_ENC)


def get_db_encryption_key(master_key: bytes) -> bytes:
    """Return the 32-byte key used for AES-256-GCM database field encryption."""
    return derive_purpose_key(master_key, config.HKDF_SALT_DB_ENC)


def get_stego_key(master_key: bytes) -> bytes:
    """Return the 32-byte key used for steganography message encryption."""
    return derive_purpose_key(master_key, config.HKDF_SALT_STEGO)


def get_super_enc_subkey(master_key: bytes, cipher_name: str) -> bytes:
    """
    Return a sub-cipher key for Super Encryption.

    Parameters
    ----------
    cipher_name : str  One of 'vigenere', 'playfair', 'chacha20', 'blowfish'.
    """
    label = config.SUPER_ENC_LABELS.get(cipher_name)
    if label is None:
        raise ValueError(f"Unknown Super Encryption cipher: {cipher_name}")
    return derive_purpose_key(master_key, label)


def master_key_to_hex(master_key: bytes) -> str:
    """Encode master key as hex for session storage."""
    return master_key.hex()


def master_key_from_hex(hex_str: str) -> bytes:
    """Decode master key from hex (as stored in session)."""
    return bytes.fromhex(hex_str)
