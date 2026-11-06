"""
modules/authentication/password_hash.py
────────────────────────────────────────
PBKDF2-HMAC-SHA256 password hashing.

Security properties:
  • Random 32-byte salt per user (os.urandom)
  • 600 000 iterations (OWASP 2023 recommendation)
  • Constant-time comparison via hmac.compare_digest
"""

import hashlib
import hmac
import os

import config


def hash_password(password: str) -> tuple[str, str]:
    """
    Hash *password* with a fresh random salt.

    Returns
    -------
    (hash_hex, salt_hex)
        Both are hex strings safe to store in the database.
    """
    salt: bytes = os.urandom(config.SALT_LENGTH)
    dk: bytes = hashlib.pbkdf2_hmac(
        config.PBKDF2_HASH_ALGO,
        password.encode("utf-8"),
        salt,
        config.PBKDF2_ITERATIONS,
    )
    return dk.hex(), salt.hex()


def verify_password(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    """
    Verify *password* against a stored hash.

    Uses ``hmac.compare_digest`` to prevent timing attacks.

    Returns
    -------
    bool
        True if the password is correct.
    """
    salt: bytes = bytes.fromhex(salt_hex)
    dk: bytes = hashlib.pbkdf2_hmac(
        config.PBKDF2_HASH_ALGO,
        password.encode("utf-8"),
        salt,
        config.PBKDF2_ITERATIONS,
    )
    return hmac.compare_digest(dk.hex(), stored_hash_hex)
