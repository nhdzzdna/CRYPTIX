"""
modules/cryptography/database_encryption.py
─────────────────────────────────────────────
AES-256-GCM encryption for sensitive database fields.

Used by:
  • Account Vault  (site_name, username, password, url, notes)
  • Secure Notes   (title, content)

The DB encryption key is derived from the master key via a separate HKDF
label (config.HKDF_SALT_DB_ENC) so it is independent from the file key.

Format stored in DB columns:
  "<nonce_hex>:<tag_hex>:<ciphertext_b64>"
  All in a single text field for simplicity.

Row-level nonces: each field in a row shares the row nonce (stored in the
nonce column) and the tag column stores only the outer tag.
For multi-field rows we encrypt with a composite and store per the schema.
"""

import os
import base64
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_field(plaintext: str, db_key: bytes) -> str:
    """
    Encrypt a single text field with AES-256-GCM.

    Parameters
    ----------
    plaintext : str    The sensitive value to protect.
    db_key    : bytes  32-byte derived key from key_management.get_db_encryption_key().

    Returns
    -------
    str  "<nonce_hex>:<tag_hex>:<ciphertext_b64>" — safe to store in SQLite TEXT.
    """
    if len(db_key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")

    nonce = os.urandom(12)
    aesgcm = AESGCM(db_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    return (
        f"{nonce.hex()}:{tag.hex()}:{base64.b64encode(ciphertext).decode()}"
    )


def decrypt_field(token: str, db_key: bytes) -> str:
    """
    Decrypt a field encrypted by encrypt_field().

    Parameters
    ----------
    token  : str    "<nonce_hex>:<tag_hex>:<ciphertext_b64>"
    db_key : bytes  Same 32-byte key.

    Returns
    -------
    str  Decrypted plaintext.

    Raises
    ------
    cryptography.exceptions.InvalidTag  if the ciphertext was tampered.
    """
    parts = token.split(":", 2)
    if len(parts) != 3:
        raise ValueError("Invalid encrypted field format.")

    nonce_hex, tag_hex, ct_b64 = parts
    nonce = bytes.fromhex(nonce_hex)
    tag   = bytes.fromhex(tag_hex)
    ct    = base64.b64decode(ct_b64)

    aesgcm = AESGCM(db_key)
    plaintext_bytes = aesgcm.decrypt(nonce, ct + tag, None)
    return plaintext_bytes.decode("utf-8")


def encrypt_record(fields: dict[str, str], db_key: bytes) -> dict[str, str]:
    """
    Encrypt every string value in *fields* dict.

    Parameters
    ----------
    fields : dict  {'site_name': 'Google', 'username': 'alice', ...}
    db_key : bytes

    Returns
    -------
    dict  Same keys, encrypted values.
    """
    return {k: encrypt_field(v, db_key) if v else "" for k, v in fields.items()}


def decrypt_record(fields: dict[str, str], db_key: bytes) -> dict[str, str]:
    """
    Decrypt every non-empty string value in *fields* dict.

    Parameters
    ----------
    fields : dict  {'site_name_enc': '<token>', ...}
    db_key : bytes

    Returns
    -------
    dict  Same keys, decrypted values.
    """
    return {k: decrypt_field(v, db_key) if v else "" for k, v in fields.items()}
