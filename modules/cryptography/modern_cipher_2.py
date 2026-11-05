"""
modules/cryptography/modern_cipher_2.py
────────────────────────────────────────
Blowfish Cipher in CBC mode with PKCS#7 padding (Modern Cipher #2)

Uses PyCryptodome's Blowfish implementation.
Output format: "<iv_hex>:<ciphertext_b64>"
"""

import os
import base64

from Crypto.Cipher import Blowfish as _Blowfish
from Crypto.Util.Padding import pad, unpad


_BLOCK_SIZE = 8   # Blowfish block size in bytes


def blowfish_encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt *plaintext* with Blowfish-CBC + PKCS#7 padding.

    Parameters
    ----------
    plaintext : str    UTF-8 text.
    key       : bytes  4–56 bytes key (we use 32 bytes).

    Returns
    -------
    str  "<iv_hex>:<ciphertext_b64>"
    """
    iv = os.urandom(_BLOCK_SIZE)
    cipher = _Blowfish.new(key[:56], _Blowfish.MODE_CBC, iv)  # key max 56 bytes
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), _BLOCK_SIZE))
    return f"{iv.hex()}:{base64.b64encode(ct).decode()}"


def blowfish_decrypt(token: str, key: bytes) -> str:
    """
    Decrypt a token produced by blowfish_encrypt().

    Parameters
    ----------
    token : str    "<iv_hex>:<ciphertext_b64>"
    key   : bytes  Same key used for encryption.

    Returns
    -------
    str  Plaintext.
    """
    iv_hex, ct_b64 = token.split(":", 1)
    iv = bytes.fromhex(iv_hex)
    ct = base64.b64decode(ct_b64)

    cipher = _Blowfish.new(key[:56], _Blowfish.MODE_CBC, iv)
    plaintext_bytes = unpad(cipher.decrypt(ct), _BLOCK_SIZE)
    return plaintext_bytes.decode("utf-8")
