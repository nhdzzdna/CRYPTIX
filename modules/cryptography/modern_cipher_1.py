"""
modules/cryptography/modern_cipher_1.py
────────────────────────────────────────
ChaCha20 Cipher (Modern Cipher #1)

Uses the cryptography library's ChaCha20 implementation.
Output is base64-encoded for text-safe storage.
Format: <nonce_hex>:<ciphertext_b64>
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


def chacha20_encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt *plaintext* with ChaCha20.

    Parameters
    ----------
    plaintext : str    UTF-8 text.
    key       : bytes  32-byte key.

    Returns
    -------
    str  "<nonce_hex>:<ciphertext_b64>"
    """
    if len(key) != 32:
        raise ValueError("ChaCha20 requires a 32-byte key.")

    nonce = os.urandom(16)  # ChaCha20 uses 16-byte nonce in cryptography lib
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()

    return f"{nonce.hex()}:{base64.b64encode(ct).decode()}"


def chacha20_decrypt(token: str, key: bytes) -> str:
    """
    Decrypt a token produced by chacha20_encrypt().

    Parameters
    ----------
    token : str    "<nonce_hex>:<ciphertext_b64>"
    key   : bytes  32-byte key.

    Returns
    -------
    str  Plaintext.
    """
    if len(key) != 32:
        raise ValueError("ChaCha20 requires a 32-byte key.")

    nonce_hex, ct_b64 = token.split(":", 1)
    nonce = bytes.fromhex(nonce_hex)
    ct = base64.b64decode(ct_b64)

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    plaintext_bytes = decryptor.update(ct) + decryptor.finalize()
    return plaintext_bytes.decode("utf-8")
