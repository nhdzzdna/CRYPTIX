"""
modules/cryptography/classical_cipher_1.py
───────────────────────────────────────────
Vigenere Cipher (Classic Cipher #1)

Standard Vigenere cipher operating on printable ASCII (32–126).
Key is cycled character-by-character; non-printable bytes are passed through.
"""


def _key_stream(key: str, length: int):
    """Generate cycled key character indices (0-94 relative to ASCII 32)."""
    key_clean = [ord(c) - 32 for c in key if 32 <= ord(c) <= 126]
    if not key_clean:
        raise ValueError("Vigenere key must contain at least one printable ASCII character.")
    for i in range(length):
        yield key_clean[i % len(key_clean)]


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """
    Encrypt *plaintext* with Vigenere cipher using *key*.

    Only printable ASCII characters (ord 32–126) are shifted;
    all other characters are passed through unchanged.

    Parameters
    ----------
    plaintext : str
    key       : str  Any printable ASCII string.

    Returns
    -------
    str  Ciphertext.
    """
    printable = [c for c in plaintext if 32 <= ord(c) <= 126]
    ks = _key_stream(key, len(printable))
    result = []
    ki = iter(ks)
    for ch in plaintext:
        if 32 <= ord(ch) <= 126:
            shift = next(ki)
            result.append(chr((ord(ch) - 32 + shift) % 95 + 32))
        else:
            result.append(ch)
    return "".join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypt *ciphertext* encrypted with vigenere_encrypt().

    Parameters
    ----------
    ciphertext : str
    key        : str  Same key used for encryption.

    Returns
    -------
    str  Plaintext.
    """
    printable = [c for c in ciphertext if 32 <= ord(c) <= 126]
    ks = _key_stream(key, len(printable))
    result = []
    ki = iter(ks)
    for ch in ciphertext:
        if 32 <= ord(ch) <= 126:
            shift = next(ki)
            result.append(chr((ord(ch) - 32 - shift) % 95 + 32))
        else:
            result.append(ch)
    return "".join(result)
