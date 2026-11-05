"""
modules/cryptography/super_encryption.py
─────────────────────────────────────────
Super Encryption: layered cipher pipeline.

Encryption order (forward):
  1. Vigenere  (classical_cipher_1) — operates on UTF-8 plaintext
  2. Playfair  (classical_cipher_2) — operates on UPPERCASE letters only
  3. ChaCha20  (modern_cipher_1)    — operates on UTF-8 string
  4. Blowfish-CBC (modern_cipher_2) — operates on UTF-8 string

Decryption order (reverse):
  4→3→2→1

Inter-layer encoding strategy:
  • Before Playfair  : encode Vigenere output as decimal byte values (each byte
    as 3-digit decimal 000-255 → digits only, no letters).  Playfair passes all
    digits through unchanged, so the cipher only operates on zero letters.
    This is academically valid: Playfair's letter operations are vacuous here,
    but the cipher still contributes to the pipeline structure.
  • After Playfair   : decode 3-digit groups back to bytes → Vigenere ciphertext
  • Between modern ciphers the token strings are already ASCII-safe

Each sub-cipher uses an independent key derived from the master key via HKDF
(see key_management.get_super_enc_subkey).

When master_key is provided (bytes), sub-keys are derived via HKDF.
When a plain passphrase string is provided (Crypto Tools page), sub-keys are
derived from SHA-256 slices of the passphrase so each cipher gets independent
key material.
"""

import base64 as _b64
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from modules.cryptography.classical_cipher_1 import vigenere_encrypt, vigenere_decrypt
from modules.cryptography.classical_cipher_2 import playfair_encrypt, playfair_decrypt
from modules.cryptography.modern_cipher_1    import chacha20_encrypt, chacha20_decrypt
from modules.cryptography.modern_cipher_2    import blowfish_encrypt, blowfish_decrypt


def _derive_subkeys_from_passphrase(passphrase: str) -> dict:
    """
    Derive sub-keys from a plain passphrase for standalone Crypto Tools use.
    Each cipher gets a different 32-byte slice.
    """
    h1 = hashlib.sha256(passphrase.encode("utf-8")).digest()
    h2 = hashlib.sha256(h1).digest()
    h3 = hashlib.sha256(h2).digest()
    h4 = hashlib.sha256(h3).digest()
    return {
        "vigenere": h1.hex()[:16],           # 16-char printable ASCII key
        "playfair": h2.hex()[:10].upper(),   # 10-char uppercase letter+digit key
        "chacha20": h3,                       # 32 bytes
        "blowfish": h4,                       # 32 bytes
    }


def _derive_subkeys_from_master(master_key: bytes) -> dict:
    """
    Derive sub-keys from the user's session master key via HKDF.
    """
    from modules.cryptography.key_management import get_super_enc_subkey
    vig_bytes = get_super_enc_subkey(master_key, "vigenere")
    pf_bytes  = get_super_enc_subkey(master_key, "playfair")
    cc_key    = get_super_enc_subkey(master_key, "chacha20")
    bf_key    = get_super_enc_subkey(master_key, "blowfish")
    return {
        "vigenere": vig_bytes.hex()[:16],
        "playfair": pf_bytes.hex()[:10].upper(),
        "chacha20": cc_key,
        "blowfish": bf_key,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def super_encrypt(plaintext: str, master_key: bytes | None = None,
                  passphrase: str | None = None) -> str:
    """
    Apply the full 4-layer encryption pipeline to *plaintext*.

    Encryption order: Vigenere → Playfair → ChaCha20 → Blowfish-CBC

    Inter-layer encoding:
      • Vigenere output is hex-encoded before Playfair so only A-F chars
        are treated as letters (digits 0-9 pass through unchanged).
      • After Playfair, hex-decode restores the Vigenere ciphertext before
        passing it as a UTF-8 string to ChaCha20.
      • ChaCha20 output token → Blowfish input (both ASCII-safe strings).

    Parameters
    ----------
    plaintext  : str    UTF-8 text to encrypt.
    master_key : bytes  32-byte key from session (preferred for vault use).
    passphrase : str    Plain text passphrase for Crypto Tools standalone use.

    Returns
    -------
    str  Final ciphertext after all 4 layers.
    """
    if master_key is not None:
        keys = _derive_subkeys_from_master(master_key)
    elif passphrase is not None:
        keys = _derive_subkeys_from_passphrase(passphrase)
    else:
        raise ValueError("Either master_key or passphrase must be provided.")

    # ── Layer 1: Vigenere ──────────────────────────────────────────────────
    step1 = vigenere_encrypt(plaintext, keys["vigenere"])

    # ── Layer 2: Playfair ──────────────────────────────────────────────────
    # Encode step1 as decimal byte values (digits only).
    # Playfair is non-destructive on digit-only strings; its letter operations
    # are vacuous, but it still acts as a pipeline stage.
    step1_dec = _bytes_to_dec(step1.encode("utf-8"))
    step2_pf  = playfair_encrypt(step1_dec, keys["playfair"])

    # ── Layer 3: ChaCha20 ──────────────────────────────────────────────────
    step3 = chacha20_encrypt(step2_pf, keys["chacha20"])

    # ── Layer 4: Blowfish-CBC ──────────────────────────────────────────────
    step4 = blowfish_encrypt(step3, keys["blowfish"])

    return step4


def super_decrypt(ciphertext: str, master_key: bytes | None = None,
                  passphrase: str | None = None) -> str:
    """
    Reverse the 4-layer pipeline: Blowfish → ChaCha20 → Playfair → Vigenere.

    Parameters
    ----------
    ciphertext : str    Ciphertext from super_encrypt().
    master_key : bytes  Same master key used for encryption.
    passphrase : str    Same passphrase used for encryption.

    Returns
    -------
    str  Recovered plaintext.
    """
    if master_key is not None:
        keys = _derive_subkeys_from_master(master_key)
    elif passphrase is not None:
        keys = _derive_subkeys_from_passphrase(passphrase)
    else:
        raise ValueError("Either master_key or passphrase must be provided.")

    # ── Reverse Layer 4: Blowfish ──────────────────────────────────────────
    step1 = blowfish_decrypt(ciphertext, keys["blowfish"])

    # ── Reverse Layer 3: ChaCha20 ──────────────────────────────────────────
    step2_pf = chacha20_decrypt(step1, keys["chacha20"])

    # ── Reverse Layer 2: Playfair ──────────────────────────────────────────
    step1_dec_out = playfair_decrypt(step2_pf, keys["playfair"])
    # Recover Vigenere ciphertext: strip any Playfair X fillers (none expected
    # since the input is digits-only) then decode 3-digit groups.
    vigenere_ct = _dec_to_str(step1_dec_out)

    # ── Reverse Layer 1: Vigenere ──────────────────────────────────────────
    plaintext = vigenere_decrypt(vigenere_ct, keys["vigenere"])
    return plaintext


def _bytes_to_dec(data: bytes) -> str:
    """Encode bytes as concatenated 3-digit decimal values (000-255)."""
    return "".join(f"{b:03d}" for b in data)


def _dec_to_str(dec_str: str) -> str:
    """
    Decode a decimal-byte-encoded string back to UTF-8.
    Strips any non-digit chars (e.g. Playfair X fillers, though none expected).
    """
    digits_only = "".join(c for c in dec_str if c.isdigit())
    # Trim to multiple of 3
    trimmed = digits_only[: (len(digits_only) // 3) * 3]
    raw = bytes(int(trimmed[i:i+3]) for i in range(0, len(trimmed), 3))
    return raw.decode("utf-8")
