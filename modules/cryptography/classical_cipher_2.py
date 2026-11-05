"""
modules/cryptography/classical_cipher_2.py
───────────────────────────────────────────
Playfair Cipher (Classic Cipher #2)

Standard 5×5 Playfair using A–Z (I and J merged).
Input is uppercased; digits and spaces are passed through unchanged.
"""

import re


def _build_table(key: str) -> list[list[str]]:
    """Build the 5×5 Playfair key table."""
    seen = set()
    sequence = []
    # Process key, then alphabet
    for ch in (key.upper() + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        ch = "I" if ch == "J" else ch
        if ch.isalpha() and ch not in seen:
            seen.add(ch)
            sequence.append(ch)
    # Fill 5×5 grid
    table = [sequence[i * 5:(i + 1) * 5] for i in range(5)]
    return table


def _find_position(table: list[list[str]], ch: str) -> tuple[int, int]:
    ch = "I" if ch == "J" else ch
    for r, row in enumerate(table):
        if ch in row:
            return r, row.index(ch)
    raise ValueError(f"Character '{ch}' not in Playfair table.")


def _prepare_text(text: str) -> list[str]:
    """
    Clean text: uppercase, replace J→I, keep only A-Z, insert X fillers
    between double-letters in a pair, and pad to even length.
    """
    text = text.upper().replace("J", "I")
    letters = re.sub(r"[^A-Z]", "", text)
    pairs = []
    i = 0
    while i < len(letters):
        a = letters[i]
        if i + 1 < len(letters):
            b = letters[i + 1]
            if a == b:
                pairs.extend([a, "X"])
                i += 1
            else:
                pairs.extend([a, b])
                i += 2
        else:
            pairs.extend([a, "X"])
            i += 1
    return pairs


def playfair_encrypt(plaintext: str, key: str) -> str:
    """
    Encrypt *plaintext* with Playfair cipher.

    Non-alphabetic characters are preserved in-place after the cipher
    operates on the extracted letters.

    Parameters
    ----------
    plaintext : str
    key       : str

    Returns
    -------
    str  Ciphertext (uppercase letters + original non-alpha chars).
    """
    table = _build_table(key)
    letters_only = re.sub(r"[^A-Za-z]", "", plaintext).upper().replace("J", "I")
    prepared = _prepare_text(letters_only)

    encrypted_letters = []
    for i in range(0, len(prepared), 2):
        a, b = prepared[i], prepared[i + 1]
        ra, ca = _find_position(table, a)
        rb, cb = _find_position(table, b)
        if ra == rb:
            encrypted_letters += [table[ra][(ca + 1) % 5], table[rb][(cb + 1) % 5]]
        elif ca == cb:
            encrypted_letters += [table[(ra + 1) % 5][ca], table[(rb + 1) % 5][cb]]
        else:
            encrypted_letters += [table[ra][cb], table[rb][ca]]

    # Re-insert non-alpha characters at original positions
    result = []
    enc_iter = iter(encrypted_letters)
    for ch in plaintext.upper():
        ch = "I" if ch == "J" else ch
        if ch.isalpha():
            result.append(next(enc_iter, ""))
        else:
            result.append(ch)
    return "".join(result)


def playfair_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypt *ciphertext* produced by playfair_encrypt().

    Parameters
    ----------
    ciphertext : str
    key        : str

    Returns
    -------
    str  Plaintext (X fillers may still be present for even-length pairs).
    """
    table = _build_table(key)
    letters_only = re.sub(r"[^A-Za-z]", "", ciphertext).upper().replace("J", "I")
    # Must be even-length (was padded during encryption)
    if len(letters_only) % 2 != 0:
        letters_only += "X"

    decrypted_letters = []
    for i in range(0, len(letters_only), 2):
        a, b = letters_only[i], letters_only[i + 1]
        ra, ca = _find_position(table, a)
        rb, cb = _find_position(table, b)
        if ra == rb:
            decrypted_letters += [table[ra][(ca - 1) % 5], table[rb][(cb - 1) % 5]]
        elif ca == cb:
            decrypted_letters += [table[(ra - 1) % 5][ca], table[(rb - 1) % 5][cb]]
        else:
            decrypted_letters += [table[ra][cb], table[rb][ca]]

    # Re-insert non-alpha characters
    result = []
    dec_iter = iter(decrypted_letters)
    for ch in ciphertext.upper():
        ch = "I" if ch == "J" else ch
        if ch.isalpha():
            result.append(next(dec_iter, ""))
        else:
            result.append(ch)
    return "".join(result)
