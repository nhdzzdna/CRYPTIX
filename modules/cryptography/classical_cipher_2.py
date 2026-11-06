"""
modules/cryptography/classical_cipher_2.py
───────────────────────────────────────────
Playfair Cipher (Classic Cipher #2)

Standard 5×5 Playfair using A–Z (I and J merged).
Input is uppercased; digits and spaces are passed through unchanged.
Filler X disisipkan saat enkripsi dan dibuang saat dekripsi.
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


def _letters_of(text: str) -> str:
    """Ekstrak huruf: huruf besar, J→I, hanya A–Z."""
    return re.sub(r"[^A-Za-z]", "", text).upper().replace("J", "I")


def _prepare_text(letters: str) -> list[tuple[str, int]]:
    """
    Bentuk daftar pasangan siap-sandi dari urutan *letters*.

    Mengembalikan tuple (huruf, indeks_huruf_asli). Huruf filler "X"
    dimiliki oleh huruf asli yang mendahuluinya sehingga posisinya dapat
    dipetakan kembali saat karakter non-huruf disisipkan pada hasil enkripsi.
    """
    prepared: list[tuple[str, int]] = []
    i = 0
    while i < len(letters):
        a = letters[i]
        if i + 1 < len(letters) and letters[i + 1] == a:
            prepared.append((a, i))
            prepared.append(("X", i))
            i += 1
        elif i + 1 < len(letters):
            prepared.append((a, i))
            prepared.append((letters[i + 1], i + 1))
            i += 2
        else:
            prepared.append((a, i))
            prepared.append(("X", i))
            i += 1
    return prepared


def playfair_encrypt(plaintext: str, key: str) -> str:
    """
    Encrypt *plaintext* with Playfair cipher.

    Karakter non-huruf dipertahankan pada posisinya. Semua huruf hasil
    pasangan (termasuk filler "X") ikut disertakan sehingga tidak ada
    huruf yang hilang saat enkripsi.

    Parameters
    ----------
    plaintext : str
    key       : str

    Returns
    -------
    str  Ciphertext (huruf A–Z + non-huruf asli, huruf besar).
    """
    table = _build_table(key)
    prepared = _prepare_text(_letters_of(plaintext))

    stream: list[str] = []
    for i in range(0, len(prepared), 2):
        a, b = prepared[i][0], prepared[i + 1][0]
        ra, ca = _find_position(table, a)
        rb, cb = _find_position(table, b)
        if ra == rb:
            stream += [table[ra][(ca + 1) % 5], table[rb][(cb + 1) % 5]]
        elif ca == cb:
            stream += [table[(ra + 1) % 5][ca], table[(rb + 1) % 5][cb]]
        else:
            stream += [table[ra][cb], table[rb][ca]]

    owners = [owner for _, owner in prepared]

    # Sisipkan non-huruf di posisi aslinya; satu huruf asli dapat memancarkan
    # lebih dari satu huruf sandi bila ada filler.
    result = []
    enc_idx = 0
    alpha_idx = 0
    for ch in plaintext.upper():
        if "A" <= ch <= "Z":
            while enc_idx < len(stream) and owners[enc_idx] == alpha_idx:
                result.append(stream[enc_idx])
                enc_idx += 1
            alpha_idx += 1
        else:
            result.append(ch)
    return "".join(result)


def playfair_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypt *ciphertext* produced by playfair_encrypt().

    Filler "X" yang disisipkan saat enkripsi (huruf kembar dan panjang
    ganjil) dibuang, sehingga keluaran hanya berisi huruf asli.

    Parameters
    ----------
    ciphertext : str
    key        : str

    Returns
    -------
    str  Plaintext (huruf A–Z, non-alpha dipertahankan di tempatnya).
    """
    table = _build_table(key)
    letters = _letters_of(ciphertext)
    # Must be even-length (was padded during encryption)
    if len(letters) % 2 != 0:
        letters += "X"

    decrypted_letters = []
    for i in range(0, len(letters), 2):
        a, b = letters[i], letters[i + 1]
        ra, ca = _find_position(table, a)
        rb, cb = _find_position(table, b)
        if ra == rb:
            decrypted_letters += [table[ra][(ca - 1) % 5], table[rb][(cb - 1) % 5]]
        elif ca == cb:
            decrypted_letters += [table[(ra - 1) % 5][ca], table[(rb - 1) % 5][cb]]
        else:
            decrypted_letters += [table[ra][cb], table[rb][ca]]

    # Re-insert non-alpha characters; drop X fillers aligned by position.
    result = []
    dec_iter = iter(decrypted_letters)
    for ch in ciphertext.upper():
        if "A" <= ch <= "Z":
            dec_ch = next(dec_iter, "")
            if dec_ch != "X":
                result.append(dec_ch)
        else:
            result.append(ch)
    return "".join(result)
