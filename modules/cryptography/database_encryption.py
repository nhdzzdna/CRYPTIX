"""
modules/cryptography/database_encryption.py
────────────────────────────────────────────
Enkripsi AES-256-GCM untuk field sensitif basis data.

Format tersimpan di kolom teks:
  "v1:<nonce_hex>:<ciphertext_hex>"
  • nonce 12 byte acak setiap kali field ditulis.
  • ciphertext = keluaran AESGCM.encrypt (ciphertext ‖ tag 16 byte).
  • AAD = "<user_id>:<tabel>:<kolom>" sehingga token tidak dapat dipindahkan
    ke pengguna lain, tabel lain, maupun kolom lain.

Kunci: purpose_key(dek, "database") dari key_management.

Field yang dilindungi:
  • account_vault  (site_name_enc, username_enc, password_enc, url_enc,
                    notes_enc)
  • secure_notes   (title_enc, content_enc)
  • vault_files.original_name dan stego_images.original_name
Metadata penyaringan (file_type, file_size) tetap polos.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VERSION = "v1"
_NONCE_LENGTH = 12


def field_aad(user_id, table: str, column: str) -> bytes:
    """
    AAD field = b"<user_id>:<tabel>:<kolom>".

    Ikat token ke pemilik, tabel, dan kolom asalnya.
    """
    if not table or not column:
        raise ValueError("Tabel dan kolom wajib diisi untuk AAD.")
    return f"{user_id}:{table}:{column}".encode("utf-8")


def encrypt_field(plaintext: str, key: bytes, aad: bytes) -> str:
    """
    Enkripsi satu field teks dengan AES-256-GCM.

    Parameters
    ----------
    plaintext : str    Nilai sensitif yang akan dilindungi.
    key       : bytes  Kunci 32 byte (purpose_key(dek, "database")).
    aad       : bytes  Hasil field_aad() untuk field ini.

    Returns
    -------
    str  "v1:<nonce_hex>:<ciphertext_hex>" — aman disimpan di SQLite TEXT.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM memerlukan kunci 32 byte.")
    if not isinstance(aad, bytes) or not aad:
        raise ValueError("AAD wajib diisi agar token terikat pada kolomnya.")

    nonce = os.urandom(_NONCE_LENGTH)
    blob = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return f"{_VERSION}:{nonce.hex()}:{blob.hex()}"


def decrypt_field(token: str, key: bytes, aad: bytes) -> str:
    """
    Dekripsi field hasil encrypt_field().

    Parameters
    ----------
    token : str    "v1:<nonce_hex>:<ciphertext_hex>".
    key   : bytes  Kunci yang sama dengan saat enkripsi.
    aad   : bytes  field_aad() yang sama; berbeda berarti token dipindahkan.

    Returns
    -------
    str  Plaintext.

    Raises
    ------
    ValueError  Jika format salah, versi tidak dikenal, kunci tidak cocok,
                AAD tidak cocok, atau data dimodifikasi.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM memerlukan kunci 32 byte.")
    try:
        version, nonce_hex, body_hex = token.split(":")
    except (AttributeError, ValueError) as exc:
        raise ValueError("Format field terenkripsi tidak valid.") from exc
    if version != _VERSION:
        raise ValueError("Versi field terenkripsi tidak dikenal.")

    try:
        blob = AESGCM(key).decrypt(
            bytes.fromhex(nonce_hex), bytes.fromhex(body_hex), aad
        )
    except Exception as exc:
        raise ValueError(
            "Field tidak dapat dibuka: kunci, AAD, atau datanya tidak cocok."
        ) from exc
    return blob.decode("utf-8")


def encrypt_record(fields: dict[str, str], key: bytes, user_id, table: str) -> dict[str, str]:
    """
    Enkripsi setiap nilai pada dict; kunci AAD memakai nama kolomnya.

    Parameters
    ----------
    fields  : dict  {'site_name_enc': 'Contoh', ...} — nama kunci = nama kolom.
    key     : bytes Kunci 32 byte.
    user_id : int   Pemilik baris.
    table   : str   Nama tabel asal.

    Returns
    -------
    dict  Kolom sama, nilai terenkripsi; nilai kosong tetap "".
    """
    return {
        column: encrypt_field(value, key, field_aad(user_id, table, column))
        if value else ""
        for column, value in fields.items()
    }


def decrypt_record(fields: dict[str, str], key: bytes, user_id, table: str) -> dict[str, str]:
    """
    Dekripsi setiap nilai pada dict hasil baris tabel.

    Nilai kosong atau NULL dilewatkan menjadi "".

    Raises
    ------
    ValueError  Jika salah satu nilai tidak dapat dibuka.
    """
    return {
        column: decrypt_field(value, key, field_aad(user_id, table, column))
        if value else ""
        for column, value in fields.items()
    }
