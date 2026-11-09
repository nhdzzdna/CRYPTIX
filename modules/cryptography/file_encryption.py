"""
modules/cryptography/file_encryption.py
────────────────────────────────────────
Enkripsi berkas AES-256-GCM per chunk 1 MiB.

Struktur berkas:
  header (37 byte) = magic "CRYPTIX1" (8) ‖ versi (1) ‖ ukuran chunk
      (4, big-endian) ‖ salt berkas acak (16) ‖ jumlah chunk (8, big-endian)
  badan             = chunk_0 ‖ chunk_1 ‖ ... ‖ chunk_n-1

  kunci_chunk = HKDF-SHA256(kunci_file, salt=salt berkas, info per tujuan)
  nonce       = indeks chunk sebagai counter 12 byte big-endian
  AAD chunk   = konteks berkas ‖ header ‖ indeks chunk (8 byte) ‖ penanda
      chunk terakhir (1 byte)

  Konteks berkas mengikat isi ke pemilik dan lokasinya; karena seluruh header
  ikut menjadi AAD, perubahan jumlah chunk maupun salt membuat semua tag GCM
  gagal. Penanda chunk terakhir menolak pemotongan ekor, dan indeks chunk
  menolak penukaran urutan chunk.

Penamaan: storage/encrypted_files/<heksadesimal_acak>.bin — nama asli tidak
ikut tersimpan di sistem berkas. Verifikasi: SHA-256 plaintext (cek setelah
dekripsi penuh) dan SHA-256 ciphertext (cek aset) dikembalikan kepada pemanggil
untuk disimpan di vault_files.
"""

import contextlib
import hashlib
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _hashes

MAGIC = b"CRYPTIX1"
VERSION = 1
CHUNK_SIZE = 1024 * 1024          # 1 MiB
SALT_LENGTH = 16
_HEADER_LENGTH = 8 + 1 + 4 + 16 + 8
_TAG_LENGTH = 16
_FILE_KEY_INFO = b"cryptix-file-chunk-v1"


def file_aad(user_id, stored_name: str) -> bytes:
    """
    AAD berkas = b"<user_id>:vault_files:<nama_simpan>".

    Ikat berkas ke pemilik dan lokasi simpannya sehingga dua berkas milik
    pengguna berbeda (atau dua baris berbeda) tidak dapat saling menukar isi.
    """
    return f"{user_id}:vault_files:{stored_name}".encode("utf-8")


# ── Header dan turunan kunci ─────────────────────────────────────────────────

def _build_header(salt: bytes, chunk_count: int) -> bytes:
    """Susun header tetap: magic, versi, ukuran chunk, salt, jumlah chunk."""
    return (
        MAGIC
        + bytes([VERSION])
        + CHUNK_SIZE.to_bytes(4, "big")
        + salt
        + chunk_count.to_bytes(8, "big")
    )


def _read_header(header: bytes) -> tuple[bytes, int, int]:
    """Baca header; kembalikan (salt, ukuran_chunk, jumlah_chunk)."""
    if len(header) != _HEADER_LENGTH or header[:8] != MAGIC:
        raise ValueError("Berkas bukan format terenkripsi CRYPTIX.")
    if header[8] != VERSION:
        raise ValueError("Versi berkas terenkripsi tidak dikenal.")
    chunk_size = int.from_bytes(header[9:13], "big")
    salt = header[13:29]
    chunk_count = int.from_bytes(header[29:37], "big")
    if chunk_size <= 0:
        raise ValueError("Ukuran chunk pada header tidak valid.")
    return salt, chunk_size, chunk_count


def _chunk_key(file_key: bytes, salt: bytes) -> bytes:
    """Kunci per berkas = HKDF(kunci file, salt acak berkas)."""
    return HKDF(
        algorithm=_hashes.SHA256(), length=32, salt=salt, info=_FILE_KEY_INFO
    ).derive(file_key)


def _chunk_nonce(index: int) -> bytes:
    """Nonce = counter indeks chunk, 12 byte big-endian."""
    return index.to_bytes(12, "big")


def _chunk_aad(context: bytes, header: bytes, index: int, is_last: bool) -> bytes:
    """AAD per chunk = konteks berkas ‖ header ‖ indeks ‖ penanda chunk terakhir."""
    return (
        context
        + header
        + index.to_bytes(8, "big")
        + (b"\x01" if is_last else b"\x00")
    )


@contextlib.contextmanager
def _open_read(source):
    """Buka path sebagai stream biner, atau lewati bila sudah berupa stream."""
    if hasattr(source, "read"):
        yield source
    else:
        with open(source, "rb") as handle:
            yield handle


@contextlib.contextmanager
def _open_write(sink):
    """Buka path tujuan sebagai stream tulis, atau lewati bila sudah stream."""
    if hasattr(sink, "write"):
        yield sink
    else:
        parent = os.path.dirname(sink)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(sink, "wb") as handle:
            yield handle


def _stream_size(handle) -> int:
    """Ukuran sisa data pada stream; mensyaratkan stream seekable."""
    try:
        offset = handle.tell()
        handle.seek(0, os.SEEK_END)
        size = handle.tell() - offset
        handle.seek(offset)
        return size
    except (AttributeError, OSError, ValueError) as exc:
        raise ValueError(
            "Input enkripsi harus path berkas atau stream biner seekable."
        ) from exc


def _file_layout(handle) -> tuple[bytes, bytes, int, int, int]:
    """
    Baca header dan hitung tata letak chunk.

    Kembalikan (header, salt, ukuran_chunk, jumlah_chunk,
    panjang_ciphertext_chunk_terakhir).
    """
    handle.seek(0, os.SEEK_END)
    file_size = handle.tell()
    handle.seek(0)
    header = handle.read(_HEADER_LENGTH)
    salt, chunk_size, chunk_count = _read_header(header)

    if chunk_count == 0:
        if file_size != _HEADER_LENGTH:
            raise ValueError("Jumlah chunk pada header tidak sesuai ukuran berkas.")
        return header, salt, chunk_size, 0, 0

    last_ct = file_size - _HEADER_LENGTH - (chunk_count - 1) * (chunk_size + _TAG_LENGTH)
    if last_ct < _TAG_LENGTH:
        raise ValueError("Berkas terpotong atau jumlah chunk tidak sesuai.")
    return header, salt, chunk_size, chunk_count, last_ct


def _decrypt_chunk(
    cipher: AESGCM,
    handle,
    context: bytes,
    header: bytes,
    index: int,
    chunk_size: int,
    ct_length: int,
    is_last: bool,
) -> bytes:
    """Baca dan dekripsi satu chunk berdasarkan offset tata letak."""
    handle.seek(_HEADER_LENGTH + index * (chunk_size + _TAG_LENGTH))
    blob = handle.read(ct_length)
    if len(blob) != ct_length:
        raise ValueError("Berkas terpotong saat membaca chunk.")
    return cipher.decrypt(
        _chunk_nonce(index), blob, _chunk_aad(context, header, index, is_last)
    )


# ── API utama ────────────────────────────────────────────────────────────────

def encrypt_stream(input, output, key: bytes, aad: bytes) -> dict:
    """
    Enkripsi seluruh isi *input* per chunk menuju *output*.

    Parameters
    ----------
    input  : str | file-like  Path atau stream biner seekable berisi plaintext.
    output : str | file-like  Path tujuan (atau stream) berkas terenkripsi.
    key    : bytes            Kunci 32 byte, purpose_key(dek, "file").
    aad    : bytes            Konteks berkas, misalnya file_aad(user_id, nama).

    Returns
    -------
    dict berisi ``sha256_plaintext``, ``sha256_ciphertext``, ``size``,
    dan ``chunk_count``.

    Catatan
    -------
    Plaintext tidak pernah ditulis ke disk; seluruh proses berjalan streaming.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM memerlukan kunci 32 byte.")
    if not isinstance(aad, bytes) or not aad:
        raise ValueError("AAD wajib diisi agar berkas terikat pada pemiliknya.")

    with _open_read(input) as source:
        size = _stream_size(source)
        chunk_count = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
        salt = os.urandom(SALT_LENGTH)
        header = _build_header(salt, chunk_count)
        cipher = AESGCM(_chunk_key(key, salt))
        plain_hash = hashlib.sha256()
        cipher_hash = hashlib.sha256()

        with _open_write(output) as sink:
            cipher_hash.update(header)
            sink.write(header)
            for index in range(chunk_count):
                chunk = source.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    raise ValueError("Ukuran input berubah saat dibaca.")
                is_last = index == chunk_count - 1
                blob = cipher.encrypt(
                    _chunk_nonce(index), chunk, _chunk_aad(aad, header, index, is_last)
                )
                plain_hash.update(chunk)
                cipher_hash.update(blob)
                sink.write(blob)
            if source.read(1):
                raise ValueError("Ukuran input berubah saat dibaca.")

    return {
        "sha256_plaintext": plain_hash.hexdigest(),
        "sha256_ciphertext": cipher_hash.hexdigest(),
        "size": size,
        "chunk_count": chunk_count,
    }


def decrypt_all(path, key: bytes, aad: bytes) -> bytes:
    """
    Dekripsi seluruh chunk berkas dan kembalikan plaintext.

    Parameters
    ----------
    path : str     Path berkas terenkripsi di storage/encrypted_files.
    key  : bytes   Kunci 32 byte yang sama dengan saat enkripsi.
    aad  : bytes   Konteks berkas yang sama dengan saat enkripsi.

    Returns
    -------
    bytes  Plaintext utuh.

    Raises
    ------
    cryptography.exceptions.InvalidTag  Tag GCM gagal: data dimodifikasi,
        kunci salah, atau AAD berbeda (berkas dipindahkan).
    ValueError  Struktur berkas tidak valid atau terpotong.

    Verifikasi SHA-256 plaintext terhadap nilai tercatat dilakukan pemanggil
    setelah fungsi ini selesai.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM memerlukan kunci 32 byte.")
    if not isinstance(aad, bytes) or not aad:
        raise ValueError("AAD wajib diisi agar berkas terikat pada pemiliknya.")
    with open(path, "rb") as handle:
        header, salt, chunk_size, chunk_count, last_ct = _file_layout(handle)
        if chunk_count == 0:
            return b""
        cipher = AESGCM(_chunk_key(key, salt))
        parts = []
        for index in range(chunk_count):
            is_last = index == chunk_count - 1
            ct_length = last_ct if is_last else chunk_size + _TAG_LENGTH
            parts.append(
                _decrypt_chunk(
                    cipher, handle, aad, header, index, chunk_size, ct_length, is_last
                )
            )
        return b"".join(parts)


def decrypt_range(path, key: bytes, aad: bytes, start: int, end: int) -> bytes:
    """
    Dekripsi hanya chunk yang beririsan dengan rentang byte [start, end].

    Keduanya inklusif, dihitung pada plaintext. Bila rentang melewati batas
    akhir berkas, ujungnya dipotong; bila mulai di luar berkas, hasil b"".

    Parameters
    ----------
    path  : str    Path berkas terenkripsi.
    key   : bytes  Kunci 32 byte.
    aad   : bytes  Konteks berkas yang sama dengan saat enkripsi.
    start : int    Byte pertama (inklusif).
    end   : int    Byte terakhir (inklusif).
    """
    if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end < start:
        raise ValueError("Rentang byte tidak valid.")
    if len(key) != 32:
        raise ValueError("AES-256-GCM memerlukan kunci 32 byte.")
    if not isinstance(aad, bytes) or not aad:
        raise ValueError("AAD wajib diisi agar berkas terikat pada pemiliknya.")

    with open(path, "rb") as handle:
        header, salt, chunk_size, chunk_count, last_ct = _file_layout(handle)
        if chunk_count == 0:
            return b""
        total = (chunk_count - 1) * chunk_size + (last_ct - _TAG_LENGTH)
        if start >= total:
            return b""
        end = min(end, total - 1)

        cipher = AESGCM(_chunk_key(key, salt))
        parts = []
        for index in range(start // chunk_size, end // chunk_size + 1):
            is_last = index == chunk_count - 1
            ct_length = last_ct if is_last else chunk_size + _TAG_LENGTH
            plain = _decrypt_chunk(
                cipher, handle, aad, header, index, chunk_size, ct_length, is_last
            )
            offset = index * chunk_size
            low = max(start, offset) - offset
            high = min(end, offset + len(plain) - 1) - offset
            parts.append(plain[low : high + 1])
        return b"".join(parts)


def generate_stored_name() -> str:
    """Nama simpan acak heksadesimal tanpa ekstensi asli, misalnya "<hex>.bin"."""
    return f"{secrets.token_hex(16)}.bin"
