"""
modules/steganography/lsb.py
──────────────────────────────
LSB (Least Significant Bit) untuk gambar PNG.

Format muatan:
  • 14 byte header ditulis berurutan pada 112 bit pertama:
      magic "CRXS" | versi (1) | jenis (0 teks, 1 berkas) |
      panjang muatan (uint32 besar) | CRC32 muatan (uint32 besar)
  • Muatan terenkripsi ditulis pada posisi bit yang diacak PRNG numpy
    yang diseed kunci steganografi; posisi diproses per blok agar hemat
    memori.

Kunci steganografi: purpose_key(DEK, "stego") atau PBKDF2-HMAC-SHA256
(passphrase, salt tetap). Kunci menentukan urutan posisi bit, sehingga
gambar tanpa pesan ditolak oleh magic dan kunci yang salah ditolak oleh
CRC32.

Muatan teks dienkripsi dengan Super Encryption; muatan berkas selalu
dienkripsi AES-256-GCM. Enkripsi teks aktif secara default.

Kapasitas = (lebar × tinggi × 3 − 112) / 8 byte.
Dimensi gambar pembawa maksimum 4000 × 4000 piksel.
"""

import hashlib
import os
import struct
import zlib

import numpy as np
from PIL import Image

import config
from modules.strings import MSG

MAGIC = b"CRXS"
VERSION = 1
TYPE_TEXT = 0
TYPE_FILE = 1
HEADER_STRUCT = struct.Struct(">4sBBII")
HEADER_BITS = HEADER_STRUCT.size * 8          # 112
MAX_DIMENSION = 4000
_BLOCK_BITS = 65536                           # 8 KiB posisi per blok acak
_STEGO_PBKDF2_SALT = b"cryptix-stego-passphrase-v1"
_SUPER_PREFIX = "CXSE2."
_FILE_SEP = b"\x00"


# ── Kunci dan urutan posisi ──────────────────────────────────────────────────

def _stego_key(master_key: bytes | None, passphrase: str | None) -> bytes | None:
    """Kunci steganografi 32 byte: PBKDF2(passphrase) atau purpose_key(DEK)."""
    if passphrase is not None:
        return hashlib.pbkdf2_hmac(
            config.PBKDF2_HASH_ALGO,
            passphrase.encode("utf-8"),
            _STEGO_PBKDF2_SALT,
            config.SUPER_ENC_PBKDF2_ITERATIONS,
            dklen=32,
        )
    if master_key is not None:
        from modules.cryptography.key_management import purpose_key
        return purpose_key(master_key, "stego")
    return None


def _seed(key: bytes) -> int:
    """Seed PRNG numpy dari 8 byte pertama kunci steganografi."""
    return int.from_bytes(key[:8], "big")


def _payload_positions(first: int, count: int, total: int, seed: int):
    """
    Hasilkan blok posisi bit teracak (numpy Generator, seed dari kunci).

    Diproses per blok _BLOCK_BITS agar memori tetap terbatas berapa pun
    ukuran gambar; jumlah posisi yang dihasilkan tepat *count*.
    """
    rng = np.random.default_rng(seed)
    taken = 0
    start = first
    while taken < count:
        end = min(start + _BLOCK_BITS, total)
        if end <= start:
            raise ValueError("Jumlah posisi bit melebihi kapasitas gambar.")
        block = np.arange(start, end, dtype=np.int64)
        rng.shuffle(block)
        take = min(block.size, count - taken)
        yield block[:take]
        taken += take
        start = end


# ── Helper gambar ────────────────────────────────────────────────────────────

def _load_carrier(path: str):
    """Buka gambar RGB dan tolak bila dimensi melebihi batas."""
    img = Image.open(path).convert("RGB")
    width, height = img.size
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        return None, MSG.STEGO_IMAGE_TOO_LARGE.format(max=MAX_DIMENSION)
    return img, None


def _capacity_of(width: int, height: int) -> int:
    """Kapasitas muatan (byte) untuk dimensi gambar tertentu."""
    return (width * height * 3 - HEADER_BITS) // 8


def image_capacity(image_path: str) -> dict:
    """
    Kapasitas sisip gambar pembawa.

    Returns
    -------
    dict {"width", "height", "capacity"} atau {"error": ...}.
    """
    try:
        with Image.open(image_path) as img:
            width, height = img.size
    except Exception:
        return {"error": MSG.STEGO_INVALID_CARRIER}
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        return {"error": MSG.STEGO_IMAGE_TOO_LARGE.format(max=MAX_DIMENSION)}
    return {"width": width, "height": height, "capacity": _capacity_of(width, height)}


# ── Enkripsi muatan ──────────────────────────────────────────────────────────

def _encrypt_text(message: str, master_key: bytes | None,
                  passphrase: str | None) -> bytes:
    """Super Encryption untuk teks; enkripsi aktif secara default."""
    from modules.cryptography.super_encryption import super_encrypt
    if passphrase is not None:
        token = super_encrypt(message, passphrase=passphrase)
    else:
        token = super_encrypt(message, master_key=master_key)
    return token.encode("utf-8")


def _encrypt_file(filename: str, data: bytes, key: bytes) -> bytes:
    """AES-256-GCM untuk berkas; nama berkas ikut terenkripsi di depan isi."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    plaintext = filename.encode("utf-8") + _FILE_SEP + data
    # AAD memakai bagian header sebelum CRC agar muatan terikat pada
    # jenis dan panjangnya; CRC sendiri dihitung setelah enkripsi.
    aad = MAGIC + bytes([VERSION, TYPE_FILE]) + len(plaintext).to_bytes(4, "big")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def _decrypt_file(key: bytes, payload: bytes) -> tuple[str, bytes]:
    """Balikan AES-256-GCM; mengembalikan (nama berkas, isi)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(payload) < 28:
        raise ValueError("Muatan berkas terlalu pendek.")
    nonce, ciphertext = payload[:12], payload[12:]
    # AAD memakai panjang plaintext; panjang itu pasti len(ciphertext) − tag.
    plaintext_len = len(ciphertext) - 16
    aad = MAGIC + bytes([VERSION, TYPE_FILE]) + plaintext_len.to_bytes(4, "big")
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    name, _, data = plaintext.partition(_FILE_SEP)
    if not name:
        raise ValueError("Nama berkas tidak ditemukan.")
    return name.decode("utf-8"), data


# ── Menulis dan membaca bit ──────────────────────────────────────────────────

def _embed_bits(flat: np.ndarray, payload: bytes, payload_type: int,
                seed: int) -> None:
    """Tulis 112 bit header dan bit muatan ke dalam LSB piksel."""
    header = HEADER_STRUCT.pack(
        MAGIC, VERSION, payload_type, len(payload),
        zlib.crc32(payload) & 0xFFFFFFFF,
    )
    flat[:HEADER_BITS] = (
        (flat[:HEADER_BITS] & np.uint8(0xFE))
        | np.unpackbits(np.frombuffer(header, dtype=np.uint8))
    )
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    done = 0
    for pos in _payload_positions(HEADER_BITS, bits.size, flat.size, seed):
        size = pos.size
        flat[pos] = (flat[pos] & np.uint8(0xFE)) | bits[done:done + size]
        done += size


def _read_payload(flat: np.ndarray, seed: int) -> dict:
    """Baca header lalu muatan; magic/CRC menolak gambar tanpa pesan."""
    if flat.size < HEADER_BITS:
        return {"success": False, "error": MSG.STEGO_NO_MESSAGE}
    header = np.packbits(flat[:HEADER_BITS] & np.uint8(1)).tobytes()
    magic, version, payload_type, length, crc = HEADER_STRUCT.unpack(header)
    if magic != MAGIC:
        return {"success": False, "error": MSG.STEGO_NO_MESSAGE}
    if version != VERSION:
        return {"success": False, "error": MSG.STEGO_VERSION_UNSUPPORTED}
    if payload_type not in (TYPE_TEXT, TYPE_FILE):
        return {"success": False, "error": MSG.STEGO_NO_MESSAGE}
    capacity = (flat.size - HEADER_BITS) // 8
    if length > capacity:
        return {"success": False, "error": MSG.STEGO_NO_MESSAGE}
    bits = np.empty(length * 8, dtype=np.uint8)
    done = 0
    for pos in _payload_positions(HEADER_BITS, bits.size, flat.size, seed):
        size = pos.size
        bits[done:done + size] = flat[pos] & np.uint8(1)
        done += size
    payload = np.packbits(bits).tobytes()
    if zlib.crc32(payload) & 0xFFFFFFFF != crc:
        return {"success": False, "error": MSG.STEGO_TAMPERED}
    return {"success": True, "type": payload_type, "payload": payload}


# ── API publik: menyisipkan ──────────────────────────────────────────────────

def _prepare_carrier(input_image_path: str):
    """Buka pembawa, cek dimensi, siapkan array piksel dan kapasitas."""
    img, error = _load_carrier(input_image_path)
    if error:
        return None, None, error
    pixels = np.array(img, dtype=np.uint8)
    flat = pixels.reshape(-1)
    capacity = (flat.size - HEADER_BITS) // 8
    return (pixels, flat), capacity, None


def _save_png(pixels: np.ndarray, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    Image.fromarray(pixels, "RGB").save(output_path, format="PNG")


def embed_message(
    input_image_path: str,
    message: str,
    output_path: str,
    master_key: bytes | None = None,
    passphrase: str | None = None,
    encrypt: bool = True,
) -> dict:
    """
    Sisipkan *message* ke gambar pembawa; hasil selalu PNG.

    Parameters
    ----------
    input_image_path : str   Gambar pembawa (PNG/JPG/BMP, maks 4000×4000).
    message          : str   Teks yang akan disisipkan.
    output_path      : str   Tujuan PNG lossless.
    master_key       : bytes DEK untuk kunci steganografi dan Super Encryption.
    passphrase       : str   Alternatif kunci kustom (PBKDF2).
    encrypt          : bool  Enkripsi Super Encryption (default aktif).

    Returns
    -------
    dict {"success", "capacity", "used", "encrypted"} atau {"error"}.
    """
    key = _stego_key(master_key, passphrase)
    if key is None:
        return {"success": False, "error": MSG.STEGO_KEY_REQUIRED}

    prepared, capacity, error = _prepare_carrier(input_image_path)
    if error:
        return {"success": False, "error": error}
    pixels, flat = prepared

    if encrypt:
        payload = _encrypt_text(message, master_key, passphrase)
    else:
        payload = message.encode("utf-8")

    if len(payload) > capacity:
        return {
            "success": False,
            "error": MSG.STEGO_TOO_LARGE.format(
                used=len(payload), capacity=capacity
            ),
        }

    _embed_bits(flat, payload, TYPE_TEXT, _seed(key))
    _save_png(pixels, output_path)
    return {
        "success": True,
        "capacity": capacity,
        "used": len(payload),
        "encrypted": encrypt,
    }


def embed_file(
    input_image_path: str,
    file_path: str,
    output_path: str,
    master_key: bytes | None = None,
    passphrase: str | None = None,
    filename: str | None = None,
) -> dict:
    """
    Sisipkan isi berkas ke gambar pembawa; muatan selalu AES-256-GCM.

    Parameters
    ----------
    filename : str  Nama berkas asli yang ikut terenkripsi di dalam muatan;
                    default nama file sumber di disk.

    Returns
    -------
    dict {"success", "capacity", "used", "encrypted": True} atau {"error"}.
    """
    key = _stego_key(master_key, passphrase)
    if key is None:
        return {"success": False, "error": MSG.STEGO_KEY_REQUIRED}

    prepared, capacity, error = _prepare_carrier(input_image_path)
    if error:
        return {"success": False, "error": error}
    pixels, flat = prepared

    try:
        with open(file_path, "rb") as handle:
            data = handle.read()
    except OSError:
        return {"success": False, "error": MSG.STEGO_NO_PAYLOAD_FILE}
    if not data:
        return {"success": False, "error": MSG.STEGO_NO_PAYLOAD_FILE}

    payload = _encrypt_file(filename or os.path.basename(file_path), data, key)
    if len(payload) > capacity:
        return {
            "success": False,
            "error": MSG.STEGO_TOO_LARGE.format(
                used=len(payload), capacity=capacity
            ),
        }

    _embed_bits(flat, payload, TYPE_FILE, _seed(key))
    _save_png(pixels, output_path)
    return {
        "success": True,
        "capacity": capacity,
        "used": len(payload),
        "encrypted": True,
    }


# ── API publik: mengekstrak ──────────────────────────────────────────────────

def extract_payload(
    stego_image_path: str,
    master_key: bytes | None = None,
    passphrase: str | None = None,
) -> dict:
    """
    Ekstrak muatan apa pun dari gambar stego.

    Returns
    -------
    dict sukses: {"success", "type": "text"|"file", "text"} atau
    {"success", "type": "file", "filename", "data"}.
    dict gagal:   {"success": False, "error"}.
    """
    img, error = _load_carrier(stego_image_path)
    if error:
        return {"success": False, "error": error}
    flat = np.array(img, dtype=np.uint8).reshape(-1)

    # Magic dicek tanpa kunci agar gambar biasa terdeteksi jelas.
    if flat.size < HEADER_BITS or np.packbits(
        flat[:HEADER_BITS] & np.uint8(1)
    ).tobytes()[:4] != MAGIC:
        return {"success": False, "error": MSG.STEGO_NO_MESSAGE}

    key = _stego_key(master_key, passphrase)
    if key is None:
        return {"success": False, "error": MSG.STEGO_KEY_REQUIRED}

    read = _read_payload(flat, _seed(key))
    if not read["success"]:
        return read

    if read["type"] == TYPE_TEXT:
        raw = read["payload"]
        try:
            token = raw.decode("utf-8")
        except UnicodeDecodeError:
            return {"success": False, "error": MSG.STEGO_DECODE_FAILED}
        if token.startswith(_SUPER_PREFIX):
            from modules.cryptography.super_encryption import super_decrypt
            try:
                if passphrase is not None:
                    text = super_decrypt(token, passphrase=passphrase)
                else:
                    text = super_decrypt(token, master_key=master_key)
            except Exception:
                return {"success": False, "error": MSG.STEGO_DECRYPT_FAILED}
            return {"success": True, "type": "text", "text": text, "encrypted": True}
        return {"success": True, "type": "text", "text": token, "encrypted": False}

    try:
        filename, data = _decrypt_file(key, read["payload"])
    except Exception:
        return {"success": False, "error": MSG.STEGO_DECRYPT_FAILED}
    return {
        "success": True,
        "type": "file",
        "filename": filename,
        "data": data,
        "encrypted": True,
    }


def extract_message(
    stego_image_path: str,
    master_key: bytes | None = None,
    passphrase: str | None = None,
) -> dict:
    """
    Ekstrak muatan teks dari gambar stego.

    Returns
    -------
    dict {"success", "message"} atau {"success": False, "error"}.
    """
    result = extract_payload(stego_image_path, master_key, passphrase)
    if not result["success"]:
        return result
    if result["type"] != "text":
        return {"success": False, "error": MSG.STEGO_NOT_TEXT}
    return {"success": True, "message": result["text"],
            "encrypted": result["encrypted"]}


def extract_file(
    stego_image_path: str,
    output_path: str,
    master_key: bytes | None = None,
    passphrase: str | None = None,
) -> dict:
    """
    Ekstrak muatan berkas ke *output_path* (hanya untuk pengujian lokal;
    rute web menyajikan berkas langsung dari memori tanpa menulis plaintext).

    Returns
    -------
    dict {"success", "filename", "path"} atau {"success": False, "error"}.
    """
    result = extract_payload(stego_image_path, master_key, passphrase)
    if not result["success"]:
        return result
    if result["type"] != "file":
        return {"success": False, "error": MSG.STEGO_NOT_FILE}
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as handle:
        handle.write(result["data"])
    return {"success": True, "filename": result["filename"],
            "path": output_path, "size": len(result["data"])}
