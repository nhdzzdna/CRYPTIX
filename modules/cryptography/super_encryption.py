"""
modules/cryptography/super_encryption.py
────────────────────────────────────────
Super Encryption: pipeline 4 layer.

Urutan enkripsi:
  1. Vigenere       — keluaran diubah ke byte UTF-8 lalu nibble heksadesimal
                      yang dipetakan ke 16 huruf "ABCDEFGHIKLMNOPQ"
                      (tanpa J dan X) sehingga Playfair benar-benar
                      mengubah huruf.
  2. Playfair       — beroperasi pada huruf hasil pemetaan; filler X dibuang
                      saat dekripsi lalu dipetakan kembali ke byte.
  3. ChaCha20
  4. Blowfish-CBC

Dekripsi: 4 → 3 → 2 → 1, dengan verifikasi MAC terlebih dahulu.

Keamanan:
  • Format keluaran bertanda versi: "CXSE2.<salt_hex>.<token>.<mac_hex>".
  • Salt acak 16 byte per pesan masuk ke HKDF sehingga kunci Vigenere,
    Playfair, dan MAC berbeda tiap pesan; kunci Vigenere/Playfair dibentuk
    dari byte HKDF, bukan heksadesimal polos.
  • HMAC-SHA256 atas seluruh bagian (encrypt-then-MAC); diverifikasi dengan
    compare_digest sebelum dekripsi.
  • Kunci turunan dari passphrase memakai PBKDF2-HMAC-SHA256
    (config.SUPER_ENC_PBKDF2_ITERATIONS) dengan salt dari keluaran.
"""

import base64
import hashlib
import hmac
import os

import config

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _hashes
from Crypto.Util.Padding import pad as _pad

from modules.cryptography.classical_cipher_1 import vigenere_encrypt, vigenere_decrypt
from modules.cryptography.classical_cipher_2 import (
    playfair_encrypt, playfair_decrypt, playfair_encrypt_trace,
)
from modules.cryptography.modern_cipher_1 import chacha20_encrypt, chacha20_decrypt
from modules.cryptography.modern_cipher_2 import blowfish_encrypt, blowfish_decrypt
from modules.cryptography.key_management import purpose_key

_VERSION = "CXSE2"
_NIBBLE_ALPHABET = "ABCDEFGHIKLMNOPQ"   # 16 huruf, tanpa J dan X
_NIBBLE_INDEX = {c: i for i, c in enumerate(_NIBBLE_ALPHABET)}
_COMPONENTS = ("vigenere", "playfair", "chacha20", "blowfish", "mac")

# Batas jejak: 200 entri karakter/byte, 100 pasangan Playfair (200 huruf),
# dan 64 byte pertama untuk layer modern.
_TRACE_LIMIT = 200
_PLAYFAIR_TRACE_LIMIT = _TRACE_LIMIT // 2
_MODERN_TRACE_LIMIT = 64
_KUNCI_DISEMBUNYIKAN = "***"
_BLOWFISH_BLOCK_SIZE = 8


def _hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 generik."""
    return HKDF(
        algorithm=_hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def _base_keys(master_key: bytes | None, passphrase: str | None, salt: bytes) -> dict:
    """Material dasar tiap komponen (belum diperkaya salt per pesan)."""
    if master_key is not None:
        return {name: purpose_key(master_key, name) for name in _COMPONENTS}
    if passphrase is not None:
        root = hashlib.pbkdf2_hmac(
            config.PBKDF2_HASH_ALGO,
            passphrase.encode("utf-8"),
            salt,
            config.SUPER_ENC_PBKDF2_ITERATIONS,
            dklen=32,
        )
        return {
            name: _hkdf(root, salt, f"cryptix-super-{name}-v1".encode("utf-8"))
            for name in _COMPONENTS
        }
    raise ValueError("master_key atau passphrase wajib disediakan.")


def _vigenere_key(raw: bytes) -> str:
    """Bentuk kunci Vigenere dari byte HKDF (printable ASCII 32–126)."""
    return "".join(chr(b % 95 + 32) for b in raw[:16])


def _playfair_key(raw: bytes) -> str:
    """Bentuk kunci Playfair dari byte HKDF (huruf A–Z)."""
    return "".join(chr(b % 26 + 65) for b in raw[:10])


def _message_keys(base: dict, salt: bytes) -> dict:
    """Kunci per pesan: Vigenere, Playfair, dan MAC melalui HKDF(salt)."""
    return {
        "vigenere": _vigenere_key(_hkdf(base["vigenere"], salt, b"cryptix-super-vigenere-v1")),
        "playfair": _playfair_key(_hkdf(base["playfair"], salt, b"cryptix-super-playfair-v1")),
        "chacha20": base["chacha20"],
        "blowfish": base["blowfish"],
        "mac": _hkdf(base["mac"], salt, b"cryptix-super-mac-v1"),
    }


def _bytes_to_nibbles(data: bytes) -> str:
    """Byte → dua huruf nibble dari _NIBBLE_ALPHABET."""
    out = []
    for b in data:
        out.append(_NIBBLE_ALPHABET[b >> 4])
        out.append(_NIBBLE_ALPHABET[b & 0x0F])
    return "".join(out)


def _nibbles_to_bytes(letters: str) -> bytes:
    """Huruf nibble (filler X sudah dibuang) → byte."""
    if len(letters) % 2 != 0:
        raise ValueError("Data nibble tidak valid.")
    try:
        return bytes(
            (_NIBBLE_INDEX[letters[i]] << 4) | _NIBBLE_INDEX[letters[i + 1]]
            for i in range(0, len(letters), 2)
        )
    except KeyError as exc:
        raise ValueError("Data nibble tidak valid.") from exc


def _mac_tag(mac_key: bytes, salt_hex: str, token: str) -> str:
    """HMAC-SHA256 atas versi, salt, dan token."""
    message = f"{_VERSION}.{salt_hex}.{token}".encode("utf-8")
    return hmac.new(mac_key, message, hashlib.sha256).hexdigest()


# ── API publik ───────────────────────────────────────────────────────────────

def _vigenere_trace(plaintext: str, ciphertext: str) -> tuple[list[dict], int]:
    """Jejak per karakter layer Vigenere; kunci layer selalu disamarkan."""
    total = len(plaintext)
    jejak: list[dict] = []
    for asal, hasil in zip(plaintext, ciphertext):
        if len(jejak) >= _TRACE_LIMIT:
            break
        digeser = 32 <= ord(asal) <= 126
        jejak.append({
            "asal": asal,
            "kunci": _KUNCI_DISEMBUNYIKAN if digeser else "",
            "hasil": hasil,
        })
    return jejak, total


def _byte_trace(before: bytes, after: bytes,
                limit: int = _MODERN_TRACE_LIMIT) -> tuple[list[dict], int]:
    """Jejak per byte dalam heksadesimal untuk layer modern."""
    total = max(len(before), len(after))
    jejak: list[dict] = []
    for offset in range(min(total, limit)):
        sebelum = before[offset] if offset < len(before) else None
        sesudah = after[offset] if offset < len(after) else None
        jejak.append({
            "sebelum": f"{sebelum:02x}" if sebelum is not None else "",
            "sesudah": f"{sesudah:02x}" if sesudah is not None else "",
        })
    return jejak, total


def _catatan(total: int, ditampilkan: int, satuan: str) -> str:
    """Catatan pemotongan jejak; kosong bila seluruh jejak ditampilkan."""
    if ditampilkan >= total:
        return ""
    if satuan:
        return f"ditampilkan {ditampilkan} {satuan} pertama dari {total} {satuan}"
    return f"ditampilkan {ditampilkan} pertama dari {total} karakter"


def super_encrypt_stages(plaintext: str, master_key: bytes | None = None,
                         passphrase: str | None = None) -> dict:
    """
    Enkripsi penuh dan kembalikan keluaran serta jejak tiap layer.

    Tidak ada kunci, kunci turunan, atau passphrase pada hasil. Kunci layer
    klasik disamarkan; nonce dan IV boleh ditampilkan karena bukan kunci.

    Returns
    -------
    dict  ``{"final": str, "stages": list[dict]}``.
    """
    salt = os.urandom(16)
    keys = _message_keys(_base_keys(master_key, passphrase, salt), salt)

    step1 = vigenere_encrypt(plaintext, keys["vigenere"])
    nibble_input = _bytes_to_nibbles(step1.encode("utf-8"))
    step2 = playfair_encrypt(nibble_input, keys["playfair"])
    step3 = chacha20_encrypt(step2, keys["chacha20"])
    step4 = blowfish_encrypt(step3, keys["blowfish"])
    salt_hex = salt.hex()
    mac = _mac_tag(keys["mac"], salt_hex, step4)
    final = f"{_VERSION}.{salt_hex}.{step4}.{mac}"

    vigenere_jejak, vigenere_total = _vigenere_trace(plaintext, step1)
    playfair_jejak, playfair_total = playfair_encrypt_trace(
        nibble_input, keys["playfair"], limit=_PLAYFAIR_TRACE_LIMIT
    )
    chacha_nonce, chacha_token = step3.split(":", 1)
    chacha_jejak, chacha_total = _byte_trace(
        step2.encode("utf-8"), base64.b64decode(chacha_token)
    )
    blowfish_iv, blowfish_token = step4.split(":", 1)
    blowfish_before = _pad(step3.encode("utf-8"), _BLOWFISH_BLOCK_SIZE)
    blowfish_jejak, blowfish_total = _byte_trace(
        blowfish_before, base64.b64decode(blowfish_token)
    )

    stages = [
        {
            "nama": "Layer 1 — Vigenere",
            "kode": "vigenere",
            "jenis": "vigenere",
            "input": plaintext,
            "output": step1,
            "keterangan": (
                "Setiap karakter printable ASCII digeser menurut kunci layer. "
                "Karakter lain dibiarkan. Kunci layer disembunyikan."
            ),
            "jejak": vigenere_jejak,
            "jejak_total": vigenere_total,
            "jejak_ditampilkan": len(vigenere_jejak),
            "jejak_dipotong": len(vigenere_jejak) < vigenere_total,
            "catatan": _catatan(vigenere_total, len(vigenere_jejak), ""),
        },
        {
            "nama": "Layer 2 — Playfair",
            "kode": "playfair",
            "jenis": "playfair",
            "input": nibble_input,
            "output": step2,
            "keterangan": (
                "Pasangan huruf diubah menurut aturan baris sama, kolom sama, "
                "atau persegi. Kunci layer disembunyikan."
            ),
            "jejak": playfair_jejak,
            "jejak_total": playfair_total,
            "jejak_ditampilkan": len(playfair_jejak),
            "jejak_dipotong": len(playfair_jejak) < playfair_total,
            "catatan": _catatan(
                playfair_total, len(playfair_jejak), "pasangan"
            ),
        },
        {
            "nama": "Layer 3 — ChaCha20",
            "kode": "chacha20",
            "jenis": "modern",
            "input": step2,
            "output": step3,
            "keterangan": (
                "Cipher stream; jejak ditampilkan per byte. Pada cipher modern, "
                "jejak per huruf tidak bermakna. Nonce boleh ditampilkan; kunci "
                "disembunyikan."
            ),
            "parameter": [
                {"label": "Nonce", "nilai": chacha_nonce},
                {"label": "Panjang nonce", "nilai": "16 byte"},
                {"label": "Mode", "nilai": "stream"},
                {"label": "Padding", "nilai": "tidak ada"},
            ],
            "jejak": chacha_jejak,
            "jejak_total": chacha_total,
            "jejak_ditampilkan": len(chacha_jejak),
            "jejak_dipotong": len(chacha_jejak) < chacha_total,
            "catatan": _catatan(chacha_total, len(chacha_jejak), "byte"),
        },
        {
            "nama": "Layer 4 — Blowfish-CBC",
            "kode": "blowfish",
            "jenis": "modern",
            "input": step3,
            "output": step4,
            "keterangan": (
                "Cipher blok mode CBC dengan padding PKCS#7; jejak ditampilkan "
                "per byte. Pada cipher modern, jejak per huruf tidak bermakna. "
                "IV boleh ditampilkan; kunci disembunyikan."
            ),
            "parameter": [
                {"label": "IV", "nilai": blowfish_iv},
                {"label": "Panjang IV", "nilai": "8 byte"},
                {"label": "Mode", "nilai": "CBC"},
                {"label": "Padding", "nilai": "PKCS#7"},
                {"label": "Ukuran blok", "nilai": "8 byte"},
            ],
            "jejak": blowfish_jejak,
            "jejak_total": blowfish_total,
            "jejak_ditampilkan": len(blowfish_jejak),
            "jejak_dipotong": len(blowfish_jejak) < blowfish_total,
            "catatan": _catatan(blowfish_total, len(blowfish_jejak), "byte"),
        },
        {
            "nama": "Keluaran Akhir (CXSE2 + HMAC-SHA256)",
            "kode": "final",
            "jenis": "final",
            "input": step4,
            "output": final,
            "keterangan": (
                "Format akhir memuat versi, salt, token, dan MAC. Salt bukan kunci."
            ),
            "jejak": [],
            "jejak_total": 0,
            "jejak_ditampilkan": 0,
            "jejak_dipotong": False,
            "catatan": "",
        },
    ]
    return {"final": final, "stages": stages}


def super_encrypt_steps(plaintext: str, master_key: bytes | None = None,
                        passphrase: str | None = None) -> dict:
    """
    Enkripsi penuh dan kembalikan keluaran tiap layer (bentuk lama).

    Fungsi ini dipertahankan agar pemanggil lama tetap memperoleh dict
    ``vigenere``/``playfair``/``chacha20``/``blowfish``/``final``. Untuk jejak
    terstruktur, gunakan :func:`super_encrypt_stages`.
    """
    detail = super_encrypt_stages(
        plaintext, master_key=master_key, passphrase=passphrase
    )
    by_code = {stage["kode"]: stage for stage in detail["stages"]}
    return {
        "vigenere": by_code["vigenere"]["output"],
        "playfair": by_code["playfair"]["output"],
        "chacha20": by_code["chacha20"]["output"],
        "blowfish": by_code["blowfish"]["output"],
        "final": detail["final"],
    }


def super_encrypt(plaintext: str, master_key: bytes | None = None,
                  passphrase: str | None = None) -> str:
    """
    Terapkan pipeline 4 layer: Vigenere → Playfair → ChaCha20 → Blowfish-CBC.

    Returns
    -------
    str  "CXSE2.<salt_hex>.<token>.<mac_hex>".
    """
    return super_encrypt_stages(
        plaintext, master_key=master_key, passphrase=passphrase
    )["final"]


def super_decrypt(ciphertext: str, master_key: bytes | None = None,
                  passphrase: str | None = None) -> str:
    """
    Balikan pipeline setelah verifikasi MAC (encrypt-then-MAC).

    Raises
    ------
    ValueError  Jika format salah, MAC gagal, atau kunci salah.
    """
    parts = str(ciphertext).split(".")
    if len(parts) != 4 or parts[0] != _VERSION:
        raise ValueError("Format Super Encryption tidak dikenal.")
    _, salt_hex, token, mac_hex = parts
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise ValueError("Format Super Encryption tidak dikenal.") from exc
    if len(salt) != 16:
        raise ValueError("Format Super Encryption tidak dikenal.")

    keys = _message_keys(_base_keys(master_key, passphrase, salt), salt)
    expected = _mac_tag(keys["mac"], salt_hex, token)
    if not hmac.compare_digest(expected, mac_hex):
        raise ValueError("MAC tidak cocok: kunci salah atau data berubah.")

    step = blowfish_decrypt(token, keys["blowfish"])
    step = chacha20_decrypt(step, keys["chacha20"])
    nibbles = playfair_decrypt(step, keys["playfair"]).replace("X", "")
    vigenere_ct = _nibbles_to_bytes(nibbles).decode("utf-8")
    return vigenere_decrypt(vigenere_ct, keys["vigenere"])
