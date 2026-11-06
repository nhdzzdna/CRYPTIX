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

import hashlib
import hmac
import os

import config

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _hashes

from modules.cryptography.classical_cipher_1 import vigenere_encrypt, vigenere_decrypt
from modules.cryptography.classical_cipher_2 import playfair_encrypt, playfair_decrypt
from modules.cryptography.modern_cipher_1 import chacha20_encrypt, chacha20_decrypt
from modules.cryptography.modern_cipher_2 import blowfish_encrypt, blowfish_decrypt
from modules.cryptography.key_management import purpose_key

_VERSION = "CXSE2"
_NIBBLE_ALPHABET = "ABCDEFGHIKLMNOPQ"   # 16 huruf, tanpa J dan X
_NIBBLE_INDEX = {c: i for i, c in enumerate(_NIBBLE_ALPHABET)}
_COMPONENTS = ("vigenere", "playfair", "chacha20", "blowfish", "mac")


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

def super_encrypt_steps(plaintext: str, master_key: bytes | None = None,
                        passphrase: str | None = None) -> dict:
    """
    Enkripsi penuh dan kembalikan keluaran tiap layer untuk tampilan edukasi.

    Returns
    -------
    dict berisi "vigenere", "playfair", "chacha20", "blowfish", dan "final".
    """
    salt = os.urandom(16)
    keys = _message_keys(_base_keys(master_key, passphrase, salt), salt)

    step1 = vigenere_encrypt(plaintext, keys["vigenere"])
    step2 = playfair_encrypt(_bytes_to_nibbles(step1.encode("utf-8")), keys["playfair"])
    step3 = chacha20_encrypt(step2, keys["chacha20"])
    step4 = blowfish_encrypt(step3, keys["blowfish"])
    salt_hex = salt.hex()
    mac = _mac_tag(keys["mac"], salt_hex, step4)

    return {
        "vigenere": step1,
        "playfair": step2,
        "chacha20": step3,
        "blowfish": step4,
        "final": f"{_VERSION}.{salt_hex}.{step4}.{mac}",
    }


def super_encrypt(plaintext: str, master_key: bytes | None = None,
                  passphrase: str | None = None) -> str:
    """
    Terapkan pipeline 4 layer: Vigenere → Playfair → ChaCha20 → Blowfish-CBC.

    Returns
    -------
    str  "CXSE2.<salt_hex>.<token>.<mac_hex>".
    """
    return super_encrypt_steps(
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
