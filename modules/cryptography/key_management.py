"""
modules/cryptography/key_management.py
───────────────────────────────────────
Hierarki kunci CRYPTIX.

Alur kunci:
  • DEK: 32 byte acak (os.urandom) dibuat saat registrasi oleh
    create_key_bundle(); tidak pernah disimpan polos dan tidak pernah
    dikirim ke cookie, flash, URL, maupun log.
  • KEK: HKDF-SHA256 dari gabungan PBKDF2-HMAC-SHA256(password, kek_salt,
    600000 iterasi, 32 byte) dan rahasia dongle 32 byte, info
    "cryptix-kek-v1". KEK membungkus DEK dengan AES-256-GCM; AAD memuat
    id pengguna dan label versi agar blob tidak dapat dipindahkan.
  • Kunci pemulihan: 32 byte acak yang hanya ditampilkan sekali dalam
    format base32 berkelompok; membungkus DEK lewat HKDF(recovery_key).
  • Kunci per tujuan: HKDF(DEK, label) — lihat PURPOSE_LABELS.

kek_salt selalu terpisah dari salt autentikasi (kolom ``salt``), sehingga
hash password tidak pernah dapat dipakai sebagai kunci enkripsi.
"""

import base64
import hashlib
import os

import config

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _hashes

# ── Label versi dan tujuan ───────────────────────────────────────────────────
KEK_INFO = b"cryptix-kek-v1"
RECOVERY_INFO = b"cryptix-recovery-v1"
PURPOSE_SALT = b"cryptix-purpose-keys-v1"
_BLOB_VERSION = "v1"

PURPOSE_LABELS: dict[str, bytes] = {
    "file": b"cryptix-purpose-file-v1",
    "database": b"cryptix-purpose-database-v1",
    "stego": b"cryptix-purpose-stego-v1",
    "vigenere": b"cryptix-purpose-super-vigenere-v1",
    "playfair": b"cryptix-purpose-super-playfair-v1",
    "chacha20": b"cryptix-purpose-super-chacha20-v1",
    "blowfish": b"cryptix-purpose-super-blowfish-v1",
    "mac": b"cryptix-purpose-super-mac-v1",
    "face": b"cryptix-purpose-face-template-v1",
    "chain": b"cryptix-purpose-hash-chain-v1",
}


# ── Primitif internal ────────────────────────────────────────────────────────

def _hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 generik."""
    return HKDF(
        algorithm=_hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def _derive_kek(password: str, kek_salt: bytes, usb_secret: bytes) -> bytes:
    """KEK = HKDF(PBKDF2(password, kek_salt) ‖ rahasia dongle, info KEK_INFO)."""
    if len(usb_secret) != 32:
        raise ValueError("Rahasia dongle harus 32 byte.")
    pw_part = hashlib.pbkdf2_hmac(
        config.PBKDF2_HASH_ALGO,
        password.encode("utf-8"),
        kek_salt,
        config.KEK_PBKDF2_ITERATIONS,
        dklen=32,
    )
    return _hkdf(pw_part + usb_secret, kek_salt, KEK_INFO)


def _aad(prefix: bytes, user_id) -> bytes:
    """AAD = label versi + id pengguna agar blob terikat pada pemiliknya."""
    return f"{prefix.decode('utf-8')}:{'' if user_id is None else user_id}".encode("utf-8")


def _wrap(key: bytes, plaintext: bytes, aad: bytes) -> str:
    """AES-256-GCM; format "v1:<nonce_hex>:<ciphertext_tag_hex>"."""
    nonce = os.urandom(12)
    blob = AESGCM(key).encrypt(nonce, plaintext, aad)
    return f"{_BLOB_VERSION}:{nonce.hex()}:{blob.hex()}"


def _unwrap(key: bytes, blob: str, aad: bytes) -> bytes:
    """Balikan _wrap; kegagalan autentikasi apa pun menjadi ValueError."""
    try:
        version, nonce_hex, body_hex = blob.split(":")
        if version != _BLOB_VERSION:
            raise ValueError("Versi blob tidak dikenal.")
        return AESGCM(key).decrypt(
            bytes.fromhex(nonce_hex), bytes.fromhex(body_hex), aad
        )
    except Exception as exc:
        raise ValueError("DEK tidak dapat dibuka dengan kunci tersebut.") from exc


# ── API publik hierarki kunci ────────────────────────────────────────────────

def create_key_bundle(password: str, usb_secret: bytes, user_id: int) -> dict:
    """
    Buat DEK baru, bungkus dengan KEK dan kunci pemulihan.

    Returns
    -------
    dict berisi ``user_id``, ``kek_salt``, ``wrapped_dek``,
    ``recovery_wrapped_dek``, dan ``recovery_key`` (base32 berkelompok —
    tampilkan sekali kepada pengguna, jangan disimpan).
    """
    dek = os.urandom(32)
    kek_salt = os.urandom(config.SALT_LENGTH)
    kek = _derive_kek(password, kek_salt, usb_secret)
    wrapped = _wrap(kek, dek, _aad(KEK_INFO, user_id))

    recovery_key = os.urandom(32)
    recovery_kek = _hkdf(recovery_key, None, RECOVERY_INFO)
    recovery_wrapped = _wrap(recovery_kek, dek, _aad(RECOVERY_INFO, user_id))

    return {
        "user_id": user_id,
        "kek_salt": kek_salt.hex(),
        "wrapped_dek": wrapped,
        "recovery_wrapped_dek": recovery_wrapped,
        "recovery_key": format_recovery_key(recovery_key),
    }


def unlock_dek(password: str, usb_secret: bytes, bundle) -> bytes:
    """
    Buka DEK dari bundle memakai password dan rahasia dongle.

    Raises
    ------
    ValueError  Jika password, dongle, atau blob tidak cocok.
    """
    b = dict(bundle)
    user_id = b.get("user_id", b.get("id"))
    kek_salt = bytes.fromhex(b["kek_salt"])
    kek = _derive_kek(password, kek_salt, usb_secret)
    return _unwrap(kek, b["wrapped_dek"], _aad(KEK_INFO, user_id))


def rewrap_dek(dek: bytes, new_password: str, usb_secret: bytes,
               user_id=None) -> dict:
    """
    Bungkus ulang DEK dengan password baru tanpa mengubah DEK.

    Data lama tetap terbuka. ``user_id`` wajib diisi agar AAD cocok dengan
    bundle tersimpan; kunci pemulihan tetap berlaku karena tidak ikut
    dibungkus ulang.
    """
    if len(dek) != 32:
        raise ValueError("DEK harus 32 byte.")
    kek_salt = os.urandom(config.SALT_LENGTH)
    kek = _derive_kek(new_password, kek_salt, usb_secret)
    wrapped = _wrap(kek, dek, _aad(KEK_INFO, user_id))
    return {
        "user_id": user_id,
        "kek_salt": kek_salt.hex(),
        "wrapped_dek": wrapped,
    }


def recover_dek(recovery_key, bundle) -> bytes:
    """
    Buka DEK dengan kunci pemulihan (base32 berkelompok atau bytes 32).

    Raises
    ------
    ValueError  Jika kunci atau blob tidak cocok.
    """
    if isinstance(recovery_key, str):
        rk = _parse_recovery_key(recovery_key)
    else:
        rk = bytes(recovery_key)
    if len(rk) != 32:
        raise ValueError("Kunci pemulihan harus 32 byte.")
    b = dict(bundle)
    user_id = b.get("user_id", b.get("id"))
    recovery_kek = _hkdf(rk, None, RECOVERY_INFO)
    return _unwrap(recovery_kek, b["recovery_wrapped_dek"], _aad(RECOVERY_INFO, user_id))


def purpose_key(dek: bytes, label) -> bytes:
    """
    Kunci per tujuan = HKDF(DEK, label).

    Parameters
    ----------
    dek   : bytes  DEK 32 byte.
    label : str    Kunci dari PURPOSE_LABELS, atau bytes label mentah.
    """
    if len(dek) != 32:
        raise ValueError("DEK harus 32 byte.")
    if isinstance(label, str):
        info = PURPOSE_LABELS.get(label)
        if info is None:
            raise ValueError(f"Label tujuan tidak dikenal: {label}")
    else:
        info = bytes(label)
    return _hkdf(dek, PURPOSE_SALT, info)


def format_recovery_key(key: bytes) -> str:
    """Format base32 tanpa padding, dikelompokkan 8 karakter, dipisah '-'."""
    b32 = base64.b32encode(key).decode("ascii").rstrip("=")
    return "-".join(b32[i:i + 8] for i in range(0, len(b32), 8))


def _parse_recovery_key(text: str) -> bytes:
    """Normalisasi input kunci pemulihan (huruf, angka 2-7, '-' atau spasi)."""
    cleaned = "".join(
        c for c in text.upper() if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    )
    if not cleaned:
        raise ValueError("Format kunci pemulihan tidak valid.")
    cleaned += "=" * ((-len(cleaned)) % 8)
    try:
        return base64.b32decode(cleaned)
    except Exception as exc:
        raise ValueError("Format kunci pemulihan tidak valid.") from exc


# ── API lama (DEPRECATED — dihapus pada tugas T8 dan T11) ────────────────────

def derive_master_key(password: str, salt_hex: str) -> bytes:
    """DEPRECATED: gunakan create_key_bundle()/unlock_dek(). PBKDF2 dari salt autentikasi."""
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac(
        config.PBKDF2_HASH_ALGO,
        password.encode("utf-8"),
        salt,
        config.PBKDF2_ITERATIONS,
        dklen=32,
    )


def derive_purpose_key(master_key: bytes, label: bytes, length: int = 32) -> bytes:
    """DEPRECATED: gunakan purpose_key(dek, label). HKDF lama berbasis label."""
    hkdf = HKDF(
        algorithm=_hashes.SHA256(),
        length=length,
        salt=label,
        info=b"cryptix-key-derivation",
    )
    return hkdf.derive(master_key)


def get_file_encryption_key(master_key: bytes) -> bytes:
    """DEPRECATED: gunakan purpose_key(dek, "file"). Kunci enkripsi file lama."""
    return derive_purpose_key(master_key, config.HKDF_SALT_FILE_ENC)


def get_db_encryption_key(master_key: bytes) -> bytes:
    """DEPRECATED: gunakan purpose_key(dek, "database"). Kunci field basis data lama."""
    return derive_purpose_key(master_key, config.HKDF_SALT_DB_ENC)


def get_stego_key(master_key: bytes) -> bytes:
    """DEPRECATED: gunakan purpose_key(dek, "stego"). Kunci steganografi lama."""
    return derive_purpose_key(master_key, config.HKDF_SALT_STEGO)


def get_super_enc_subkey(master_key: bytes, cipher_name: str) -> bytes:
    """DEPRECATED: gunakan purpose_key(dek, <nama>). Sub-kunci Super Encryption lama."""
    label = config.SUPER_ENC_LABELS.get(cipher_name)
    if label is None:
        raise ValueError(f"Unknown Super Encryption cipher: {cipher_name}")
    return derive_purpose_key(master_key, label)


def master_key_to_hex(master_key: bytes) -> str:
    """DEPRECATED: jangan serialisasi kunci ke cookie/session/log. Hapus pada T8/T11."""
    return master_key.hex()


def master_key_from_hex(hex_str: str) -> bytes:
    """DEPRECATED: kunci tidak boleh disimpan sebagai hex di session. Hapus pada T8/T11."""
    return bytes.fromhex(hex_str)
