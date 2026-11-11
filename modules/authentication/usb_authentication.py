"""
modules/authentication/usb_authentication.py
─────────────────────────────────────────────
Lapisan autentikasi dongle USB.

Alur:
  1. Pendaftaran: register_usb_token(mountpoint) menulis berkas
     ``.cryptix_token`` berisi JSON {version, token_id, secret} ke dongle.
     Server hanya menyimpan token_id, verifier =
     HMAC-SHA256(secret, "cryptix-usb-verifier"), dan serial volume.
  2. Verifikasi: verify_usb_token() membaca berkas token dari drive
     removable yang cocok, menghitung ulang verifier, membandingkannya
     dengan hmac.compare_digest, lalu mengembalikan rahasia dongle untuk
     membentuk KEK (lihat key_management.create_key_bundle).
  3. Gerbang: gerbang_startup() menolak aplikasi berjalan bila pengguna
     terdaftar tanpa dongle terpasang; dongle_pengguna_terpasang() mengecek
     sesi berjalan dengan hasil di-cache maksimal 2 detik.
  4. Mode pengembangan (CRYPTIX_DEV_MODE): DEV_DONGLE_DIR dipakai sebagai
     dongle simulasi agar pengujian dapat berjalan tanpa USB fisik.
"""

import hashlib
import hmac
import json
import os
import platform
import secrets
import sqlite3
import time

import config
from modules.strings import MSG

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

import ctypes

TOKEN_VERSION = 1
VERIFIER_INFO = b"cryptix-usb-verifier"
_CACHE_DETIK = 2.0

_cache_dongle: dict[int, tuple[float, bool]] = {}


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_removable_drives() -> list[str]:
    """Titik lepas hanya untuk partisi bertanda "removable" (tanpa heuristik fstype)."""
    if not _PSUTIL_AVAILABLE:
        return []
    return [
        part.mountpoint
        for part in psutil.disk_partitions(all=False)
        if "removable" in part.opts.lower()
    ]


def _folder_dev_dongle() -> str:
    """Folder simulasi dongle saat CRYPTIX_DEV_MODE (DEV_DONGLE_DIR bila diisi)."""
    if config.DEV_DONGLE_DIR:
        return config.DEV_DONGLE_DIR
    basis = os.path.dirname(os.path.abspath(config.__file__))
    return os.path.join(basis, "instance", "dev_dongle")


def _kandidat_drive() -> list[str]:
    """Drive removable yang terpasang, ditambah folder simulasi mode pengembangan."""
    drives = _get_removable_drives()
    if config.CRYPTIX_DEV_MODE:
        dev = os.path.normpath(_folder_dev_dongle())
        if dev not in {os.path.normpath(d) for d in drives}:
            drives.append(dev)
    return drives


def _akar_volume(path: str) -> str:
    """Akar volume Windows dari path (folder mana pun menghasilkan root-nya)."""
    p = os.path.abspath(path)
    drive, _ = os.path.splitdrive(p)
    return drive + os.sep if drive else p


def _get_volume_serial(mountpoint: str) -> str:
    """
    Serial volume lewat ctypes GetVolumeInformationW (8 digit heksadesimal).
    Mengembalikan string kosong di luar Windows atau bila gagal dibaca.
    """
    if platform.system() != "Windows" or not mountpoint:
        return ""
    try:
        get_info = ctypes.windll.kernel32.GetVolumeInformationW
        get_info.argtypes = (
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p, ctypes.c_uint32,
        )
        get_info.restype = ctypes.c_int
        serial = ctypes.c_uint32(0)
        ok = get_info(_akar_volume(mountpoint), None, 0, ctypes.byref(serial),
                      None, None, None, 0)
        return f"{serial.value:08X}" if ok else ""
    except (OSError, AttributeError):
        return ""


def _verifier(rahasia: bytes) -> str:
    """verifier = HMAC-SHA256(rahasia dongle, "cryptix-usb-verifier")."""
    return hmac.new(rahasia, VERIFIER_INFO, hashlib.sha256).hexdigest()


def _token_file_path(mountpoint: str) -> str:
    return os.path.join(mountpoint, config.USB_TOKEN_FILENAME)


def path_token(mountpoint: str) -> str:
    """Lokasi berkas token pada sebuah mountpoint."""
    return _token_file_path(mountpoint)


def _tulis_atomik(path: str, isi: bytes) -> bool:
    """Tulis ``isi`` ke ``path`` lewat berkas sementara lalu os.replace."""
    sementara = f"{path}.tmp-{secrets.token_hex(8)}"
    try:
        with open(sementara, "wb") as handle:
            handle.write(isi)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(sementara, path)
        return True
    except OSError:
        try:
            os.remove(sementara)
        except OSError:
            pass
        return False


# ── API publik ────────────────────────────────────────────────────────────────

def daftar_drive() -> list[dict]:
    """Daftar dongle terdeteksi untuk dipilih pada form pendaftaran."""
    return [
        {"mountpoint": m, "volume_serial": _get_volume_serial(m)}
        for m in _kandidat_drive()
    ]


def buat_token(mountpoint: str) -> dict | None:
    """
    Siapkan token baru di memori tanpa menulis berkas.

    Returns
    -------
    dict berisi ``token_id``, ``verifier``, ``volume_serial``, dan ``secret``
    (bytes 32) bila mountpoint kandidat dongle; None bila bukan kandidat.
    """
    if not mountpoint:
        return None
    kandidat = {os.path.normpath(d) for d in _kandidat_drive()}
    if os.path.normpath(mountpoint) not in kandidat:
        return None

    rahasia = os.urandom(32)
    token_id = secrets.token_hex(16)
    return {
        "token_id": token_id,
        "verifier": _verifier(rahasia),
        "volume_serial": _get_volume_serial(mountpoint),
        "secret": rahasia,
    }


def tulis_token(mountpoint: str, token: dict) -> bool:
    """Tulis token ke dongle secara atomik (berkas sementara lalu replace)."""
    if not mountpoint or not isinstance(token, dict):
        return False
    try:
        os.makedirs(mountpoint, exist_ok=True)
        payload = {
            "version": TOKEN_VERSION,
            "token_id": token["token_id"],
            "secret": token["secret"].hex(),
        }
        isi = json.dumps(payload).encode("utf-8")
    except (KeyError, AttributeError, OSError, TypeError):
        return False
    return _tulis_atomik(_token_file_path(mountpoint), isi)


def pulihkan_token(mountpoint: str, isi: bytes | None) -> bool:
    """
    Pulihkan berkas token lama setelah pembaruan basis data gagal.

    ``isi`` None berarti berkas token sebelumnya tidak ada sehingga berkas
    baru dihapus. Pemulihan dilakukan secara atomik.
    """
    path = _token_file_path(mountpoint)
    if isi is None:
        try:
            os.remove(path)
            return True
        except OSError:
            return False
    return _tulis_atomik(path, isi)


def register_usb_token(mountpoint: str) -> dict | None:
    """
    Tulis berkas token JSON ke dongle terpilih.

    Berkas memuat versi, token_id, dan rahasia acak 32 byte. Rahasia tidak
    pernah disimpan di basis data; yang disimpan hanya token_id dan verifier.

    Returns
    -------
    dict berisi ``token_id``, ``verifier``, ``volume_serial``, dan ``secret``
    (bytes 32) bila berhasil; None bila mountpoint bukan kandidat dongle.
    """
    token = buat_token(mountpoint)
    if token is None:
        return None
    if not tulis_token(mountpoint, token):
        return None
    return token


def verify_usb_token(stored_verifier: str, stored_serial: str,
                     stored_token_id: str) -> tuple[bool, bytes | None]:
    """
    Verifikasi dongle yang terpasang terhadap data tersimpan.

    Returns
    -------
    (True, rahasia) bila berkas token cocok dan verifier sama persis;
    (False, None) bila tidak ada drive yang cocok atau verifikasi gagal.
    """
    if not stored_token_id or not stored_verifier:
        return False, None

    for mountpoint in _kandidat_drive():
        serial = _get_volume_serial(mountpoint)
        if stored_serial and serial != stored_serial:
            continue
        path = _token_file_path(mountpoint)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or data.get("version") != TOKEN_VERSION:
            continue
        if data.get("token_id") != stored_token_id:
            continue
        try:
            rahasia = bytes.fromhex(str(data.get("secret", "")))
        except ValueError:
            continue
        if len(rahasia) != 32:
            continue
        if hmac.compare_digest(_verifier(rahasia), stored_verifier):
            return True, rahasia
    return False, None


def dongle_pengguna_terpasang(user_id: int) -> bool:
    """
    Cek dongle milik ``user_id``; hasil di-cache maksimal 2 detik.

    Akun tanpa data dongle dianggap terpasang (kondisi transisi); keketatan
    di gerbang startup, yang menolak aplikasi berjalan tanpa dongle terdaftar.
    """
    sekarang = time.monotonic()
    entri = _cache_dongle.get(user_id)
    if entri and sekarang - entri[0] < _CACHE_DETIK:
        return entri[1]

    hasil = True
    try:
        from database.db import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT usb_token_id, usb_verifier, usb_volume_serial "
                "FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        if row is not None and row["usb_token_id"]:
            hasil, _rahasia = verify_usb_token(
                row["usb_verifier"], row["usb_volume_serial"], row["usb_token_id"]
            )
    except sqlite3.Error:
        # Skema lama/DB tes tanpa tabel users: ditangani gerbang startup.
        hasil = True

    _cache_dongle[user_id] = (sekarang, hasil)
    return hasil


def lupakan_cache(user_id: int | None = None) -> None:
    """Buang cache gerbang (dipanggil setelah pendaftaran atau perubahan dongle)."""
    if user_id is None:
        _cache_dongle.clear()
    else:
        _cache_dongle.pop(user_id, None)


def gerbang_startup() -> str | None:
    """
    Gerbang saat ``python app.py`` dijalankan.

    Returns
    -------
    None bila aplikasi boleh berjalan (belum ada pengguna, atau ada dongle
    terdaftar yang terpasang); pesan penolakan berbahasa jelas bila tidak.
    """
    from database.db import get_db
    try:
        with get_db() as db:
            rows = db.execute(
                "SELECT id, usb_token_id, usb_verifier, usb_volume_serial FROM users"
            ).fetchall()
    except sqlite3.Error:
        return MSG.USB_STARTUP_BLOCKED

    if not rows:
        # Mode setup awal: belum ada pengguna, dongle belum wajib.
        return None

    ada_dongle = False
    for row in rows:
        if not row["usb_token_id"]:
            continue
        ada_dongle = True
        ok, _rahasia = verify_usb_token(
            row["usb_verifier"], row["usb_volume_serial"], row["usb_token_id"]
        )
        if ok:
            return None
    return MSG.USB_STARTUP_UNREGISTERED if not ada_dongle else MSG.USB_STARTUP_BLOCKED
