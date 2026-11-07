"""
modules/media/winamp_integration.py
─────────────────────────────────────
Integrasi Winamp untuk Media Vault.

Alur:
  1. Hanya bila Winamp benar-benar dipakai, plaintext ditulis ke berkas
     sementara bernama acak di storage/temporary_files/.
  2. Winamp dibuka melalui subprocess (Windows).
  3. Berkas sementara dijadwalkan dihapus setelah 60 detik; sebelum dihapus
     dilakukan penimpaan nol sebagai upaya terbaik.
  4. atexit membersihkan berkas yang masih aktif, dan saat aplikasi dimulai
     kembali sisa berkas ber-prefix CRYPTIX dibersihkan.

Penimpaan nol adalah upaya terbaik, bukan jaminan penghapusan permanen pada
SSD atau media penyimpanan modern yang memakai wear leveling.

Jika Winamp tidak ditemukan pada config.WINAMP_PATH, pemanggil harus memakai
pemutar HTML5.
"""

import atexit
import os
import secrets
import subprocess
import threading
import time

import config
from modules.strings import MSG

WINAMP_TEMP_TTL_SECONDS = 60
_TEMP_PREFIX = "cryptix_winamp_"
_ACTIVE_TEMP_FILES = set()


def _temp_dir() -> str:
    """Direktori sementara milik CRYPTIX (dibaca saat dipanggil)."""
    return os.path.realpath(config.TEMPORARY_FILES_DIR)


def _is_inside_temp_dir(path: str) -> bool:
    """True hanya bila *path* berada di dalam direktori temporary_files CRYPTIX."""
    try:
        target = os.path.realpath(path)
        return os.path.commonpath([_temp_dir(), target]) == _temp_dir()
    except (OSError, ValueError):
        return False


def _random_temp_name(filename: str) -> str:
    """Nama acak dengan ekstensi asli, tanpa memakai nama asli secara langsung."""
    ext = os.path.splitext(filename or "")[1].lower()
    if len(ext) > 10 or not ext[1:].isalnum():
        ext = ""
    return f"{_TEMP_PREFIX}{secrets.token_hex(16)}{ext}"


def _zero_overwrite(path: str) -> None:
    """Timpa isi berkas dengan nol sebelum dihapus (upaya terbaik)."""
    size = os.path.getsize(path)
    with open(path, "r+b") as handle:
        remaining = size
        block = b"\x00" * 65536
        while remaining > 0:
            written = min(len(block), remaining)
            handle.write(block[:written])
            remaining -= written
        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError:
            pass


def cleanup_temp_file(path: str) -> bool:
    """
    Hapus satu berkas sementara CRYPTIX setelah penimpaan nol.

    Returns
    -------
    bool  True bila berkas sudah tidak ada atau berhasil dihapus; False bila
          path berada di luar temporary_files atau penghapusan gagal (misalnya
          berkas masih dipakai Winamp).
    """
    if not _is_inside_temp_dir(path):
        return False
    if not os.path.exists(path):
        _ACTIVE_TEMP_FILES.discard(path)
        return True
    try:
        _zero_overwrite(path)
        os.remove(path)
    except OSError:
        # Berkas masih dipakai atau gagal dihapus; biarkan terdaftar agar
        # atexit dapat mencoba lagi.
        return False
    _ACTIVE_TEMP_FILES.discard(path)
    return True


def cleanup_stale_temp_files() -> int:
    """
    Bersihkan sisa berkas Winamp dari proses sebelumnya saat aplikasi mulai.

    Hanya berkas ber-prefix CRYPTIX yang disentuh agar berkas lain di
    temporary_files tidak ikut terhapus. Mengembalikan jumlah berkas terhapus.
    """
    temp_dir = config.TEMPORARY_FILES_DIR
    if not os.path.isdir(temp_dir):
        return 0
    removed = 0
    try:
        entries = list(os.scandir(temp_dir))
    except OSError:
        return 0
    for entry in entries:
        try:
            if entry.is_file() and entry.name.startswith(_TEMP_PREFIX):
                if cleanup_temp_file(entry.path):
                    removed += 1
        except OSError:
            continue
    return removed


def _cleanup_active_temp_files() -> None:
    """Bersihkan berkas sementara yang masih aktif (dipanggil atexit)."""
    for path in list(_ACTIVE_TEMP_FILES):
        cleanup_temp_file(path)


atexit.register(_cleanup_active_temp_files)


def _schedule_delete(path: str, delay_seconds: float = WINAMP_TEMP_TTL_SECONDS):
    """Jadwalkan penghapusan *path* setelah *delay_seconds* di thread latar."""
    def _worker():
        time.sleep(delay_seconds)
        cleanup_temp_file(path)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    return thread


def is_winamp_available() -> bool:
    """Return True if Winamp executable exists at config.WINAMP_PATH."""
    return bool(config.WINAMP_PATH) and os.path.isfile(config.WINAMP_PATH)


def play_with_winamp(decrypted_audio_path: str) -> dict:
    """
    Buka *decrypted_audio_path* di Winamp dan jadwalkan pembersihan.

    Returns
    -------
    dict dengan ``success`` bool, ``winamp_available`` bool, ``error`` str.
    """
    if not is_winamp_available():
        return {
            "success": False,
            "winamp_available": False,
            "error": MSG.WINAMP_NOT_FOUND,
        }

    try:
        subprocess.Popen([config.WINAMP_PATH, decrypted_audio_path])
        _schedule_delete(decrypted_audio_path, delay_seconds=WINAMP_TEMP_TTL_SECONDS)
        return {"success": True, "winamp_available": True}
    except Exception:
        return {"success": False, "winamp_available": True,
                "error": MSG.WINAMP_START_FAILED}


def save_temp_audio(decrypted_bytes: bytes, filename: str) -> str:
    """
    Tulis plaintext audio ke berkas sementara bernama acak dan kembalikan path.

    Berkas hanya boleh dibuat untuk pemutaran Winamp; pemanggil wajib memastikan
    Winamp benar-benar digunakan sebelum memanggil fungsi ini.
    """
    os.makedirs(config.TEMPORARY_FILES_DIR, exist_ok=True)
    dest = os.path.join(config.TEMPORARY_FILES_DIR, _random_temp_name(filename))
    with open(dest, "wb") as handle:
        handle.write(decrypted_bytes)
    _ACTIVE_TEMP_FILES.add(dest)
    return dest
