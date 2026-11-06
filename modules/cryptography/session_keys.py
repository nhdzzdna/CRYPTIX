"""
modules/cryptography/session_keys.py
─────────────────────────────────────
Penyimpanan kunci DEK sesi di sisi server.

Alur kunci:
  • Cookie sesi hanya memuat session id acak (secrets.token_urlsafe),
    user_id, dan username — tidak ada materi kunci di cookie.
  • dict di memori, dikunci thread, memetakan session id ke
    {DEK, created_at, last_seen}. Kunci hilang saat server restart,
    logout, atau timeout (batas diam dan batas mutlak dari config).
  • Saat entri dibuang, bytearray DEK ditimpa sebagai upaya terbaik.
    Python tidak menjamin penghapusan memori: nilai salinan hasil
    konversi dapat bertahan di heap, sehingga penimpaan ini bukan
    jaminan keamanan melainkan mitigasi terbaik yang tersedia.
"""

from __future__ import annotations

import secrets
import threading
import time

import config

_lock = threading.Lock()
_store: dict[str, dict] = {}


def create_session_id() -> str:
    """Hasilkan session id acak untuk disimpan di cookie sesi."""
    return secrets.token_urlsafe(32)


def put(session_id: str, dek: bytes) -> None:
    """Simpan DEK sebuah sesi; entri lama dibuang dan bytearray-nya ditimpa."""
    if not session_id:
        raise ValueError("session_id wajib terisi")
    now = time.monotonic()
    with _lock:
        lama = _store.pop(session_id, None)
        if lama is not None:
            _buang(lama)
        _store[session_id] = {
            "dek": bytearray(dek),
            "created_at": now,
            "last_seen": now,
        }


def get(session_id: str) -> bytes | None:
    """Ambil DEK bila sesi masih hidup; perbarui tanda waktu diam."""
    if not session_id:
        return None
    now = time.monotonic()
    with _lock:
        entri = _store.get(session_id)
        if entri is None:
            return None
        if _kedaluwarsa(entri, now):
            _buang(entri)
            del _store[session_id]
            return None
        entri["last_seen"] = now
        return bytes(entri["dek"])


def drop(session_id: str) -> None:
    """Buang DEK sesi (logout) dan timpa bytearray-nya."""
    if not session_id:
        return
    with _lock:
        entri = _store.pop(session_id, None)
        if entri is not None:
            _buang(entri)


def clear() -> None:
    """Kosongkan seluruh penyimpanan (dipakai pengujian dan pembersihan proses)."""
    with _lock:
        for entri in _store.values():
            _buang(entri)
        _store.clear()


def _kedaluwarsa(entri: dict, now: float) -> bool:
    """True bila batas diam atau batas mutlak sudah terlampaui."""
    diam = config.SESSION_IDLE_MINUTES * 60
    mutlak = config.SESSION_ABSOLUTE_MINUTES * 60
    return (now - entri["last_seen"] > diam) or (now - entri["created_at"] > mutlak)


def _buang(entri: dict) -> None:
    """Timpa bytearray DEK dengan nol — upaya terbaik, lihat docstring modul."""
    dek = entri["dek"]
    dek[:] = b"\x00" * len(dek)
