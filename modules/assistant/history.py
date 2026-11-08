"""
modules/assistant/history.py
────────────────────────────
Riwayat percakapan Security Assistant di sisi server.

Riwayat TIDAK disimpan di cookie sesi: cookie hanya memuat id sesi acak,
sehingga isi percakapan tidak pernah ikut terkirim ke browser. Penyimpanan
ini hanya di memori proses dan hilang saat server restart, logout, atau
riwayat dibersihkan.

Batas:
  • ``_MAX_PER_SESI`` entri terakhir per sesi (user + agent).
  • ``_MAX_SESI`` sesi aktif; sesi terlama dibuang lebih dulu agar memori
    tidak tumbuh tanpa batas.
"""

from __future__ import annotations

import threading

_MAX_PER_SESI = 40
_MAX_SESI = 200

_lock = threading.Lock()
_riwayat: dict[str, list[dict]] = {}


def get(session_id: str) -> list[dict]:
    """Salinan riwayat sebuah sesi (list kosong bila belum ada)."""
    if not session_id:
        return []
    with _lock:
        return [dict(entri) for entri in _riwayat.get(session_id, [])]


def append(session_id: str, entri: list[dict]) -> None:
    """Tambahkan entri ke riwayat sesi, potong ke batas terakhir."""
    if not session_id or not entri:
        return
    with _lock:
        riwayat = _riwayat.pop(session_id, [])
        riwayat.extend(dict(item) for item in entri)
        if len(riwayat) > _MAX_PER_SESI:
            riwayat = riwayat[-_MAX_PER_SESI:]
        _riwayat[session_id] = riwayat
        while len(_riwayat) > _MAX_SESI:
            _riwayat.pop(next(iter(_riwayat)))


def clear(session_id: str) -> None:
    """Hapus riwayat sebuah sesi (tombol Bersihkan)."""
    if not session_id:
        return
    with _lock:
        _riwayat.pop(session_id, None)


def forget(session_id: str) -> None:
    """Alias ``clear`` untuk dipanggil saat sesi berakhir."""
    clear(session_id)


def clear_all() -> None:
    """Kosongkan seluruh riwayat (dipakai pengujian)."""
    with _lock:
        _riwayat.clear()
