"""
modules/cryptography/pending_keys.py
─────────────────────────────────────
Penyimpanan DEK sementara untuk login dua tahap (butir 2.4).

Alur kunci:
  • Tahap 1 membuka DEK lalu menahannya di sini, maksimal 3 menit,
    menunggu tahap biometrik. DEK tidak pernah masuk cookie, flash,
    URL, log, maupun basis data.
  • Cookie sesi hanya memuat token acak sekali pakai (secrets.token_urlsafe)
    yang menunjuk entri ini, bukan DEK maupun password.
  • Enri dibuang setelah tahap 2 lulus atau kedaluwarsa; bytearray DEK
    ditimpa dengan nol sebagai upaya terbaik (lihat session_keys.modul).
"""

from __future__ import annotations

import secrets
import threading
import time

TTL_DETIK = 180.0  # 3 menit, sesuai butir 2.4a

_lock = threading.Lock()
_store: dict[str, dict] = {}


def letakkan(user_id: int, dek: bytes) -> str:
    """Tahan DEK tahap 1; kembalikan token acak sekali pakai untuk cookie sesi."""
    if len(dek) != 32:
        raise ValueError("DEK harus 32 byte.")
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _lock:
        _buang_kedaluwarsa(now)
        _store[token] = {
            "user_id": user_id,
            "dek": bytearray(dek),
            "created_at": now,
        }
    return token


def periksa(token: str) -> tuple[int, bytes] | None:
    """Ambil (user_id, DEK) tanpa membuang entri; None bila hilang/kedaluwarsa."""
    if not token:
        return None
    now = time.monotonic()
    with _lock:
        entri = _store.get(token)
        if entri is None:
            return None
        if now - entri["created_at"] > TTL_DETIK:
            _timpa(_store.pop(token))
            return None
        return entri["user_id"], bytes(entri["dek"])


def ambil(token: str) -> tuple[int, bytes] | None:
    """Ambil sekaligus buang entri (sekali pakai); timpa bytearray DEK-nya."""
    if not token:
        return None
    now = time.monotonic()
    with _lock:
        entri = _store.pop(token, None)
        if entri is None:
            return None
        if now - entri["created_at"] > TTL_DETIK:
            _timpa(entri)
            return None
        dek = bytes(entri["dek"])
        _timpa(entri)
        return entri["user_id"], dek


def buang(token: str) -> None:
    """Buang satu entri (restart tahap atau kedaluwarsa)."""
    if not token:
        return
    with _lock:
        entri = _store.pop(token, None)
        if entri is not None:
            _timpa(entri)


def kosongkan() -> None:
    """Kosongkan seluruh penyimpanan (dipakai pengujian)."""
    with _lock:
        for entri in list(_store.values()):
            _timpa(entri)
        _store.clear()


def _buang_kedaluwarsa(now: float) -> None:
    """Buang entri yang sudah lewat TTL sebelum menambah yang baru."""
    for token in [
        t for t, e in _store.items() if now - e["created_at"] > TTL_DETIK
    ]:
        _timpa(_store.pop(token))


def _timpa(entri: dict) -> None:
    """Timpa bytearray DEK dengan nol — upaya terbaik, lihat docstring modul."""
    dek = entri["dek"]
    dek[:] = b"\x00" * len(dek)
