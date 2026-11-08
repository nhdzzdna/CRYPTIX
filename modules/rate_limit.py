"""
modules/rate_limit.py
─────────────────────
Pembatas laju berbasis Flask-Limiter untuk endpoint sensitif (butir 2.7).

Penyimpanan penghitung berada di memori proses (``memory://``) sehingga
tidak memerlukan layanan tambahan pada aplikasi lokal. Batas per alamat
klien:
  • login                 — 15 permintaan POST per menit
  • verifikasi wajah      — 20 permintaan per menit
  • autentikasi ulang     — 20 permintaan per menit
  • pemulihan akun        — 10 permintaan per menit

Rute reveal belum tersedia pada revisi ini; batasnya ditambahkan bersama
rute tersebut pada sesi yang mengerjakannya.
"""

from __future__ import annotations

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

LOGIN_LIMIT = "15 per minute"
FACE_VERIFY_LIMIT = "20 per minute"
REAUTH_LIMIT = "20 per minute"
RECOVERY_LIMIT = "10 per minute"

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=[],
    headers_enabled=True,
)


def init_app(app) -> None:
    """Pasang limiter ke aplikasi dan bersihkan penghitung lama."""
    limiter.init_app(app)
    limiter.reset()
