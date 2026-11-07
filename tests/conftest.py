"""
tests/conftest.py
─────────────────
Bersihkan penyimpanan kunci sesi sebelum dan sesudah tiap test agar
tidak ada DEK tes yang bocor ke test berikutnya.
"""

import pytest

from modules.authentication import usb_authentication as usb_mod
from modules.cryptography import session_keys


@pytest.fixture(autouse=True)
def _kunci_sesi_bersih():
    session_keys.clear()
    usb_mod.lupakan_cache()
    yield
    session_keys.clear()
    usb_mod.lupakan_cache()


# ── Sesi F: login dua tahap ───────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _pending_sesi_bersih():
    """Buang DEK tahap 1 yang tertahan antar test."""
    from modules.cryptography import pending_keys
    pending_keys.kosongkan()
    yield
    pending_keys.kosongkan()
