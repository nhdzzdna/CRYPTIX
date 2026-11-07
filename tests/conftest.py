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


# ── Sesi I: cegah tempfile.tempdir menunjuk folder uji yang sudah dihapus ─────
import tempfile as _tempfile


@pytest.fixture(autouse=True)
def _pulihkan_tempdir_sesi_i():
    yield
    _tempfile.tempdir = None
