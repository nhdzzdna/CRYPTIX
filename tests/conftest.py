"""
tests/conftest.py
─────────────────
Bersihkan penyimpanan kunci sesi sebelum dan sesudah tiap test agar
tidak ada DEK tes yang bocor ke test berikutnya.
"""

import pytest

from modules.cryptography import session_keys


@pytest.fixture(autouse=True)
def _kunci_sesi_bersih():
    session_keys.clear()
    yield
    session_keys.clear()
