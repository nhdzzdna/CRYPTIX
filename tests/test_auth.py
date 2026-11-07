"""
tests/test_auth.py
──────────────────
Unit tests for password hashing (fungsi turunan kunci lama dihapus
bersama alur login dua tahap — lihat tests/test_two_stage_login.py).
"""

from modules.authentication.password_hash import hash_password, verify_password


class TestPasswordHash:
    def test_hash_returns_two_hex_strings(self):
        h, s = hash_password("secret123")
        assert isinstance(h, str)
        assert isinstance(s, str)
        # salt must be 32 bytes → 64 hex chars
        assert len(s) == 64

    def test_correct_password_verifies(self):
        h, s = hash_password("correct_password")
        assert verify_password("correct_password", h, s) is True

    def test_wrong_password_fails(self):
        h, s = hash_password("correct_password")
        assert verify_password("wrong_password", h, s) is False

    def test_different_salts_different_hashes(self):
        h1, s1 = hash_password("same_password")
        h2, s2 = hash_password("same_password")
        assert s1 != s2
        assert h1 != h2

    def test_empty_password(self):
        h, s = hash_password("")
        assert verify_password("", h, s) is True
        assert verify_password("x", h, s) is False


def test_fungsi_turunan_kunci_lama_dihapus():
    """Alur login dua tahap memakai unlock_dek; turunan lama dihapus."""
    from modules.cryptography import key_management
    for nama in ("derive_master_key", "derive_purpose_key",
                 "get_file_encryption_key", "get_db_encryption_key"):
        assert not hasattr(key_management, nama), nama


def test_autentikasi_lama_dihapus():
    """authenticate_user digantikan verifikasi_tahap_satu (tahap 1)."""
    from modules.authentication import auth as auth_mod
    assert not hasattr(auth_mod, "authenticate_user")
    assert callable(auth_mod.verifikasi_tahap_satu)
