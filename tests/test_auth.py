"""
tests/test_auth.py
───────────────────
Unit tests for password hashing and key derivation.
"""

from modules.authentication.password_hash import hash_password, verify_password
from modules.cryptography.key_management  import (
    derive_master_key, derive_purpose_key,
    get_file_encryption_key, get_db_encryption_key,
)


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


class TestKeyDerivation:
    def setup_method(self):
        self.pw = "test_password_42"
        _, self.salt_hex = hash_password(self.pw)
        self.mk = derive_master_key(self.pw, self.salt_hex)

    def test_master_key_is_32_bytes(self):
        assert len(self.mk) == 32

    def test_master_key_is_bytes(self):
        assert isinstance(self.mk, bytes)

    def test_derived_file_key_is_32_bytes(self):
        fk = get_file_encryption_key(self.mk)
        assert len(fk) == 32

    def test_derived_db_key_is_32_bytes(self):
        dk = get_db_encryption_key(self.mk)
        assert len(dk) == 32

    def test_file_and_db_keys_are_different(self):
        fk = get_file_encryption_key(self.mk)
        dk = get_db_encryption_key(self.mk)
        assert fk != dk

    def test_derivation_is_deterministic(self):
        mk2 = derive_master_key(self.pw, self.salt_hex)
        assert mk2 == self.mk
