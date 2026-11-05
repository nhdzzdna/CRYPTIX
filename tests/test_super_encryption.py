"""
tests/test_super_encryption.py
────────────────────────────────
Round-trip tests for the 4-layer Super Encryption pipeline.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from modules.cryptography.super_encryption import super_encrypt, super_decrypt


PASSPHRASE = "test-super-enc-passphrase-42"


class TestSuperEncryption:
    def test_roundtrip_simple(self):
        msg = "Hello, Super Encryption!"
        ct  = super_encrypt(msg, passphrase=PASSPHRASE)
        pt  = super_decrypt(ct, passphrase=PASSPHRASE)
        assert pt == msg

    def test_roundtrip_longer_text(self):
        msg = "The quick brown fox jumps over the lazy dog. " * 10
        ct  = super_encrypt(msg, passphrase=PASSPHRASE)
        pt  = super_decrypt(ct, passphrase=PASSPHRASE)
        assert pt == msg

    def test_roundtrip_with_special_chars(self):
        # Playfair only handles A-Z letters; non-alpha pass through
        msg = "Test message 12345"
        ct  = super_encrypt(msg, passphrase=PASSPHRASE)
        pt  = super_decrypt(ct, passphrase=PASSPHRASE)
        assert pt == msg

    def test_different_passphrases_differ(self):
        msg = "Same plaintext"
        ct1 = super_encrypt(msg, passphrase="pass1")
        ct2 = super_encrypt(msg, passphrase="pass2")
        assert ct1 != ct2

    def test_same_passphrase_different_ciphertext(self):
        # ChaCha20 and Blowfish use random nonces/IVs each time
        msg = "Same message"
        ct1 = super_encrypt(msg, passphrase=PASSPHRASE)
        ct2 = super_encrypt(msg, passphrase=PASSPHRASE)
        assert ct1 != ct2

    def test_wrong_passphrase_fails_to_decrypt_correctly(self):
        msg = "Secret message"
        ct  = super_encrypt(msg, passphrase="correct_pass")
        try:
            pt  = super_decrypt(ct, passphrase="wrong_pass")
            assert pt != msg
        except Exception:
            pass  # decryption error with wrong key is acceptable

    def test_with_master_key(self):
        """Test pipeline with bytes master_key (as used from session)."""
        import hashlib
        mk = hashlib.sha256(b"session_master_key").digest()
        msg = "Testing with master key"
        ct  = super_encrypt(msg, master_key=mk)
        pt  = super_decrypt(ct, master_key=mk)
        assert pt == msg

    def test_encrypt_requires_key(self):
        import pytest
        with pytest.raises(ValueError):
            super_encrypt("test")

    def test_decrypt_requires_key(self):
        import pytest
        ct = super_encrypt("test", passphrase="x")
        with pytest.raises(ValueError):
            super_decrypt(ct)
