"""
tests/test_super_encryption.py
───────────────────────────────
Round-trip tests for the 4-layer Super Encryption pipeline.
"""

import pytest

from modules.cryptography.super_encryption import (
    super_encrypt, super_decrypt, super_encrypt_steps,
)


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


class TestSuperEncryptionFormat:
    def test_output_is_versioned_with_mac(self):
        ct = super_encrypt("Halo", passphrase=PASSPHRASE)
        parts = ct.split(".")
        assert len(parts) == 4
        assert parts[0] == "CXSE2"
        assert len(parts[1]) == 32          # salt 16 byte hex
        assert len(parts[3]) == 64          # HMAC-SHA256 hex

    def test_roundtrip_unicode(self):
        msg = "Halo dunia — 你好, élan! 😀"
        ct = super_encrypt(msg, passphrase=PASSPHRASE)
        assert super_decrypt(ct, passphrase=PASSPHRASE) == msg

    def test_roundtrip_empty_text(self):
        ct = super_encrypt("", passphrase=PASSPHRASE)
        assert super_decrypt(ct, passphrase=PASSPHRASE) == ""

    def test_roundtrip_long_text(self):
        msg = "Pesan panjang untuk menguji seluruh pipeline. " * 40
        ct = super_encrypt(msg, passphrase=PASSPHRASE)
        assert super_decrypt(ct, passphrase=PASSPHRASE) == msg

    def test_roundtrip_consecutive_double_letters(self):
        msg = "aaabbbcccaaaxxxdddeeefff"
        ct = super_encrypt(msg, passphrase=PASSPHRASE)
        assert super_decrypt(ct, passphrase=PASSPHRASE) == msg

    def test_salt_differs_per_message(self):
        ct1 = super_encrypt("sama", passphrase=PASSPHRASE)
        ct2 = super_encrypt("sama", passphrase=PASSPHRASE)
        assert ct1.split(".")[1] != ct2.split(".")[1]

    def test_mac_tamper_single_char_rejected(self):
        ct = super_encrypt("rahasia", passphrase=PASSPHRASE)
        parts = ct.split(".")
        mac = parts[3]
        mac = ("A" if mac[0] != "A" else "B") + mac[1:]
        tampered = ".".join([parts[0], parts[1], parts[2], mac])
        with pytest.raises(ValueError):
            super_decrypt(tampered, passphrase=PASSPHRASE)

    def test_token_tamper_rejected(self):
        ct = super_encrypt("rahasia", passphrase=PASSPHRASE)
        parts = ct.split(".")
        token = parts[2]
        token = ("A" if token[0] != "A" else "B") + token[1:]
        tampered = ".".join([parts[0], parts[1], token, parts[3]])
        with pytest.raises(ValueError):
            super_decrypt(tampered, passphrase=PASSPHRASE)

    def test_wrong_passphrase_rejected(self):
        ct = super_encrypt("rahasia", passphrase="benar")
        with pytest.raises(ValueError):
            super_decrypt(ct, passphrase="salah")

    def test_wrong_master_key_rejected(self):
        import hashlib
        mk1 = hashlib.sha256(b"kunci-satu").digest()
        mk2 = hashlib.sha256(b"kunci-dua").digest()
        ct = super_encrypt("rahasia", master_key=mk1)
        with pytest.raises(ValueError):
            super_decrypt(ct, master_key=mk2)

    def test_malformed_format_rejected(self):
        with pytest.raises(ValueError):
            super_decrypt("bukan-format", passphrase=PASSPHRASE)


class TestSuperEncryptionSteps:
    def test_steps_expose_every_layer(self):
        steps = super_encrypt_steps("pesan uji", passphrase=PASSPHRASE)
        assert list(steps) == ["vigenere", "playfair", "chacha20", "blowfish", "final"]
        assert steps["final"].startswith("CXSE2.")

    def test_playfair_layer_differs_from_input(self):
        """Playfair benar-benar mengubah data (bukan input digit yang lewat)."""
        msg = "SECRETMESSAGE"
        steps = super_encrypt_steps(msg, passphrase=PASSPHRASE)
        assert steps["playfair"] != msg
        assert steps["playfair"] != steps["vigenere"]
        # Keluaran Playfair hanya huruf A–Z.
        assert steps["playfair"].isalpha() and steps["playfair"].isupper()

    def test_steps_final_matches_super_encrypt(self):
        """super_encrypt mengembalikan nilai "final" yang sama secara konsep."""
        steps = super_encrypt_steps("bandingkan", passphrase=PASSPHRASE)
        ct = super_encrypt("bandingkan", passphrase=PASSPHRASE)
        assert steps["final"].split(".")[0] == ct.split(".")[0]
        assert super_decrypt(steps["final"], passphrase=PASSPHRASE) == "bandingkan"
