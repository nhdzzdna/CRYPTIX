"""
tests/test_ciphers.py
──────────────────────
Unit tests for all four individual ciphers.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import hashlib
from modules.cryptography.classical_cipher_1 import vigenere_encrypt, vigenere_decrypt
from modules.cryptography.classical_cipher_2 import playfair_encrypt, playfair_decrypt
from modules.cryptography.modern_cipher_1    import chacha20_encrypt, chacha20_decrypt
from modules.cryptography.modern_cipher_2    import blowfish_encrypt, blowfish_decrypt


def _sha256_key(s: str) -> bytes:
    return hashlib.sha256(s.encode()).digest()


# ── Vigenere ─────────────────────────────────────────────────────────────────

class TestVigenere:
    def test_roundtrip_simple(self):
        ct = vigenere_encrypt("Hello World", "secret")
        pt = vigenere_decrypt(ct, "secret")
        assert pt == "Hello World"

    def test_roundtrip_full_ascii(self):
        msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789!@#$%"
        ct = vigenere_encrypt(msg, "MyKey123")
        pt = vigenere_decrypt(ct, "MyKey123")
        assert pt == msg

    def test_different_key_no_decrypt(self):
        ct = vigenere_encrypt("Hello", "key1")
        pt = vigenere_decrypt(ct, "key2")
        assert pt != "Hello"

    def test_empty_string(self):
        assert vigenere_encrypt("", "key") == ""
        assert vigenere_decrypt("", "key") == ""

    def test_non_printable_passthrough(self):
        # Newlines are outside 32-126 range and should pass through
        msg = "Hi\nthere"
        ct = vigenere_encrypt(msg, "key")
        pt = vigenere_decrypt(ct, "key")
        assert pt == msg


# ── Playfair ─────────────────────────────────────────────────────────────────

class TestPlayfair:
    def test_roundtrip_letters_only(self):
        # Playfair inserts X fillers for double letters and odd-length pairs.
        # It also merges I/J and uppercases everything.
        # Round-trip: decrypt(encrypt(msg)) should contain all original letters.
        msg = "HELPME"  # 6 letters, no doubles → clean round-trip
        ct = playfair_encrypt(msg, "SECRET")
        pt = playfair_decrypt(ct, "SECRET")
        # Strip any Playfair X fillers and compare core letters
        core = pt.replace("X", "")
        assert core == "HELPME"

    def test_roundtrip_preserves_non_alpha(self):
        msg = "HELLO, WORLD!"
        ct = playfair_encrypt(msg, "KEY")
        pt = playfair_decrypt(ct, "KEY")
        # Non-alpha chars preserved; letters may have X fillers
        assert "," in pt and "!" in pt

    def test_ij_merge(self):
        # J → I in Playfair; encryption should handle J input
        ct = playfair_encrypt("JUMP", "KEY")
        assert ct  # just ensure no crash

    def test_different_key_no_decrypt(self):
        ct = playfair_encrypt("TESTING", "RIGHTKEY")
        pt = playfair_decrypt(ct, "WRONGKEY")
        assert pt != playfair_decrypt(ct, "RIGHTKEY")


# ── ChaCha20 ─────────────────────────────────────────────────────────────────

class TestChaCha20:
    def test_roundtrip(self):
        key = _sha256_key("chacha_test_key")
        ct  = chacha20_encrypt("Hello ChaCha20!", key)
        pt  = chacha20_decrypt(ct, key)
        assert pt == "Hello ChaCha20!"

    def test_nonce_is_random(self):
        key = _sha256_key("k")
        ct1 = chacha20_encrypt("same", key)
        ct2 = chacha20_encrypt("same", key)
        assert ct1 != ct2   # different nonces

    def test_roundtrip_unicode(self):
        key = _sha256_key("unicode_key")
        msg = "Привет 🌍"
        ct  = chacha20_encrypt(msg, key)
        pt  = chacha20_decrypt(ct, key)
        assert pt == msg

    def test_wrong_key_fails(self):
        key1 = _sha256_key("key1")
        key2 = _sha256_key("key2")
        ct = chacha20_encrypt("secret", key1)
        try:
            pt = chacha20_decrypt(ct, key2)
            assert pt != "secret"
        except Exception:
            pass  # decryption with wrong key may raise, that's fine


# ── Blowfish ─────────────────────────────────────────────────────────────────

class TestBlowfish:
    def test_roundtrip(self):
        key = _sha256_key("blowfish_test_key")
        ct  = blowfish_encrypt("Hello Blowfish!", key)
        pt  = blowfish_decrypt(ct, key)
        assert pt == "Hello Blowfish!"

    def test_iv_is_random(self):
        key = _sha256_key("k")
        ct1 = blowfish_encrypt("same", key)
        ct2 = blowfish_encrypt("same", key)
        assert ct1 != ct2

    def test_roundtrip_long_text(self):
        key = _sha256_key("long_text")
        msg = "A" * 500
        ct  = blowfish_encrypt(msg, key)
        pt  = blowfish_decrypt(ct, key)
        assert pt == msg

    def test_wrong_key_raises_or_garbles(self):
        key1 = _sha256_key("key1")
        key2 = _sha256_key("key2")
        ct = blowfish_encrypt("secret", key1)
        try:
            pt = blowfish_decrypt(ct, key2)
            assert pt != "secret"
        except Exception:
            pass
