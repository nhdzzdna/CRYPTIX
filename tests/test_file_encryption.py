"""
tests/test_file_encryption.py
──────────────────────────────
Unit tests for AES-256-GCM file encryption.
Tests include:
  • Round-trip correctness.
  • Tampered file detection (InvalidTag).
  • Different files produce different nonces.
  • SHA-256 of plaintext is correct.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import hashlib
from cryptography.exceptions import InvalidTag

from modules.cryptography.file_encryption import encrypt_file, decrypt_file


def _make_key(seed: str = "test_file_enc_key") -> bytes:
    return hashlib.sha256(seed.encode()).digest()


class TestFileEncryption:
    def test_roundtrip_text_file(self):
        key  = _make_key()
        data = b"Hello, this is a test file payload."
        res  = encrypt_file(data, key)
        pt   = decrypt_file(res["ciphertext"], res["nonce_hex"], key)
        assert pt == data

    def test_roundtrip_binary_file(self):
        key  = _make_key("binary")
        data = os.urandom(4096)
        res  = encrypt_file(data, key)
        pt   = decrypt_file(res["ciphertext"], res["nonce_hex"], key)
        assert pt == data

    def test_nonce_is_12_bytes(self):
        key = _make_key()
        res = encrypt_file(b"data", key)
        assert len(bytes.fromhex(res["nonce_hex"])) == 12

    def test_sha256_correct(self):
        key  = _make_key()
        data = b"checksum test"
        res  = encrypt_file(data, key)
        expected = hashlib.sha256(data).hexdigest()
        assert res["sha256_hex"] == expected

    def test_different_nonces_each_call(self):
        key = _make_key()
        res1 = encrypt_file(b"same", key)
        res2 = encrypt_file(b"same", key)
        assert res1["nonce_hex"] != res2["nonce_hex"]

    def test_tampered_ciphertext_raises_invalid_tag(self):
        key = _make_key()
        res = encrypt_file(b"important data", key)
        # Flip one byte in the ciphertext
        tampered = bytearray(res["ciphertext"])
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_file(bytes(tampered), res["nonce_hex"], key)

    def test_wrong_key_raises_invalid_tag(self):
        key1 = _make_key("key1")
        key2 = _make_key("key2")
        res  = encrypt_file(b"data", key1)
        with pytest.raises(InvalidTag):
            decrypt_file(res["ciphertext"], res["nonce_hex"], key2)

    def test_empty_file(self):
        key = _make_key()
        res = encrypt_file(b"", key)
        pt  = decrypt_file(res["ciphertext"], res["nonce_hex"], key)
        assert pt == b""


import pytest  # noqa: E402 — placed after test definitions intentionally
