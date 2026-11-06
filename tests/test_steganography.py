"""
tests/test_steganography.py
────────────────────────────
Unit tests for LSB steganography.
Creates real PNG images in a temp directory.
"""

import os
import tempfile

import pytest
from PIL import Image
import numpy as np

from modules.steganography.lsb import embed_message, extract_message


def _make_white_png(path: str, width: int = 100, height: int = 100) -> None:
    """Create a small white RGB PNG for testing."""
    arr = np.full((height, width, 3), 255, dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(path, format="PNG")


class TestLSBSteganography:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_embed_and_extract_basic(self):
        src = os.path.join(self.tmpdir, "carrier.png")
        out = os.path.join(self.tmpdir, "stego.png")
        _make_white_png(src)
        msg = "Hello LSB!"
        result = embed_message(src, msg, out)
        assert result["success"] is True

        ext = extract_message(out)
        assert ext["success"] is True
        assert ext["message"] == msg

    def test_capacity_check(self):
        src = os.path.join(self.tmpdir, "tiny.png")
        out = os.path.join(self.tmpdir, "tiny_stego.png")
        # 10×10 = 300 channel bits → ~(300-32)/8 = 33 bytes capacity
        _make_white_png(src, 10, 10)
        long_msg = "A" * 500   # way over capacity
        result = embed_message(src, long_msg, out)
        assert result["success"] is False
        assert "terlalu besar" in result["error"].lower()

    def test_embed_and_extract_with_encryption(self):
        import hashlib
        mk  = hashlib.sha256(b"stego_master_key").digest()
        src = os.path.join(self.tmpdir, "carrier2.png")
        out = os.path.join(self.tmpdir, "stego2.png")
        _make_white_png(src, 200, 200)
        msg = "Encrypted LSB message"
        embed_result = embed_message(src, msg, out, master_key=mk)
        assert embed_result["success"] is True
        assert embed_result["encrypted"] is True

        ext = extract_message(out, master_key=mk)
        assert ext["success"] is True
        assert ext["message"] == msg

    def test_extract_without_key_on_encrypted_message(self):
        """Extracting without key should return garbled/error result."""
        import hashlib
        mk  = hashlib.sha256(b"stego_enc_key").digest()
        src = os.path.join(self.tmpdir, "carrier3.png")
        out = os.path.join(self.tmpdir, "stego3.png")
        _make_white_png(src, 200, 200)
        embed_message(src, "Secret!", out, master_key=mk)

        # Attempt extraction without key → should not equal original
        ext = extract_message(out)
        if ext["success"]:
            assert ext["message"] != "Secret!"

    def test_no_stego_image_gives_error(self):
        """A plain image with no embedded message should fail or return nonsense."""
        src = os.path.join(self.tmpdir, "plain.png")
        _make_white_png(src, 50, 50)
        result = extract_message(src)
        # All-white image LSBs are 0 → length will be 0 → error
        assert result["success"] is False or result.get("message") == ""
