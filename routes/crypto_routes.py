"""
routes/crypto_routes.py
────────────────────────
Crypto Tools: test each cipher individually and Super Encryption.
Pure Python, no file I/O needed.
"""

import hashlib
import re

from flask import Blueprint, jsonify, render_template, request

import config
from routes.auth_routes import login_required
from modules.strings import MSG
from modules.cryptography.classical_cipher_1 import (
    is_valid_vigenere_key, vigenere_letter_encrypt, vigenere_letter_decrypt,
)
from modules.cryptography.classical_cipher_2 import playfair_encrypt, playfair_decrypt
from modules.cryptography.modern_cipher_1    import chacha20_encrypt, chacha20_decrypt
from modules.cryptography.modern_cipher_2    import blowfish_encrypt, blowfish_decrypt
from modules.cryptography.super_encryption   import (
    super_encrypt, super_decrypt, super_encrypt_stages,
)

crypto_bp = Blueprint("crypto", __name__)

# Salt tetap untuk turunan kunci alat (domain separation antar penggunaan).
_TOOL_KDF_SALT = b"cryptix-crypto-tools-v1"


def _wants_json() -> bool:
    """True bila pemanggil mengharapkan balasan JSON, bukan halaman HTML."""
    if request.is_json:
        return True
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    penerima = request.accept_mimetypes
    return (
        penerima.best_match(["text/html", "application/json"]) == "application/json"
        and penerima["application/json"] > penerima["text/html"]
    )


def _tool_key(key: str) -> bytes:
    """
    Turunkan kunci 32 byte untuk alat kripto individual.

    Heksadesimal 64 digit dipakai langsung sebagai kunci mentah; teks lain
    diturunkan dengan PBKDF2-HMAC-SHA256 bersalt, bukan SHA-256 polos.
    """
    k = key.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", k):
        return bytes.fromhex(k)
    if not k:
        raise ValueError("Kunci tidak boleh kosong.")
    return hashlib.pbkdf2_hmac(
        config.PBKDF2_HASH_ALGO,
        k.encode("utf-8"),
        _TOOL_KDF_SALT,
        config.SUPER_ENC_PBKDF2_ITERATIONS,
        dklen=32,
    )


@crypto_bp.route("/crypto-tools", methods=["GET", "POST"])
@login_required
def index():
    result = None
    error  = None
    stages = None
    status = 200

    if request.method == "POST":
        action     = request.form.get("action", "encrypt")   # encrypt / decrypt
        cipher     = request.form.get("cipher", "super")
        text       = request.form.get("text",       "")
        key        = request.form.get("key",        "")
        passphrase = request.form.get("passphrase", "")

        try:
            if cipher == "vigenere":
                if not is_valid_vigenere_key(key):
                    error = MSG.CRYPTO_VIGENERE_KEY_INVALID
                    status = 400
                    if _wants_json():
                        return jsonify({"error": error}), status
                else:
                    result = (
                        vigenere_letter_encrypt(text, key)
                        if action == "encrypt"
                        else vigenere_letter_decrypt(text, key)
                    )

            elif cipher == "playfair":
                result = playfair_encrypt(text, key) if action == "encrypt" else playfair_decrypt(text, key)

            elif cipher == "chacha20":
                bkey = _tool_key(key)
                result = chacha20_encrypt(text, bkey) if action == "encrypt" else chacha20_decrypt(text, bkey)

            elif cipher == "blowfish":
                bkey = _tool_key(key)
                result = blowfish_encrypt(text, bkey) if action == "encrypt" else blowfish_decrypt(text, bkey)

            elif cipher == "super":
                if not passphrase:
                    error = MSG.CRYPTO_PASSPHRASE_REQUIRED
                elif action == "encrypt" and request.form.get("show_steps"):
                    detail = super_encrypt_stages(text, passphrase=passphrase)
                    result = detail["final"]
                    stages = detail["stages"]
                else:
                    result = (
                        super_encrypt(text, passphrase=passphrase)
                        if action == "encrypt"
                        else super_decrypt(text, passphrase=passphrase)
                    )
            else:
                error = MSG.CRYPTO_UNKNOWN_CIPHER
        except Exception:
            error = MSG.CRYPTO_OPERATION_FAILED

    return render_template(
        "crypto_tools.html", result=result, error=error, stages=stages,
    ), status
