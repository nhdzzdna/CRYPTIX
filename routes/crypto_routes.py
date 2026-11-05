"""
routes/crypto_routes.py
─────────────────────────
Crypto Tools: test each cipher individually and Super Encryption.
Pure Python, no file I/O needed.
"""

import os
import sys
from flask import Blueprint, render_template, request, session

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from routes.auth_routes import login_required
from modules.cryptography.classical_cipher_1 import vigenere_encrypt, vigenere_decrypt
from modules.cryptography.classical_cipher_2 import playfair_encrypt, playfair_decrypt
from modules.cryptography.modern_cipher_1    import chacha20_encrypt, chacha20_decrypt
from modules.cryptography.modern_cipher_2    import blowfish_encrypt, blowfish_decrypt
from modules.cryptography.super_encryption   import super_encrypt, super_decrypt

crypto_bp = Blueprint("crypto", __name__)


@crypto_bp.route("/crypto-tools", methods=["GET", "POST"])
@login_required
def index():
    result = None
    error  = None

    if request.method == "POST":
        action     = request.form.get("action", "encrypt")   # encrypt / decrypt
        cipher     = request.form.get("cipher", "super")
        text       = request.form.get("text",       "")
        key        = request.form.get("key",        "")
        passphrase = request.form.get("passphrase", "")

        try:
            if cipher == "vigenere":
                result = vigenere_encrypt(text, key) if action == "encrypt" else vigenere_decrypt(text, key)

            elif cipher == "playfair":
                result = playfair_encrypt(text, key) if action == "encrypt" else playfair_decrypt(text, key)

            elif cipher == "chacha20":
                if not key or len(bytes.fromhex(key.zfill(64))) < 32:
                    # Derive 32-byte key from passphrase via sha256 if user typed text key
                    import hashlib
                    bkey = hashlib.sha256(key.encode()).digest()
                else:
                    bkey = bytes.fromhex(key.zfill(64))[:32]
                result = chacha20_encrypt(text, bkey) if action == "encrypt" else chacha20_decrypt(text, bkey)

            elif cipher == "blowfish":
                import hashlib
                bkey = hashlib.sha256(key.encode()).digest()
                result = blowfish_encrypt(text, bkey) if action == "encrypt" else blowfish_decrypt(text, bkey)

            elif cipher == "super":
                if not passphrase:
                    error = "Passphrase is required for Super Encryption."
                else:
                    result = (
                        super_encrypt(text, passphrase=passphrase)
                        if action == "encrypt"
                        else super_decrypt(text, passphrase=passphrase)
                    )
            else:
                error = f"Unknown cipher: {cipher}"
        except Exception as exc:
            error = str(exc)

    return render_template("crypto_tools.html", result=result, error=error)
