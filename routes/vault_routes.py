"""
routes/vault_routes.py
───────────────────────
My Vault: upload, list, decrypt, and delete files.
File type: any allowed extension.
Encryption: AES-256-GCM (file_encryption.py).
"""

import os
import hashlib

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, send_file, jsonify, abort
)
from werkzeug.utils import secure_filename

import config
from modules.strings import MSG
from routes.auth_routes import login_required
from database.db import get_db
from modules.cryptography.key_management import master_key_from_hex, get_file_encryption_key
from modules.cryptography.file_encryption import (
    encrypt_file, decrypt_file, save_encrypted_file,
    load_encrypted_file, generate_stored_name,
)
from modules.blockchain.blockchain import add_block

vault_bp = Blueprint("vault", __name__)


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in config.ALLOWED_EXTENSIONS


def _get_file_key() -> bytes:
    mk = master_key_from_hex(session["master_key_hex"])
    return get_file_encryption_key(mk)


# ── List files ────────────────────────────────────────────────────────────────

@vault_bp.route("/vault")
@login_required
def index():
    with get_db() as db:
        files = db.execute(
            "SELECT * FROM vault_files WHERE user_id=? ORDER BY uploaded_at DESC",
            (session["user_id"],),
        ).fetchall()
    return render_template("vault.html", files=files)


# ── Upload ────────────────────────────────────────────────────────────────────

@vault_bp.route("/vault/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        flash(MSG.VAULT_NO_FILE_SELECTED, "warning")
        return redirect(url_for("vault.index"))

    filename = secure_filename(f.filename)
    if not _allowed_file(filename):
        flash(MSG.VAULT_FILE_TYPE_DENIED, "danger")
        return redirect(url_for("vault.index"))

    raw = f.read()
    if len(raw) > config.MAX_CONTENT_LENGTH:
        flash(MSG.VAULT_FILE_TOO_LARGE, "danger")
        return redirect(url_for("vault.index"))

    ext = os.path.splitext(filename)[1].lower()
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}:
        file_type = "image"
    elif ext in {".mp3", ".wav", ".flac", ".ogg", ".m4a"}:
        file_type = "audio"
    elif ext in {".mp4", ".avi", ".mkv", ".mov"}:
        file_type = "video"
    else:
        file_type = "document"

    fkey = _get_file_key()
    enc_result = encrypt_file(raw, fkey)
    stored_name = generate_stored_name(filename)
    save_encrypted_file(enc_result["ciphertext"], stored_name)

    with get_db() as db:
        db.execute(
            """INSERT INTO vault_files
               (user_id, original_name, stored_name, file_type, file_size, nonce, tag, sha256_hash)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                session["user_id"], filename, stored_name, file_type, len(raw),
                enc_result["nonce_hex"], enc_result["tag_hex"], enc_result["sha256_hex"],
            ),
        )
        db.commit()

    add_block(session["user_id"], "UPLOAD", enc_result["sha256_hex"])
    flash(MSG.VAULT_UPLOAD_SUCCESS.format(filename=filename), "success")
    return redirect(url_for("vault.index"))


# ── Download / Decrypt ────────────────────────────────────────────────────────

@vault_bp.route("/vault/decrypt/<int:file_id>")
@login_required
def decrypt(file_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=?",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    try:
        ciphertext = load_encrypted_file(row["stored_name"])
        fkey = _get_file_key()
        plaintext = decrypt_file(ciphertext, row["nonce"], fkey)
    except Exception:
        flash(MSG.VAULT_DECRYPT_FAILED, "danger")
        return redirect(url_for("vault.index"))

    add_block(session["user_id"], "DECRYPT", row["sha256_hash"])

    import io
    return send_file(
        io.BytesIO(plaintext),
        download_name=row["original_name"],
        as_attachment=True,
    )


# ── Delete ────────────────────────────────────────────────────────────────────

@vault_bp.route("/vault/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=?",
            (file_id, session["user_id"]),
        ).fetchone()
        if not row:
            abort(404)

        enc_path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        if os.path.exists(enc_path):
            os.remove(enc_path)

        db.execute("DELETE FROM vault_files WHERE id=?", (file_id,))
        db.commit()

    add_block(session["user_id"], "DELETE", row["sha256_hash"])
    flash(MSG.VAULT_FILE_DELETED, "info")
    return redirect(url_for("vault.index"))
