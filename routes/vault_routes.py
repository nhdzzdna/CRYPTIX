"""
routes/vault_routes.py
───────────────────────
My Vault: upload, list, decrypt, and delete files.
File type: any allowed extension.
Encryption: AES-256-GCM (file_encryption.py).
"""

import os
import io
import hashlib

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, send_file, jsonify, abort
)
from PIL import Image
from werkzeug.utils import secure_filename

import config
from modules.strings import MSG
from modules.authentication.reauth import require_grant
from modules.rate_limit import limiter, REVEAL_LIMIT, user_or_ip_key
from routes.auth_routes import login_required
from database.db import get_db
from modules.cryptography import session_keys
from modules.cryptography.key_management import purpose_key
from modules.cryptography.database_encryption import decrypt_field, encrypt_field, field_aad
from modules.cryptography.file_encryption import (
    encrypt_stream, decrypt_all, generate_stored_name, file_aad,
)
from modules.blockchain.blockchain import add_block

vault_bp = Blueprint("vault", __name__)


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in config.ALLOWED_EXTENSIONS


_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}


def _valid_image(raw: bytes) -> bool:
    """Verifikasi isi gambar dengan Pillow, bukan hanya ekstensinya."""
    try:
        with Image.open(io.BytesIO(raw)) as image:
            image.verify()
        return True
    except Exception:
        return False


def _get_file_key() -> bytes:
    """Kunci enkripsi berkas = purpose_key(DEK sesi, "file")."""
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        abort(403)
    return purpose_key(dek, "file")


def _get_db_key() -> bytes:
    """Kunci field = purpose_key(DEK sesi, "database")."""
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        abort(403)
    return purpose_key(dek, "database")


def _name_aad(user_id) -> bytes:
    return field_aad(user_id, "vault_files", "original_name")


def _display_name(row, db_key: bytes) -> str:
    """Buka nama asli berkas untuk daftar; token gagal ditandai aman."""
    try:
        return decrypt_field(row["original_name"], db_key, _name_aad(row["user_id"]))
    except ValueError:
        return "[Nama tidak terbaca]"


# ── List files ────────────────────────────────────────────────────────────────

@vault_bp.route("/vault")
@login_required
def index():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM vault_files WHERE user_id=? ORDER BY uploaded_at DESC",
            (session["user_id"],),
        ).fetchall()

    db_key = _get_db_key()
    files = []
    for r in rows:
        row = dict(r)
        row["original_name"] = _display_name(r, db_key)
        files.append(row)
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
    if ext in _IMAGE_EXTENSIONS and not _valid_image(raw):
        flash(MSG.VAULT_FILE_CONTENT_INVALID, "danger")
        return redirect(url_for("vault.index"))
    if ext in _IMAGE_EXTENSIONS:
        file_type = "image"
    elif ext in {".mp3", ".wav", ".flac", ".ogg", ".m4a"}:
        file_type = "audio"
    elif ext in {".mp4", ".avi", ".mkv", ".mov"}:
        file_type = "video"
    else:
        file_type = "document"

    fkey = _get_file_key()
    stored_name = generate_stored_name()
    enc_result = encrypt_stream(
        io.BytesIO(raw),
        os.path.join(config.ENCRYPTED_FILES_DIR, stored_name),
        fkey,
        file_aad(session["user_id"], stored_name),
    )
    name_token = encrypt_field(filename, _get_db_key(), _name_aad(session["user_id"]))

    with get_db() as db:
        cursor = db.execute(
            """INSERT INTO vault_files
               (user_id, original_name, stored_name, file_type, file_size,
                sha256_hash, sha256_ciphertext)
               VALUES (?,?,?,?,?,?,?)""",
            (
                session["user_id"], name_token, stored_name, file_type, len(raw),
                enc_result["sha256_plaintext"], enc_result["sha256_ciphertext"],
            ),
        )
        file_id = cursor.lastrowid
        db.commit()

    add_block(session["user_id"], "UPLOAD", f"file:{file_id}",
              enc_result["sha256_ciphertext"])
    flash(MSG.VAULT_UPLOAD_SUCCESS.format(filename=filename), "success")
    return redirect(url_for("vault.index"))


# ── Download / Decrypt ────────────────────────────────────────────────────────

@vault_bp.route("/vault/decrypt/<int:resource_id>", methods=["POST"])
@limiter.limit(REVEAL_LIMIT, key_func=user_or_ip_key)
@login_required
@require_grant("file.download")
def decrypt(resource_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=?",
            (resource_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    try:
        fkey = _get_file_key()
        db_key = _get_db_key()
        path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        plaintext = decrypt_all(path, fkey, file_aad(row["user_id"], row["stored_name"]))
        if hashlib.sha256(plaintext).hexdigest() != row["sha256_hash"]:
            raise ValueError("SHA-256 plaintext tidak cocok dengan nilai tercatat.")
        original_name = decrypt_field(row["original_name"], db_key, _name_aad(row["user_id"]))
    except OSError:
        flash(MSG.VAULT_DECRYPT_FAILED, "danger")
        return redirect(url_for("vault.index"))
    except Exception:
        # Tag GCM gagal, struktur berkas tidak sah, atau hash plaintext beda.
        add_block(session["user_id"], "TAMPER_DETECTED", f"file:{resource_id}",
                  row["sha256_ciphertext"])
        flash(MSG.VAULT_DECRYPT_FAILED, "danger")
        return redirect(url_for("vault.index"))

    add_block(session["user_id"], "DOWNLOAD", f"file:{resource_id}",
              row["sha256_ciphertext"])

    response = send_file(
        io.BytesIO(plaintext),
        download_name=original_name,
        as_attachment=True,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


# ── Delete ────────────────────────────────────────────────────────────────────

@vault_bp.route("/vault/delete/<int:resource_id>", methods=["POST"])
@limiter.limit(REVEAL_LIMIT, key_func=user_or_ip_key)
@login_required
@require_grant("item.delete")
def delete(resource_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=?",
            (resource_id, session["user_id"]),
        ).fetchone()
        if not row:
            abort(404)

        enc_path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        if os.path.exists(enc_path):
            os.remove(enc_path)

        db.execute("DELETE FROM vault_files WHERE id=? AND user_id=?",
                   (resource_id, session["user_id"]))
        db.commit()

    add_block(session["user_id"], "DELETE", f"file:{resource_id}",
              row["sha256_ciphertext"])
    flash(MSG.VAULT_FILE_DELETED, "info")
    return redirect(url_for("vault.index"))
