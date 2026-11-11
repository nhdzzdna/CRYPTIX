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
from routes.collection_shared import halaman_koleksi
from modules import trash

vault_bp = Blueprint("vault", __name__)


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in config.ALLOWED_EXTENSIONS


_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
_AUDIO_EXTENSIONS = {".mp3", ".wav", ".flac", ".ogg", ".m4a"}


def _tujuan_unggah() -> str:
    """Halaman kembali setelah unggah sesuai kategori formulir."""
    if (request.form.get("kategori") or "").strip().lower() == "musik":
        return "collection.musik"
    return "vault.index"


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
    db_key = _get_db_key()
    with get_db() as db:
        data = halaman_koleksi(
            db, session["user_id"], "dokumen", ("document",), db_key,
        )
    return render_template(
        "vault.html",
        folders=data["folders"],
        unfiled=data["unfiled"],
        msg=_dokumen_msg(),
    )


def _dokumen_msg() -> dict:
    """Teks antarmuka halaman Dokumen."""
    return {
        "title": MSG.DOCUMENT_TITLE,
        "upload_title": MSG.DOCUMENT_UPLOAD_TITLE,
        "folder_section": MSG.DOCUMENT_FOLDER_SECTION,
        "unfiled_section": MSG.DOCUMENT_UNFILED_SECTION,
        "empty": MSG.DOCUMENT_EMPTY,
        "unfiled_empty": MSG.DOCUMENT_UNFILED_EMPTY,
        "search_label": MSG.DOCUMENT_SEARCH_LABEL,
        "search_placeholder": MSG.DOCUMENT_SEARCH_PLACEHOLDER,
        "sort_label": MSG.DOCUMENT_SORT_LABEL,
        "sort_name": MSG.DOCUMENT_SORT_NAME,
        "sort_date": MSG.DOCUMENT_SORT_DATE,
        "sort_size": MSG.DOCUMENT_SORT_SIZE,
        "folder_placeholder": MSG.FOLDER_CREATE_PLACEHOLDER,
        "folder_create_button": MSG.FOLDER_CREATE_BUTTON,
        "folder_lock_label": MSG.FOLDER_LOCK_LABEL,
        "folder_rename": MSG.FOLDER_RENAME_BUTTON,
        "folder_delete": MSG.FOLDER_DELETE_BUTTON,
        "folder_lock_toggle": MSG.FOLDER_LOCK_TOGGLE,
        "folder_unlock_toggle": MSG.FOLDER_UNLOCK_TOGGLE,
        "hidden_button": MSG.FOLDER_HIDDEN_BUTTON,
        "count": MSG.FOLDER_COUNT,
        "locked_suffix": MSG.FOLDER_LOCKED_SUFFIX,
        "move_none": MSG.FOLDER_MOVE_TARGET_NONE,
        "move_button": MSG.FOLDER_MOVE_BUTTON,
        "lock_items": MSG.COLLECTION_LOCK_ITEMS,
        "hide_items": MSG.COLLECTION_HIDE_ITEMS,
        "delete_confirm": MSG.DOCUMENT_DELETE_CONFIRM,
        "download": MSG.DOCUMENT_DOWNLOAD,
        "delete_file": MSG.DOCUMENT_DELETE,
        "move": MSG.COLLECTION_MOVED,
        "state": MSG.COLLECTION_STATE_CHANGED,
        "need_folder": MSG.FOLDER_PICK_NOTE,
        "error": MSG.COLLECTION_ACTION_DENIED,
    }


# ── Upload ────────────────────────────────────────────────────────────────────

@vault_bp.route("/vault/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        flash(MSG.VAULT_NO_FILE_SELECTED, "warning")
        return redirect(url_for(_tujuan_unggah()))

    filename = secure_filename(f.filename)
    if not _allowed_file(filename):
        flash(MSG.VAULT_FILE_TYPE_DENIED, "danger")
        return redirect(url_for(_tujuan_unggah()))

    ext = os.path.splitext(filename)[1].lower()
    kategori = (request.form.get("kategori") or "").strip().lower()
    if kategori == "musik" and ext not in _AUDIO_EXTENSIONS:
        flash(MSG.VAULT_FILE_TYPE_DENIED, "danger")
        return redirect(url_for(_tujuan_unggah()))

    raw = f.read()
    if len(raw) > config.MAX_CONTENT_LENGTH:
        flash(MSG.VAULT_FILE_TOO_LARGE, "danger")
        return redirect(url_for(_tujuan_unggah()))

    if ext in _IMAGE_EXTENSIONS and not _valid_image(raw):
        flash(MSG.VAULT_FILE_CONTENT_INVALID, "danger")
        return redirect(url_for(_tujuan_unggah()))
    if ext in _IMAGE_EXTENSIONS:
        file_type = "image"
    elif ext in _AUDIO_EXTENSIONS:
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
    return redirect(url_for(_tujuan_unggah()))


# ── Download / Decrypt ────────────────────────────────────────────────────────

@vault_bp.route("/vault/decrypt/<int:resource_id>", methods=["POST"])
@limiter.limit(REVEAL_LIMIT, key_func=user_or_ip_key)
@login_required
@require_grant("file.download")
def decrypt(resource_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=? "
            "AND deleted_at IS NULL",
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
def delete(resource_id: int):
    """Pindahkan berkas ke Sampah (soft delete); purge dilakukan di /sampah."""
    with get_db() as db:
        row = trash.pindah_ke_sampah(db, "file", resource_id, session["user_id"])
    if row is None:
        abort(404)

    add_block(session["user_id"], "TRASH_MOVE", f"file:{resource_id}",
              trash.hash_aset("file", row))
    flash(MSG.TRASH_MOVED_FILE, "info")
    return redirect(url_for("vault.index"))
