"""
routes/media_routes.py
───────────────────────
Media Vault: encrypted audio/video files with Winamp/HTML5 playback.
"""

import os
import io
import hashlib

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, send_file, abort, jsonify
)

import config
from modules.strings import MSG
from routes.auth_routes import login_required
from database.db import get_db
from modules.cryptography import session_keys
from modules.cryptography.key_management import purpose_key
from modules.cryptography.database_encryption import decrypt_field, field_aad
from modules.cryptography.file_encryption import decrypt_all, file_aad
from modules.media.winamp_integration import (
    is_winamp_available, play_with_winamp, save_temp_audio, cleanup_temp_file
)
from modules.blockchain.blockchain import add_block

media_bp = Blueprint("media", __name__)


def _file_key() -> bytes:
    """Kunci enkripsi berkas = purpose_key(DEK sesi, "file")."""
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        abort(403)
    return purpose_key(dek, "file")


def _db_key() -> bytes:
    """Kunci field = purpose_key(DEK sesi, "database")."""
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        abort(403)
    return purpose_key(dek, "database")


def _display_name(row, db_key: bytes) -> str:
    """Buka nama asli media untuk daftar; token gagal ditandai aman."""
    try:
        return decrypt_field(
            row["original_name"], db_key,
            field_aad(row["user_id"], "vault_files", "original_name"),
        )
    except ValueError:
        return "[Nama tidak terbaca]"


@media_bp.route("/media-vault")
@login_required
def index():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM vault_files WHERE user_id=? AND file_type IN ('audio','video') ORDER BY uploaded_at DESC",
            (session["user_id"],),
        ).fetchall()

    db_key = _db_key()
    files = []
    for r in rows:
        row = dict(r)
        row["original_name"] = _display_name(r, db_key)
        files.append(row)
    return render_template("media_vault.html", files=files, winamp_available=is_winamp_available())


@media_bp.route("/media-vault/play/<int:file_id>", methods=["POST"])
@login_required
def play(file_id: int):
    """Decrypt and play in Winamp (if available) or return audio for HTML5."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=? AND file_type IN ('audio','video')",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    try:
        fkey = _file_key()
        db_key = _db_key()
        path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        plaintext = decrypt_all(path, fkey, file_aad(row["user_id"], row["stored_name"]))
        if hashlib.sha256(plaintext).hexdigest() != row["sha256_hash"]:
            raise ValueError("SHA-256 plaintext tidak cocok dengan nilai tercatat.")
        original_name = decrypt_field(
            row["original_name"], db_key,
            field_aad(row["user_id"], "vault_files", "original_name"),
        )
    except OSError:
        flash(MSG.MEDIA_DECRYPT_FAILED, "danger")
        return redirect(url_for("media.index"))
    except Exception:
        # Tag GCM gagal, struktur berkas tidak sah, atau hash plaintext beda.
        add_block(session["user_id"], "TAMPER_DETECTED", f"file:{file_id}",
                  row["sha256_ciphertext"])
        flash(MSG.MEDIA_DECRYPT_FAILED, "danger")
        return redirect(url_for("media.index"))

    add_block(session["user_id"], "STREAM", f"file:{file_id}",
              row["sha256_ciphertext"])

    use_winamp = request.form.get("player") == "winamp" and is_winamp_available()

    if use_winamp:
        tmp_path = save_temp_audio(plaintext, original_name)
        result = play_with_winamp(tmp_path)
        if result["success"]:
            flash(MSG.MEDIA_WINAMP_OPENED, "success")
        else:
            cleanup_temp_file(tmp_path)
            flash(MSG.MEDIA_WINAMP_ERROR.format(error=result.get('error')), "danger")
        return redirect(url_for("media.index"))
    else:
        # Serve decrypted bytes for HTML5 <audio>/<video>
        ext = os.path.splitext(original_name)[1].lower().lstrip(".")
        mime_map = {
            "mp3": "audio/mpeg", "wav": "audio/wav", "ogg": "audio/ogg",
            "flac": "audio/flac", "m4a": "audio/mp4",
            "mp4": "video/mp4",  "webm": "video/webm",
        }
        mime = mime_map.get(ext, "application/octet-stream")
        return send_file(io.BytesIO(plaintext), mimetype=mime,
                         download_name=original_name)
