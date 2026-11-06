"""
routes/media_routes.py
───────────────────────
Media Vault: encrypted audio/video files with Winamp/HTML5 playback.
"""

import os
import io

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, send_file, abort, jsonify
)

import config
from modules.strings import MSG
from routes.auth_routes import login_required
from database.db import get_db
from modules.cryptography.key_management import master_key_from_hex, get_file_encryption_key
from modules.cryptography.file_encryption import decrypt_file, load_encrypted_file
from modules.media.winamp_integration import (
    is_winamp_available, play_with_winamp, save_temp_audio, cleanup_temp_file
)
from modules.blockchain.blockchain import add_block

media_bp = Blueprint("media", __name__)


def _file_key() -> bytes:
    mk = master_key_from_hex(session["master_key_hex"])
    return get_file_encryption_key(mk)


@media_bp.route("/media-vault")
@login_required
def index():
    with get_db() as db:
        files = db.execute(
            "SELECT * FROM vault_files WHERE user_id=? AND file_type IN ('audio','video') ORDER BY uploaded_at DESC",
            (session["user_id"],),
        ).fetchall()
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
        ciphertext = load_encrypted_file(row["stored_name"])
        fkey = _file_key()
        plaintext = decrypt_file(ciphertext, row["nonce"], fkey)
    except Exception:
        flash(MSG.MEDIA_DECRYPT_FAILED, "danger")
        return redirect(url_for("media.index"))

    add_block(session["user_id"], "DECRYPT", row["sha256_hash"])

    use_winamp = request.form.get("player") == "winamp" and is_winamp_available()

    if use_winamp:
        tmp_path = save_temp_audio(plaintext, row["original_name"])
        result = play_with_winamp(tmp_path)
        if result["success"]:
            flash(MSG.MEDIA_WINAMP_OPENED, "success")
        else:
            cleanup_temp_file(tmp_path)
            flash(MSG.MEDIA_WINAMP_ERROR.format(error=result.get('error')), "danger")
        return redirect(url_for("media.index"))
    else:
        # Serve decrypted bytes for HTML5 <audio>/<video>
        ext = os.path.splitext(row["original_name"])[1].lower().lstrip(".")
        mime_map = {
            "mp3": "audio/mpeg", "wav": "audio/wav", "ogg": "audio/ogg",
            "flac": "audio/flac", "m4a": "audio/mp4",
            "mp4": "video/mp4",  "webm": "video/webm",
        }
        mime = mime_map.get(ext, "application/octet-stream")
        return send_file(io.BytesIO(plaintext), mimetype=mime,
                         download_name=row["original_name"])
