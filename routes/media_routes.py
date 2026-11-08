"""
routes/media_routes.py
───────────────────────
Media Vault: encrypted audio/video files with Winamp/HTML5 playback.
"""

import io
import os
import hashlib

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, abort, Response, send_file
)

import config
from modules.strings import MSG
from modules.authentication.reauth import require_grant
from routes.auth_routes import login_required
from database.db import get_db
from modules.cryptography import session_keys
from modules.cryptography.key_management import purpose_key
from modules.cryptography.database_encryption import decrypt_field, field_aad
from modules.cryptography.file_encryption import (
    decrypt_all, decrypt_range, file_aad,
)
from modules.media.winamp_integration import (
    is_winamp_available, play_with_winamp, save_temp_audio, cleanup_temp_file
)
from modules.blockchain.blockchain import add_block

media_bp = Blueprint("media", __name__)

# ── MIME dan format yang dapat diputar (Sesi J1) ─────────────────────────────
MIME_TYPES = {
    "mp3":  "audio/mpeg",
    "wav":  "audio/wav",
    "ogg":  "audio/ogg",
    "oga":  "audio/ogg",
    "flac": "audio/flac",
    "m4a":  "audio/mp4",
    "aac":  "audio/aac",
    "mp4":  "video/mp4",
    "m4v":  "video/mp4",
    "webm": "video/webm",
    "avi":  "video/x-msvideo",
    "mkv":  "video/x-matroska",
    "mov":  "video/quicktime",
}

PLAYABLE_EXTENSIONS = frozenset({
    "mp4", "webm", "mp3", "wav", "ogg", "m4a", "flac",
})
DOWNLOAD_ONLY_EXTENSIONS = frozenset({"avi", "mkv", "mov"})


def _extension(filename: str) -> str:
    """Ekstensi huruf kecil tanpa titik; string kosong bila tidak ada."""
    return os.path.splitext(filename or "")[1].lower().lstrip(".")


def mime_for(filename: str) -> str:
    """MIME yang sesuai untuk format yang dikenal."""
    return MIME_TYPES.get(_extension(filename), "application/octet-stream")


def is_playable(filename: str) -> bool:
    """True bila ekstensi termasuk format yang dapat dicoba di browser."""
    return _extension(filename) in PLAYABLE_EXTENSIONS


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
        ext = _extension(row["original_name"])
        row["extension"] = ext
        row["mime"] = MIME_TYPES.get(ext, "application/octet-stream")
        row["playable"] = ext in PLAYABLE_EXTENSIONS
        row["download_only"] = ext in DOWNLOAD_ONLY_EXTENSIONS
        files.append(row)
    return render_template(
        "media_vault.html",
        files=files,
        winamp_available=is_winamp_available(),
        download_only_note=MSG.MEDIA_DOWNLOAD_ONLY,
        temp_warning=MSG.MEDIA_TEMP_WARNING,
    )


def _parse_range_header(header: str, size: int):
    """
    Urai satu rentang byte ``bytes=start-end`` / ``bytes=start-`` / ``bytes=-n``.

    Returns
    -------
    tuple[int, int] | None  Rentang inklusif yang sudah dipotong ke ukuran
                            berkas, atau None bila tidak valid.
    """
    if not header or not header.startswith("bytes="):
        return None
    spec = header[len("bytes="):].strip()
    if not spec or "," in spec or "-" not in spec:
        return None

    first, _, last = spec.partition("-")
    first, last = first.strip(), last.strip()
    try:
        if first == "":
            if last == "" or size == 0:
                return None
            suffix = int(last)
            if suffix <= 0:
                return None
            return max(0, size - suffix), size - 1

        start = int(first)
        if start < 0 or size == 0 or start >= size:
            return None
        if last == "":
            return start, size - 1
        end = int(last)
        if end < start:
            return None
        return start, min(end, size - 1)
    except ValueError:
        return None


def _range_not_satisfiable(size: int) -> Response:
    """Respons 416 dengan Content-Range sesuai standar HTTP."""
    response = Response(status=416)
    response.headers["Content-Range"] = f"bytes */{size}"
    response.headers["Accept-Ranges"] = "bytes"
    return response


@media_bp.route("/media-vault/stream/<int:file_id>")
@login_required
@require_grant("media.stream")
def stream(file_id: int):
    """
    Sajikan media terenkripsi lewat HTTP Range tanpa menulis plaintext ke disk.

    Rentang yang valid dijawab 206 Partial Content; rentang tidak valid 416.
    Hanya chunk yang beririsan dengan rentang yang didekripsi.
    """
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=? AND file_type IN ('audio','video')",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    try:
        original_name = decrypt_field(
            row["original_name"], _db_key(),
            field_aad(row["user_id"], "vault_files", "original_name"),
        )
    except ValueError:
        abort(404)

    ext = _extension(original_name)
    if ext not in PLAYABLE_EXTENSIONS:
        return Response(MSG.MEDIA_STREAM_UNSUPPORTED, status=415,
                        mimetype="text/plain")

    size = int(row["file_size"])
    path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
    fkey = _file_key()
    aad = file_aad(row["user_id"], row["stored_name"])
    mime = MIME_TYPES.get(ext, "application/octet-stream")

    range_header = request.headers.get("Range")
    try:
        if range_header is not None:
            parsed = _parse_range_header(range_header, size)
            if parsed is None:
                return _range_not_satisfiable(size)
            start, end = parsed
            data = decrypt_range(path, fkey, aad, start, end)
            if len(data) != end - start + 1:
                return _range_not_satisfiable(size)

            response = Response(data, status=206, mimetype=mime)
            response.headers["Content-Range"] = f"bytes {start}-{end}/{size}"
            response.headers["Accept-Ranges"] = "bytes"
            response.headers["Content-Length"] = str(len(data))
            if start == 0:
                add_block(session["user_id"], "STREAM", f"file:{file_id}",
                          row["sha256_ciphertext"])
            return response

        # Tanpa Range: layani seluruh berkas dan verifikasi hash plaintext.
        data = decrypt_all(path, fkey, aad)
        if hashlib.sha256(data).hexdigest() != row["sha256_hash"]:
            raise ValueError("SHA-256 plaintext tidak cocok dengan nilai tercatat.")
        response = Response(data, status=200, mimetype=mime)
        response.headers["Accept-Ranges"] = "bytes"
        response.headers["Content-Length"] = str(len(data))
        add_block(session["user_id"], "STREAM", f"file:{file_id}",
                  row["sha256_ciphertext"])
        return response
    except OSError:
        abort(404)
    except Exception:
        # Tag GCM gagal atau hash plaintext berbeda: jangan sajikan data.
        add_block(session["user_id"], "TAMPER_DETECTED", f"file:{file_id}",
                  row["sha256_ciphertext"])
        abort(403)


@media_bp.route("/media-vault/play/<int:file_id>", methods=["POST"])
@login_required
@require_grant("media.winamp")
def play(file_id: int):
    """Buka audio di Winamp; pemutaran HTML5 memakai rute stream."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=? AND file_type IN ('audio','video')",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    use_winamp = (
        request.form.get("player") == "winamp" and is_winamp_available()
    )
    if not use_winamp:
        return redirect(url_for("media.stream", file_id=file_id))
    if row["file_type"] != "audio":
        abort(400)

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

    # Berkas plaintext sementara hanya dibuat karena Winamp benar-benar dipakai.
    tmp_path = save_temp_audio(plaintext, original_name)
    result = play_with_winamp(tmp_path)
    if result["success"]:
        flash(MSG.MEDIA_WINAMP_OPENED, "success")
    else:
        cleanup_temp_file(tmp_path)
        flash(MSG.MEDIA_WINAMP_ERROR.format(error=result.get('error')), "danger")
    return redirect(url_for("media.index"))


@media_bp.route("/media-vault/download/<int:file_id>")
@login_required
@require_grant("file.download")
def download(file_id: int):
    """Unduh media terenkripsi sebagai lampiran setelah autentikasi ulang."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=? "
            "AND file_type IN ('audio','video')",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    try:
        original_name = decrypt_field(
            row["original_name"], _db_key(),
            field_aad(row["user_id"], "vault_files", "original_name"),
        )
        path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        plaintext = decrypt_all(
            path, _file_key(), file_aad(row["user_id"], row["stored_name"])
        )
        if hashlib.sha256(plaintext).hexdigest() != row["sha256_hash"]:
            raise ValueError("SHA-256 plaintext tidak cocok dengan nilai tercatat.")
    except OSError:
        abort(404)
    except Exception:
        add_block(session["user_id"], "TAMPER_DETECTED", f"file:{file_id}",
                  row["sha256_ciphertext"])
        abort(403)

    return send_file(
        io.BytesIO(plaintext),
        mimetype=mime_for(original_name),
        download_name=original_name,
        as_attachment=True,
    )
