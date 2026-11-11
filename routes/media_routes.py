"""
routes/media_routes.py
───────────────────────
Media Vault: encrypted audio/video files with Winamp/HTML5 playback,
plus in-memory document preview (PDF, image, text) with magic-byte
detection.
"""

import io
import os
import hashlib

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, abort, Response, send_file, jsonify
)
from PIL import Image

import config
from modules.strings import MSG
from modules.authentication.reauth import require_grant
from modules.rate_limit import limiter, REVEAL_LIMIT, user_or_ip_key
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
from routes.collection_shared import (
    halaman_koleksi, file_info as _berkas_info, akses_item, display_name,
)

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

IMAGE_MIME_TYPES = {
    "png":  "image/png",
    "jpg":  "image/jpeg",
    "jpeg": "image/jpeg",
    "gif":  "image/gif",
    "bmp":  "image/bmp",
    "webp": "image/webp",
}


def _mime_any(filename: str) -> str:
    """MIME untuk media apa pun termasuk gambar."""
    ext = _extension(filename)
    return IMAGE_MIME_TYPES.get(ext) or MIME_TYPES.get(
        ext, "application/octet-stream"
    )


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
    """Buka nama asli media; token gagal memakai nama penyimpanan ringkas."""
    return display_name(row, db_key)


@media_bp.route("/media-vault")
@login_required
def index():
    db_key = _db_key()
    with get_db() as db:
        data = halaman_koleksi(
            db, session["user_id"], "album", ("image", "video"), db_key,
        )

    return render_template(
        "media_vault.html",
        albums=data["folders"],
        unfiled=data["unfiled"],
        semua=data["semua"],
        winamp_available=is_winamp_available(),
        download_only_note=MSG.MEDIA_DOWNLOAD_ONLY,
        temp_warning=MSG.MEDIA_TEMP_WARNING,
        empty_note=MSG.COLLECTION_EMPTY,
        msg={
            "move": MSG.COLLECTION_MOVED,
            "state": MSG.COLLECTION_STATE_CHANGED,
            "need_collection": MSG.COLLECTION_PICK_ONE,
            "error": MSG.COLLECTION_ACTION_DENIED,
            "delete_confirm": MSG.COLLECTION_DELETE_CONFIRM,
        },
    )


def _collection_name(row, db_key: bytes) -> str:
    """Buka nama koleksi; token gagal ditandai aman."""
    try:
        return decrypt_field(
            row["name_enc"], db_key,
            field_aad(row["user_id"], "collections", "name_enc"),
        )
    except ValueError:
        return "[Nama tidak terbaca]"


def _media_info(row, db_key: bytes) -> dict:
    """Bentuk data tampilan aman untuk satu berkas media."""
    return _berkas_info(row, db_key)


def _respons_terkunci(pesan: str, status: int):
    """Penolakan JSON reason 'terkunci' untuk item/album yang terkunci."""
    return jsonify({
        "success": False,
        "error": pesan,
        "reason": "terkunci",
    }), status


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


@media_bp.route("/media-vault/view/<int:file_id>")
@login_required
def view(file_id: int):
    """
    Pratinjau gambar/audio/video dengan dekripsi di memori.

    Mendukung HTTP Range (206/416) dan tidak pernah menyimpan plaintext
    ke disk. Akses mengikuti state item dan kunci koleksi.
    """
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=? "
            "AND deleted_at IS NULL",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    ditolak = akses_item(row, file_id)
    if ditolak:
        return _respons_terkunci(*ditolak)

    try:
        original_name = decrypt_field(
            row["original_name"], _db_key(),
            field_aad(row["user_id"], "vault_files", "original_name"),
        )
    except ValueError:
        abort(404)

    size = int(row["file_size"])
    path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
    fkey = _file_key()
    aad = file_aad(row["user_id"], row["stored_name"])
    mime = _mime_any(original_name)

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
        else:
            data = decrypt_all(path, fkey, aad)
            if hashlib.sha256(data).hexdigest() != row["sha256_hash"]:
                raise ValueError("SHA-256 plaintext tidak cocok dengan nilai tercatat.")
            response = Response(data, status=200, mimetype=mime)
            response.headers["Accept-Ranges"] = "bytes"
            response.headers["Content-Length"] = str(len(data))
    except OSError:
        abort(404)
    except Exception:
        add_block(session["user_id"], "TAMPER_DETECTED", f"file:{file_id}",
                  row["sha256_ciphertext"])
        abort(403)

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@media_bp.route("/media-vault/thumb/<int:file_id>")
@login_required
def thumb(file_id: int):
    """Thumbnail gambar diperkecil di memori; video/audio tidak punya."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=? "
            "AND deleted_at IS NULL",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row or row["file_type"] != "image":
        abort(404)

    ditolak = akses_item(row, file_id)
    if ditolak:
        return _respons_terkunci(*ditolak)

    try:
        path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        plaintext = decrypt_all(
            path, _file_key(), file_aad(row["user_id"], row["stored_name"])
        )
        if hashlib.sha256(plaintext).hexdigest() != row["sha256_hash"]:
            raise ValueError("SHA-256 plaintext tidak cocok dengan nilai tercatat.")
        with Image.open(io.BytesIO(plaintext)) as gambar:
            gambar.thumbnail((320, 320))
            keluaran = io.BytesIO()
            gambar.convert("RGB").save(keluaran, format="JPEG", quality=82)
        data = keluaran.getvalue()
    except OSError:
        abort(404)
    except Exception:
        add_block(session["user_id"], "TAMPER_DETECTED", f"file:{file_id}",
                  row["sha256_ciphertext"])
        abort(403)

    response = Response(data, status=200, mimetype="image/jpeg")
    response.headers["Content-Length"] = str(len(data))
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
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
            "SELECT * FROM vault_files WHERE id=? AND user_id=? "
            "AND deleted_at IS NULL AND file_type IN ('audio','video')",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    ditolak = akses_item(row, file_id)
    if ditolak:
        return _respons_terkunci(*ditolak)

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
@limiter.limit(REVEAL_LIMIT, key_func=user_or_ip_key)
@login_required
@require_grant("media.winamp")
def play(file_id: int):
    """Buka audio di Winamp; pemutaran HTML5 memakai rute stream."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=? "
            "AND deleted_at IS NULL AND file_type IN ('audio','video')",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    ditolak = akses_item(row, file_id)
    if ditolak:
        return _respons_terkunci(*ditolak)

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
@limiter.limit(REVEAL_LIMIT, key_func=user_or_ip_key)
@login_required
@require_grant("file.download")
def download(file_id: int):
    """Unduh media terenkripsi sebagai lampiran setelah autentikasi ulang."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=? "
            "AND deleted_at IS NULL AND file_type IN ('audio','video')",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    ditolak = akses_item(row, file_id)
    if ditolak:
        return _respons_terkunci(*ditolak)

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


# ── Pratinjau dokumen (UB) ────────────────────────────────────────────────────

MAX_TEXT_BYTES = 1_000_000


def _deteksi_jenis(data: bytes):
    if data.startswith(b"%PDF-"):
        return ("pdf", "application/pdf")
    if data.startswith(bytes.fromhex("89504e470d0a1a0a")):
        return ("image", "image/png")
    if data.startswith(bytes.fromhex("ffd8ff")):
        return ("image", "image/jpeg")
    if data.startswith((b"GIF87a", b"GIF89a")):
        return ("image", "image/gif")
    if data.startswith(b"BM"):
        return ("image", "image/bmp")
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ("image", "image/webp")
    try:
        teks = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(ch) < 32 and ch not in "\t\n\r\f\b" for ch in teks):
        return None
    return ("text", "text/plain; charset=utf-8")


@media_bp.route("/media-vault/preview/<int:file_id>")
@login_required
@require_grant("doc.preview")
def preview(file_id: int):
    """
    Pratinjau dokumen dalam memori: PDF dan gambar disajikan inline,
    teks dikirim sebagai JSON, jenis lain ditolak 415.

    Dekripsi terjadi hanya di memori dan hash plaintext diverifikasi
    seperti rute view. Untuk item terkunci, grant ``doc.preview`` berlaku
    sebagai pengganti ``item.view`` karena keduanya adalah verifikasi
    ulang per item; kunci koleksi tetap memerlukan ``album.unlock``.
    """
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=? "
            "AND deleted_at IS NULL",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    ditolak = akses_item(row, file_id, scope_item="doc.preview")
    if ditolak:
        return _respons_terkunci(*ditolak)

    try:
        path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        plaintext = decrypt_all(
            path, _file_key(), file_aad(row["user_id"], row["stored_name"])
        )
        if hashlib.sha256(plaintext).hexdigest() != row["sha256_hash"]:
            raise ValueError("SHA-256 plaintext tidak cocok dengan nilai tercatat.")
        original_name = decrypt_field(
            row["original_name"], _db_key(),
            field_aad(row["user_id"], "vault_files", "original_name"),
        )
    except OSError:
        abort(404)
    except Exception:
        add_block(session["user_id"], "TAMPER_DETECTED", f"file:{file_id}",
                  row["sha256_ciphertext"])
        abort(403)

    jenis = _deteksi_jenis(plaintext)
    if jenis is None:
        return jsonify({
            "success": False,
            "error": MSG.DOC_PREVIEW_UNSUPPORTED,
            "reason": "jenis",
        }), 415
    kategori, mime = jenis

    if kategori == "text":
        return jsonify({
            "success": True,
            "name": original_name,
            "kind": "text",
            "size": len(plaintext),
            "truncated": len(plaintext) > MAX_TEXT_BYTES,
            "text": plaintext.decode("utf-8", errors="replace")[:MAX_TEXT_BYTES],
        })

    response = Response(plaintext, status=200, mimetype=mime)
    response.headers["Content-Disposition"] = "inline"
    response.headers["Content-Length"] = str(len(plaintext))
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    if kategori == "pdf":
        # Hanya rute ini yang boleh di-frame sendiri (penampil PDF modal).
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
    return response
