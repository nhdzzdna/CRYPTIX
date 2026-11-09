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
    session, flash, abort, Response, send_file, jsonify
)
from PIL import Image

import config
from modules.strings import MSG
from modules.authentication.reauth import (
    require_grant, consume_grant, find_active_grant,
)
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
            "SELECT * FROM vault_files WHERE user_id=? "
            "AND file_type IN ('image','audio','video') ORDER BY uploaded_at DESC",
            (session["user_id"],),
        ).fetchall()
        koleksi_rows = db.execute(
            "SELECT * FROM collections WHERE user_id=? ORDER BY created_at, id",
            (session["user_id"],),
        ).fetchall()
        item_rows = db.execute(
            """SELECT ci.file_id, ci.collection_id, ci.state, c.locked
               FROM collection_items ci
               JOIN collections c ON c.id = ci.collection_id
               WHERE c.user_id=? ORDER BY ci.added_at""",
            (session["user_id"],),
        ).fetchall()

    db_key = _db_key()
    info = {r["id"]: _media_info(r, db_key) for r in rows}
    item_map = {r["file_id"]: r for r in item_rows}

    albums = []
    album_by_id = {}
    for k in koleksi_rows:
        nama = _collection_name(k, db_key)
        album = {
            "id": k["id"], "name": nama, "kind": k["kind"],
            "locked": bool(k["locked"]), "cover": None,
            "jumlah": 0,
        }
        album_by_id[k["id"]] = album
        albums.append(album)

    for fid, item in item_map.items():
        album = album_by_id.get(item["collection_id"])
        if album is None:
            continue
        if item["state"] == "hidden":
            continue
        album["jumlah"] += 1
        berkas = info.get(fid)
        if (album["cover"] is None and berkas is not None
                and berkas["file_type"] == "image"):
            album["cover"] = berkas["thumb_url"]

    unfiled = [
        info[fid] for fid in info
        if fid not in item_map
    ]

    audio_files = []
    for fid, berkas in info.items():
        if berkas["file_type"] != "audio":
            continue
        item = item_map.get(fid)
        if item is not None:
            if item["state"] != "normal" or item["locked"]:
                continue
        audio_files.append(dict(
            berkas,
            collection_id=(item["collection_id"] if item is not None else None),
        ))

    return render_template(
        "media_vault.html",
        files=audio_files,
        albums=albums,
        unfiled=unfiled,
        winamp_available=is_winamp_available(),
        download_only_note=MSG.MEDIA_DOWNLOAD_ONLY,
        temp_warning=MSG.MEDIA_TEMP_WARNING,
        hidden_note=MSG.COLLECTION_LOCKED_NOTE,
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
    nama = _display_name(row, db_key)
    ext = _extension(nama)
    jenis = row["file_type"]
    if jenis == "image":
        ikon = "📷"
    elif jenis == "video":
        ikon = "🎬"
    else:
        ikon = "🎵"
    return {
        "id": row["id"],
        "original_name": nama,
        "file_type": jenis,
        "extension": ext,
        "icon": ikon,
        "view_url": url_for("media.view", file_id=row["id"]),
        "thumb_url": (url_for("media.thumb", file_id=row["id"])
                      if jenis == "image" else None),
        "stream_url": url_for("media.stream", file_id=row["id"]),
        "playable": ext in PLAYABLE_EXTENSIONS,
        "download_only": ext in DOWNLOAD_ONLY_EXTENSIONS,
        "file_size": row["file_size"],
        "uploaded_at": row["uploaded_at"],
    }


def _item_context(file_id: int, user_id: int):
    """Baris koleksi untuk sebuah berkas, atau None bila Tanpa album."""
    with get_db() as db:
        return db.execute(
            """SELECT ci.state AS state, ci.collection_id AS collection_id,
                      c.locked AS collection_locked
               FROM collection_items ci
               JOIN collections c ON c.id = ci.collection_id
               WHERE ci.file_id=? AND c.user_id=?""",
            (file_id, user_id),
        ).fetchone()


def _grant_sah(scope: str, resource_id) -> bool:
    """Periksa grant lewat header atau grant aktif berulang."""
    session_id = session.get("session_id", "")
    token = request.headers.get("X-Reauth-Grant") or ""
    if not token:
        token = find_active_grant(session_id, scope, resource_id) or ""
    sah, _ = consume_grant(token, session_id, scope, resource_id)
    return sah


def _akses_item(row, file_id: int):
    """
    Periksa aturan akses pratinjau berdasarkan state dan kunci koleksi.

    Returns None bila boleh, atau (pesan, status) untuk penolakan.
    """
    item = _item_context(file_id, row["user_id"])
    if item is None:
        return None
    state = item["state"]
    if state == "locked":
        if not _grant_sah("media.stream", file_id):
            return MSG.REAUTH_REQUIRED, 401
        return None
    if state == "hidden" or item["collection_locked"]:
        if not _grant_sah("album.unlock", item["collection_id"]):
            return MSG.REAUTH_REQUIRED, 403
    return None


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
            "SELECT * FROM vault_files WHERE id=? AND user_id=?",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    ditolak = _akses_item(row, file_id)
    if ditolak:
        pesan, status = ditolak
        return jsonify({"success": False, "error": pesan,
                        "reason": "grant"}), status

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
            "SELECT * FROM vault_files WHERE id=? AND user_id=?",
            (file_id, session["user_id"]),
        ).fetchone()

    if not row or row["file_type"] != "image":
        abort(404)

    ditolak = _akses_item(row, file_id)
    if ditolak:
        pesan, status = ditolak
        return jsonify({"success": False, "error": pesan,
                        "reason": "grant"}), status

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
@limiter.limit(REVEAL_LIMIT, key_func=user_or_ip_key)
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
@limiter.limit(REVEAL_LIMIT, key_func=user_or_ip_key)
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
