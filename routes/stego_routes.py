"""
routes/stego_routes.py
───────────────────────
Steganography: menyisipkan dan mengekstrak muatan LSB pada PNG.
"""

import hashlib
import io
import mimetypes
import os
import uuid

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, send_file, abort, jsonify
)
from werkzeug.utils import secure_filename

import config
from modules.strings import MSG
from routes.auth_routes import login_required
from database.db import get_db
from modules.steganography.lsb import (
    embed_file, embed_message, extract_payload, image_capacity,
)
from modules.cryptography import session_keys
from modules.cryptography.key_management import purpose_key
from modules.cryptography.database_encryption import decrypt_field, encrypt_field, field_aad
from modules.blockchain.blockchain import add_block

stego_bp = Blueprint("stego", __name__)


def _dek() -> bytes:
    """DEK sesi; 403 bila kunci sudah hilang (timeout, logout, restart)."""
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        abort(403)
    return dek


def _db_key() -> bytes:
    """Kunci field = purpose_key(DEK sesi, "database")."""
    return purpose_key(_dek(), "database")


def _name_aad(user_id) -> bytes:
    return field_aad(user_id, "stego_images", "original_name")


def _display_name(row, db_key: bytes) -> str:
    """Buka nama asli gambar untuk daftar; token gagal ditandai aman."""
    try:
        return decrypt_field(row["original_name"], db_key, _name_aad(row["user_id"]))
    except ValueError:
        return "[Nama tidak terbaca]"


def _png_download_name(nama_asli: str) -> str:
    """Nama unduhan selalu berekstensi .png agar muatan tidak rusak."""
    stem = os.path.splitext(os.path.basename(nama_asli))[0] or "stego"
    return f"{stem}.png"


def _hash_gambar(path: str) -> str:
    """SHA-256 berkas PNG hasil sisip (bukan isi pesan) untuk blok rantai."""
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


@stego_bp.route("/steganography")
@login_required
def index():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM stego_images WHERE user_id=? ORDER BY created_at DESC",
            (session["user_id"],),
        ).fetchall()

    db_key = _db_key()
    images = []
    for r in rows:
        row = dict(r)
        row["original_name"] = _display_name(r, db_key)
        images.append(row)
    return render_template("steganography.html", images=images)


@stego_bp.route("/steganography/capacity", methods=["POST"])
@login_required
def capacity():
    """Kapasitas gambar pembawa sebelum muatan disisipkan."""
    carrier = request.files.get("carrier_image")
    if not carrier or not carrier.filename:
        return jsonify({"error": MSG.STEGO_NO_CARRIER}), 400

    fname = secure_filename(carrier.filename)
    ext = os.path.splitext(fname)[1].lower()
    if ext not in {".png", ".jpg", ".jpeg", ".bmp"}:
        return jsonify({"error": MSG.STEGO_INVALID_CARRIER}), 400

    os.makedirs(config.TEMPORARY_FILES_DIR, exist_ok=True)
    tmp_path = os.path.join(
        config.TEMPORARY_FILES_DIR, f"stego_cap_{uuid.uuid4().hex}{ext}"
    )
    carrier.save(tmp_path)
    try:
        info = image_capacity(tmp_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    if "error" in info:
        return jsonify(info), 400
    return jsonify(info)


@stego_bp.route("/steganography/embed", methods=["POST"])
@login_required
def embed():
    carrier = request.files.get("carrier_image")
    payload_type = request.form.get("payload_type", "text")
    message = request.form.get("message", "").strip()
    payload_file = request.files.get("payload_file")
    # Enkripsi aktif secara default; kotak centang dikirim value "0" bila
    # dicabut pengguna.
    use_enc = request.form.get("use_encryption", "1") == "1"
    key_mode = request.form.get("key_mode", "account")
    if key_mode not in {"account", "passphrase"}:
        key_mode = "account"
    passphrase = request.form.get("passphrase", "").strip()
    if key_mode == "passphrase" and not passphrase:
        flash(MSG.STEGO_PASSPHRASE_REQUIRED, "warning")
        return redirect(url_for("stego.index"))
    if key_mode != "passphrase":
        # Passphrase tidak pernah disimpan di sesi/cookie/log.
        passphrase = None

    if not carrier or not carrier.filename:
        flash(MSG.STEGO_NO_CARRIER, "warning")
        return redirect(url_for("stego.index"))
    if payload_type == "file" and (not payload_file or not payload_file.filename):
        flash(MSG.STEGO_NO_PAYLOAD_FILE, "warning")
        return redirect(url_for("stego.index"))
    if payload_type == "text" and not message:
        flash(MSG.STEGO_EMPTY_MESSAGE, "warning")
        return redirect(url_for("stego.index"))

    fname = secure_filename(carrier.filename)
    ext = os.path.splitext(fname)[1].lower()
    if ext not in {".png", ".jpg", ".jpeg", ".bmp"}:
        flash(MSG.STEGO_INVALID_CARRIER, "danger")
        return redirect(url_for("stego.index"))

    os.makedirs(config.TEMPORARY_FILES_DIR, exist_ok=True)
    tmp_in = os.path.join(config.TEMPORARY_FILES_DIR, f"stego_in_{uuid.uuid4().hex}{ext}")
    carrier.save(tmp_in)

    stored_name = f"{uuid.uuid4().hex}.png"
    out_path = os.path.join(config.STEGO_IMAGES_DIR, stored_name)
    os.makedirs(config.STEGO_IMAGES_DIR, exist_ok=True)

    mk = _dek()
    stego_master = mk if key_mode == "account" else None
    tmp_payload = None
    try:
        if payload_type == "file":
            payload_name = secure_filename(payload_file.filename)
            tmp_payload = os.path.join(
                config.TEMPORARY_FILES_DIR, f"stego_pl_{uuid.uuid4().hex}"
            )
            payload_file.save(tmp_payload)
            result = embed_file(
                tmp_in, tmp_payload, out_path,
                master_key=stego_master, passphrase=passphrase,
                filename=payload_name,
            )
            has_encryption = 1
        else:
            result = embed_message(
                tmp_in, message, out_path,
                master_key=stego_master, passphrase=passphrase,
                encrypt=use_enc,
            )
            has_encryption = int(use_enc)
    finally:
        if os.path.exists(tmp_in):
            os.remove(tmp_in)
        if tmp_payload and os.path.exists(tmp_payload):
            os.remove(tmp_payload)

    if not result["success"]:
        flash(MSG.STEGO_EMBED_FAILED.format(error=result.get('error')), "danger")
        return redirect(url_for("stego.index"))

    with get_db() as db:
        cursor = db.execute(
            """INSERT INTO stego_images
               (user_id, original_name, stored_name, has_encryption)
               VALUES (?,?,?,?)""",
            (
                session["user_id"],
                encrypt_field(fname, _db_key(), _name_aad(session["user_id"])),
                stored_name,
                has_encryption,
            ),
        )
        img_id = cursor.lastrowid
        db.commit()

    add_block(session["user_id"], "STEGO_EMBED", f"stego:{img_id}",
              _hash_gambar(out_path))
    flash(MSG.STEGO_EMBED_SUCCESS, "success")
    flash(MSG.STEGO_PNG_WARNING, "info")
    return redirect(url_for("stego.index"))


def _hasil_ekstraksi(result: dict):
    """
    Sajikan hasil ekstrak.

    Teks dikirim sebagai JSON agar ditampilkan di dalam halaman, bukan flash.
    Berkas disajikan langsung dari memori sehingga plaintext tidak ditulis ke
    disk.
    """
    if not result["success"]:
        pesan = result.get("error") or MSG.STEGO_DECRYPT_FAILED
        return jsonify({
            "success": False,
            "error": pesan,
            "message": MSG.STEGO_EXTRACT_FAILED.format(error=pesan),
        }), 400
    if result["type"] == "file":
        mime = (
            mimetypes.guess_type(result["filename"])[0]
            or "application/octet-stream"
        )
        response = send_file(
            io.BytesIO(result["data"]),
            download_name=result["filename"],
            as_attachment=True,
            mimetype=mime,
        )
        response.headers["X-Cryptix-Extract"] = "file"
        return response
    response = jsonify({
        "success": True,
        "type": "text",
        "text": result["text"],
        "encrypted": bool(result.get("encrypted", False)),
        "message": MSG.STEGO_EXTRACT_TEXT_SUCCESS,
    })
    response.headers["X-Cryptix-Extract"] = "text"
    return response


@stego_bp.route("/steganography/extract/<int:img_id>", methods=["POST"])
@login_required
def extract(img_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM stego_images WHERE id=? AND user_id=?",
            (img_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    img_path = os.path.join(config.STEGO_IMAGES_DIR, row["stored_name"])
    mk = _dek()
    passphrase = request.form.get("passphrase", "").strip()
    result = extract_payload(
        img_path, master_key=mk, passphrase=passphrase or None
    )

    if result["success"]:
        add_block(session["user_id"], "STEGO_EXTRACT", f"stego:{img_id}",
                  _hash_gambar(img_path))
    return _hasil_ekstraksi(result)


@stego_bp.route("/steganography/extract-upload", methods=["POST"])
@login_required
def extract_upload():
    """Ekstrak muatan dari gambar yang diunggah; passphrase opsional."""
    carrier = request.files.get("stego_image")
    if not carrier or not carrier.filename:
        flash(MSG.STEGO_NO_CARRIER, "warning")
        return redirect(url_for("stego.index"))

    fname = secure_filename(carrier.filename)
    ext = os.path.splitext(fname)[1].lower()
    if ext not in {".png", ".jpg", ".jpeg", ".bmp"}:
        flash(MSG.STEGO_INVALID_CARRIER, "danger")
        return redirect(url_for("stego.index"))

    passphrase = request.form.get("passphrase", "").strip()
    mk = _dek()

    os.makedirs(config.TEMPORARY_FILES_DIR, exist_ok=True)
    tmp_path = os.path.join(
        config.TEMPORARY_FILES_DIR, f"stego_up_{uuid.uuid4().hex}{ext}"
    )
    carrier.save(tmp_path)
    try:
        result = extract_payload(
            tmp_path,
            master_key=mk,
            passphrase=passphrase or None,
        )
        hash_gambar = _hash_gambar(tmp_path)
    except Exception:
        result = {"success": False, "error": MSG.STEGO_INVALID_CARRIER}
        hash_gambar = "0" * 64
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    if result["success"]:
        add_block(session["user_id"], "STEGO_EXTRACT", "stego:unggahan",
                  hash_gambar)
    return _hasil_ekstraksi(result)


@stego_bp.route("/steganography/download/<int:img_id>")
@login_required
def download(img_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM stego_images WHERE id=? AND user_id=?",
            (img_id, session["user_id"]),
        ).fetchone()

    if not row:
        abort(404)

    img_path = os.path.join(config.STEGO_IMAGES_DIR, row["stored_name"])
    # Nama unduhan selalu .png agar muatan tidak rusak oleh konversi JPEG.
    return send_file(
        img_path,
        download_name=_png_download_name(_display_name(row, _db_key())),
        as_attachment=True,
    )


@stego_bp.route("/steganography/delete/<int:img_id>", methods=["POST"])
@login_required
def delete(img_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM stego_images WHERE id=? AND user_id=?",
            (img_id, session["user_id"]),
        ).fetchone()
        if not row:
            abort(404)
        img_path = os.path.join(config.STEGO_IMAGES_DIR, row["stored_name"])
        if os.path.exists(img_path):
            os.remove(img_path)
        db.execute("DELETE FROM stego_images WHERE id=?", (img_id,))
        db.commit()

    flash(MSG.STEGO_DELETED, "info")
    return redirect(url_for("stego.index"))
