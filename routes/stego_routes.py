"""
routes/stego_routes.py
───────────────────────
Steganography: embed and extract LSB messages in PNG images.
"""

import os
import uuid
import hashlib
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, send_file, abort
)
from werkzeug.utils import secure_filename

import config
from modules.strings import MSG
from routes.auth_routes import login_required
from database.db import get_db
from modules.steganography.lsb import embed_message, extract_message
from modules.cryptography.key_management import master_key_from_hex, get_stego_key
from modules.blockchain.blockchain import add_block

stego_bp = Blueprint("stego", __name__)


@stego_bp.route("/steganography")
@login_required
def index():
    with get_db() as db:
        images = db.execute(
            "SELECT * FROM stego_images WHERE user_id=? ORDER BY created_at DESC",
            (session["user_id"],),
        ).fetchall()
    return render_template("steganography.html", images=images)


@stego_bp.route("/steganography/embed", methods=["POST"])
@login_required
def embed():
    carrier = request.files.get("carrier_image")
    message = request.form.get("message", "").strip()
    use_enc = request.form.get("use_encryption") == "1"

    if not carrier or not carrier.filename:
        flash(MSG.STEGO_NO_CARRIER, "warning")
        return redirect(url_for("stego.index"))
    if not message:
        flash(MSG.STEGO_EMPTY_MESSAGE, "warning")
        return redirect(url_for("stego.index"))

    fname = secure_filename(carrier.filename)
    ext   = os.path.splitext(fname)[1].lower()
    if ext not in {".png", ".jpg", ".jpeg", ".bmp"}:
        flash(MSG.STEGO_INVALID_CARRIER, "danger")
        return redirect(url_for("stego.index"))

    tmp_in = os.path.join(config.TEMPORARY_FILES_DIR, f"stego_in_{uuid.uuid4().hex}{ext}")
    os.makedirs(config.TEMPORARY_FILES_DIR, exist_ok=True)
    carrier.save(tmp_in)

    stored_name = f"{uuid.uuid4().hex}.png"
    out_path    = os.path.join(config.STEGO_IMAGES_DIR, stored_name)
    os.makedirs(config.STEGO_IMAGES_DIR, exist_ok=True)

    mk     = master_key_from_hex(session["master_key_hex"])
    mk_arg = mk if use_enc else None

    result = embed_message(tmp_in, message, out_path, master_key=mk_arg)
    os.remove(tmp_in)

    if not result["success"]:
        flash(MSG.STEGO_EMBED_FAILED.format(error=result.get('error')), "danger")
        return redirect(url_for("stego.index"))

    with get_db() as db:
        db.execute(
            "INSERT INTO stego_images (user_id, original_name, stored_name, has_encryption) VALUES (?,?,?,?)",
            (session["user_id"], fname, stored_name, int(use_enc)),
        )
        db.commit()

    add_block(session["user_id"], "UPLOAD", hashlib.sha256(message.encode()).hexdigest())
    flash(MSG.STEGO_EMBED_SUCCESS, "success")
    return redirect(url_for("stego.index"))


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

    mk     = master_key_from_hex(session["master_key_hex"])
    mk_arg = mk if row["has_encryption"] else None

    result = extract_message(img_path, master_key=mk_arg)
    if not result["success"]:
        flash(MSG.STEGO_EXTRACT_FAILED.format(error=result.get('error')), "danger")
    else:
        flash(MSG.STEGO_EXTRACT_SUCCESS.format(message=result['message']), "success")

    return redirect(url_for("stego.index"))


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
    return send_file(img_path, download_name=row["original_name"], as_attachment=True)


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
