"""
routes/auth_routes.py
──────────────────────
Login, logout, register, and biometric setup routes.
"""

import os
import tempfile
import base64

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, current_app, jsonify
)
from werkzeug.utils import secure_filename

import config
from modules.strings import MSG
from modules.authentication.auth import (
    register_user, authenticate_user, get_user_by_id,
    update_usb_token, update_face_model_path, update_fingerprint_path,
)
from modules.authentication import face_recognition as face_mod
from modules.authentication import fingerprint as fp_mod
from modules.authentication import usb_authentication as usb_mod
from modules.cryptography.key_management import derive_master_key, master_key_to_hex
from modules.blockchain.blockchain import add_block
import hashlib

auth_bp = Blueprint("auth", __name__)


def login_required(f):
    """Decorator: redirect to login if not authenticated."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash(MSG.LOGIN_REQUIRED, "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


# ── Register ──────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash(MSG.REGISTER_FIELDS_REQUIRED, "danger")
            return render_template("register.html")

        if password != confirm:
            flash(MSG.REGISTER_PASSWORD_MISMATCH, "danger")
            return render_template("register.html")

        result = register_user(username, email, password)
        if not result["success"]:
            flash(MSG.REGISTER_FAILED.format(error=result['error']), "danger")
            return render_template("register.html")

        user_id = result["user_id"]

        # ── Fingerprint upload (optional) ─────────────────────────────────
        fp_file = request.files.get("fingerprint_image")
        if fp_file and fp_file.filename:
            fname = secure_filename(fp_file.filename)
            ext = os.path.splitext(fname)[1].lower()
            if ext not in {".png", ".jpg", ".jpeg", ".bmp"}:
                flash(MSG.FINGERPRINT_INVALID_FORMAT, "warning")
            else:
                tmp_path = os.path.join(config.TEMPORARY_FILES_DIR, f"fp_reg_{user_id}{ext}")
                os.makedirs(config.TEMPORARY_FILES_DIR, exist_ok=True)
                fp_file.save(tmp_path)
                if fp_mod.register_fingerprint(user_id, tmp_path):
                    update_fingerprint_path(user_id, fp_mod._fp_path(user_id))
                    flash(MSG.FINGERPRINT_REGISTERED, "success")
                os.remove(tmp_path)

        add_block(user_id, "REGISTER",
                  hashlib.sha256(username.encode()).hexdigest())
        flash(MSG.REGISTER_SUCCESS, "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # ── Optional fingerprint probe ────────────────────────────────────
        fp_path = None
        fp_file = request.files.get("fingerprint_image")
        if fp_file and fp_file.filename:
            fname = secure_filename(fp_file.filename)
            ext = os.path.splitext(fname)[1].lower()
            tmp_dir = config.TEMPORARY_FILES_DIR
            os.makedirs(tmp_dir, exist_ok=True)
            fp_path = os.path.join(tmp_dir, f"fp_login_{fname}")
            fp_file.save(fp_path)

        result = authenticate_user(
            username, password,
            secret_key=current_app.config["SECRET_KEY"],
            fingerprint_path=fp_path,
        )

        # Clean up temp fingerprint
        if fp_path and os.path.exists(fp_path):
            os.remove(fp_path)

        if not result["success"]:
            flash(MSG.LOGIN_FAILED.format(error=result["error"]), "danger")
            return render_template("login.html")

        user = result["user"]
        session["user_id"]   = user["id"]
        session["username"]  = user["username"]
        # Derive and store master key in session (hex-encoded)
        mk = derive_master_key(password, user["salt"])
        session["master_key_hex"] = master_key_to_hex(mk)

        add_block(user["id"], "LOGIN",
                  hashlib.sha256(username.encode()).hexdigest())
        flash(MSG.LOGIN_SUCCESS.format(username=user['username']), "success")
        return redirect(url_for("dashboard.index"))

    return render_template("login.html")


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
def logout():
    session.clear()
    flash(MSG.LOGOUT_SUCCESS, "info")
    return redirect(url_for("auth.login"))


# ── Face registration (AJAX endpoint) ────────────────────────────────────────

@auth_bp.route("/api/register_face", methods=["POST"])
@login_required
def register_face():
    """
    Receives a JSON list of base64-encoded JPEG frames from the webcam
    and trains the LBPH model.
    """
    import cv2
    import numpy as np

    data = request.get_json()
    if not data or "frames" not in data:
        return jsonify({"success": False, "error": MSG.FACE_NO_FRAMES})

    frames = []
    for b64 in data["frames"]:
        try:
            img_bytes = base64.b64decode(b64.split(",")[-1])
            arr = np.frombuffer(img_bytes, dtype=np.uint8)
            frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if frame is not None:
                frames.append(frame)
        except Exception:
            continue

    user_id = session["user_id"]
    ok = face_mod.register_face_from_frames(user_id, frames)
    if ok:
        update_face_model_path(user_id, face_mod._model_path(user_id))
        return jsonify({"success": True, "message": MSG.FACE_MODEL_SAVED})
    return jsonify({"success": False, "error": MSG.FACE_NOT_ENOUGH_SAMPLES})


# ── Face verification (AJAX endpoint) ────────────────────────────────────────

@auth_bp.route("/api/verify_face", methods=["POST"])
def verify_face():
    """Verify a single base64 webcam frame during login."""
    import cv2
    import numpy as np

    data = request.get_json()
    username = data.get("username", "")
    b64 = data.get("frame", "")

    from database.db import get_db as _get_db
    with _get_db() as db:
        row = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({"verified": False})

    try:
        img_bytes = base64.b64decode(b64.split(",")[-1])
        arr = np.frombuffer(img_bytes, dtype=np.uint8)
        frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    except Exception:
        return jsonify({"verified": False})

    verified = face_mod.verify_face_from_frame(row["id"], frame)
    return jsonify({"verified": verified})


# ── USB Token registration ────────────────────────────────────────────────────

@auth_bp.route("/api/register_usb", methods=["POST"])
@login_required
def register_usb():
    result = usb_mod.register_usb_token(current_app.config["SECRET_KEY"])
    if result is None:
        return jsonify({"success": False, "error": MSG.USB_NO_DRIVE})
    update_usb_token(session["user_id"], result["hmac_hex"], result["volume_serial"])
    return jsonify({"success": True, "message": MSG.USB_REGISTERED})
