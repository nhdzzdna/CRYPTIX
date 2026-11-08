"""
routes/settings_routes.py  (referenced as settings in requirements)
────────────────────────────
User settings: profile, change password, USB token, biometrics.
"""

import os
import hashlib
from flask import Blueprint, render_template, request, redirect, url_for, session, flash

from modules.strings import MSG
from routes.auth_routes import login_required
from database.db import get_db
from modules.authentication.auth import (
    get_user_by_id, store_usb_token, validate_password,
)
from modules.authentication.password_hash import hash_password, verify_password
from modules.authentication import usb_authentication as usb_mod
from modules.authentication import webauthn
from modules.authentication import face_recognition as face_mod
from modules.authentication.reauth import require_grant
from modules.cryptography import session_keys
from modules.cryptography.key_management import rewrap_dek
from modules.blockchain.blockchain import add_block, content_hash

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings")
@login_required
def index():
    user = get_user_by_id(session["user_id"])
    return render_template(
        "settings.html",
        user=user,
        webauthn_terdaftar=webauthn.ada_kredensial(user["id"]),
        wajah_terdaftar=face_mod.template_ada(user["id"]),
    )


@settings_bp.route("/settings/change-password", methods=["POST"])
@login_required
@require_grant("settings.change")
def change_password():
    current  = request.form.get("current_password", "")
    new_pwd  = request.form.get("new_password",     "")
    confirm  = request.form.get("confirm_password", "")

    user = get_user_by_id(session["user_id"])
    if not verify_password(current, user["password_hash"], user["salt"]):
        flash(MSG.SETTINGS_WRONG_PASSWORD, "danger")
        return redirect(url_for("settings.index"))

    if new_pwd != confirm:
        flash(MSG.SETTINGS_PASSWORD_MISMATCH, "danger")
        return redirect(url_for("settings.index"))

    galat = validate_password(new_pwd, user["username"])
    if galat:
        flash(galat, "danger")
        return redirect(url_for("settings.index"))

    if new_pwd == current:
        flash(MSG.SETTINGS_PASSWORD_SAME, "danger")
        return redirect(url_for("settings.index"))

    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        flash(MSG.SESSION_EXPIRED, "warning")
        return redirect(url_for("auth.login"))

    sah, rahasia = usb_mod.verify_usb_token(
        user["usb_verifier"], user["usb_volume_serial"], user["usb_token_id"]
    )
    if not sah or rahasia is None:
        flash(MSG.SETTINGS_USB_MISSING, "danger")
        return redirect(url_for("settings.index"))

    try:
        bundle = rewrap_dek(dek, new_pwd, rahasia, user["id"])
    except (TypeError, ValueError):
        flash(MSG.SETTINGS_PASSWORD_REWRAP_FAILED, "danger")
        return redirect(url_for("settings.index"))

    new_hash, new_salt = hash_password(new_pwd)
    with get_db() as db:
        db.execute(
            "UPDATE users SET password_hash=?, salt=?, kek_salt=?, "
            "wrapped_dek=?, failed_attempts=0, locked_until=NULL WHERE id=?",
            (new_hash, new_salt, bundle["kek_salt"], bundle["wrapped_dek"],
             session["user_id"]),
        )
        db.commit()
    del dek, rahasia, new_pwd, current

    add_block(session["user_id"], "PASSWORD_CHANGE", "auth:password",
              content_hash(str(session["user_id"]).encode("utf-8")))

    # Wajib masuk ulang: kunci utama diturunkan lagi dari kata sandi baru.
    session_keys.drop(session.get("session_id", ""))
    session.clear()
    flash(MSG.SETTINGS_PASSWORD_CHANGED, "success")
    return redirect(url_for("auth.login"))


@settings_bp.route("/settings/register-usb", methods=["POST"])
@login_required
def register_usb():
    mountpoint = request.form.get("mountpoint", "").strip()
    if not mountpoint:
        drives = usb_mod.daftar_drive()
        mountpoint = drives[0]["mountpoint"] if drives else ""
    result = usb_mod.register_usb_token(mountpoint)
    if result is None:
        flash(MSG.SETTINGS_USB_NO_DRIVE, "danger")
    else:
        store_usb_token(
            session["user_id"],
            result["token_id"],
            result["verifier"],
            result["volume_serial"],
        )
        usb_mod.lupakan_cache(session["user_id"])
        add_block(session["user_id"], "DONGLE_REGISTER", "auth:usb",
                  content_hash(str(session["user_id"]).encode("utf-8")))
        flash(MSG.SETTINGS_USB_REGISTERED, "success")
    return redirect(url_for("settings.index"))
