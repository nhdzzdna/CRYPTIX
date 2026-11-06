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
from modules.authentication.auth import get_user_by_id, update_usb_token
from modules.authentication.password_hash import hash_password, verify_password
from modules.authentication import usb_authentication as usb_mod
from modules.blockchain.blockchain import add_block, content_hash

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings")
@login_required
def index():
    user = get_user_by_id(session["user_id"])
    return render_template("settings.html", user=user)


@settings_bp.route("/settings/change-password", methods=["POST"])
@login_required
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

    new_hash, new_salt = hash_password(new_pwd)
    with get_db() as db:
        db.execute(
            "UPDATE users SET password_hash=?, salt=? WHERE id=?",
            (new_hash, new_salt, session["user_id"]),
        )
        db.commit()

    add_block(session["user_id"], "PASSWORD_CHANGE", "auth:password",
              content_hash(str(session["user_id"]).encode("utf-8")))

    # Force re-login so master key is re-derived with new salt
    session.clear()
    flash(MSG.SETTINGS_PASSWORD_CHANGED, "success")
    return redirect(url_for("auth.login"))


@settings_bp.route("/settings/register-usb", methods=["POST"])
@login_required
def register_usb():
    from flask import current_app
    result = usb_mod.register_usb_token(current_app.config["SECRET_KEY"])
    if result is None:
        flash(MSG.SETTINGS_USB_NO_DRIVE, "danger")
    else:
        update_usb_token(session["user_id"], result["hmac_hex"], result["volume_serial"])
        add_block(session["user_id"], "DONGLE_REGISTER", "auth:usb",
                  content_hash(str(session["user_id"]).encode("utf-8")))
        flash(MSG.SETTINGS_USB_REGISTERED, "success")
    return redirect(url_for("settings.index"))
