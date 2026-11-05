"""
routes/settings_routes.py  (referenced as settings in requirements)
────────────────────────────
User settings: profile, change password, USB token, biometrics.
"""

import os
import sys
import hashlib
from flask import Blueprint, render_template, request, redirect, url_for, session, flash

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from routes.auth_routes import login_required
from database.db import get_db
from modules.authentication.auth import get_user_by_id, update_usb_token
from modules.authentication.password_hash import hash_password, verify_password
from modules.authentication import usb_authentication as usb_mod

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
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("settings.index"))

    if new_pwd != confirm:
        flash("New passwords do not match.", "danger")
        return redirect(url_for("settings.index"))

    new_hash, new_salt = hash_password(new_pwd)
    db = get_db()
    try:
        db.execute(
            "UPDATE users SET password_hash=?, salt=? WHERE id=?",
            (new_hash, new_salt, session["user_id"]),
        )
        db.commit()
    finally:
        db.close()

    # Force re-login so master key is re-derived with new salt
    session.clear()
    flash("Password changed. Please log in again.", "success")
    return redirect(url_for("auth.login"))


@settings_bp.route("/settings/register-usb", methods=["POST"])
@login_required
def register_usb():
    from flask import current_app
    result = usb_mod.register_usb_token(current_app.config["SECRET_KEY"])
    if result is None:
        flash("No removable drive detected.", "danger")
    else:
        update_usb_token(session["user_id"], result["hmac_hex"], result["volume_serial"])
        flash("USB token registered successfully.", "success")
    return redirect(url_for("settings.index"))
