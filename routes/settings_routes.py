"""
routes/settings_routes.py  (referenced as settings in requirements)
────────────────────────────
User settings: profil, ganti kata sandi, dongle, biometrik, kunci pemulihan,
dan batas sesi.

Semua tindakan yang mengubah faktor keamanan memerlukan autentikasi ulang:
  • ``settings.change``  — ganti kata sandi, daftar ulang dongle, kunci
    pemulihan baru, batas sesi.
  • ``biometric.manage`` — tambah/hapus kredensial WebAuthn dan daftar ulang
    wajah (lewat endpoint API dengan ``when`` sesi login).
"""

import config
from flask import Blueprint, render_template, request, redirect, url_for, session, flash

from modules.strings import MSG
from routes.auth_routes import login_required, _respon_tanpa_simpan
from database.db import get_db
from modules.authentication.auth import (
    get_user_by_id, reregister_usb_token, validate_password,
)
from modules.authentication.password_hash import hash_password, verify_password
from modules.authentication import usb_authentication as usb_mod
from modules.authentication import webauthn
from modules.authentication import face_recognition as face_mod
from modules.authentication.reauth import require_grant
from modules.cryptography import session_keys
from modules.cryptography.key_management import rewrap_dek, rewrap_recovery_key
from modules.blockchain.blockchain import add_block, content_hash

settings_bp = Blueprint("settings", __name__)

# Pilihan batas diam sesi (menit) yang ditampilkan di Settings.
_SESSION_TIMEOUT_PILIHAN = (5, 10, 15, 30, 60, 120)


def _konteks(user: dict, recovery_key_baru: str | None = None) -> dict:
    """Konteks halaman Settings; dipakai juga saat menampilkan kunci pemulihan."""
    waktu = user.get("session_timeout_minutes") or config.SESSION_IDLE_MINUTES
    pilihan = sorted(set(_SESSION_TIMEOUT_PILIHAN) | {int(waktu)})
    kredensial = webauthn.kredensial_pengguna(user["id"])
    return {
        "user": user,
        "kredensial": kredensial,
        "wajah_terdaftar": face_mod.template_ada(user["id"]),
        "webauthn_terdaftar": bool(kredensial),
        "dongle_terpasang": usb_mod.dongle_pengguna_terpasang(user["id"]),
        "drives": usb_mod.daftar_drive(),
        "session_timeout": int(waktu),
        "session_timeout_pilihan": pilihan,
        "recovery_key_baru": recovery_key_baru,
    }


@settings_bp.route("/settings")
@login_required
def index():
    user = get_user_by_id(session["user_id"])
    return render_template("settings.html", **_konteks(user))


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
@require_grant("settings.change")
def register_usb():
    """Daftarkan dongle pengganti lalu bungkus ulang DEK dengan rahasianya."""
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        flash(MSG.SESSION_EXPIRED, "warning")
        return redirect(url_for("auth.login"))

    try:
        hasil = reregister_usb_token(
            session["user_id"],
            dek,
            request.form.get("current_password", ""),
            request.form.get("mountpoint", "").strip(),
        )
    finally:
        del dek

    if not hasil["success"]:
        flash(hasil["error"], "danger")
        return redirect(url_for("settings.index"))

    add_block(session["user_id"], "DONGLE_REGISTER", "auth:usb",
              content_hash(str(session["user_id"]).encode("utf-8")))
    flash(MSG.SETTINGS_USB_REGISTERED, "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/settings/webauthn/delete", methods=["POST"])
@login_required
@require_grant("biometric.manage")
def delete_webauthn():
    """Hapus satu kredensial WebAuthn milik pengguna yang sedang masuk."""
    user_id = session["user_id"]
    credential_id = request.form.get("credential_id", "").strip()

    kredensial = webauthn.kredensial_pengguna(user_id)
    if not any(k["credential_id"] == credential_id for k in kredensial):
        flash(MSG.SETTINGS_BIOMETRIC_NOT_FOUND, "danger")
        return redirect(url_for("settings.index"))

    tersisa = [
        k for k in kredensial
        if k["credential_id"] != credential_id
    ]
    if not tersisa and not face_mod.template_ada(user_id):
        flash(MSG.SETTINGS_BIOMETRIC_LAST, "danger")
        return redirect(url_for("settings.index"))

    if webauthn.hapus_kredensial(user_id, credential_id):
        add_block(user_id, "BIOMETRIC_REMOVE", "auth:webauthn",
                  content_hash(credential_id.encode("utf-8")))
        flash(MSG.SETTINGS_BIOMETRIC_DELETED, "success")
    else:
        flash(MSG.SETTINGS_BIOMETRIC_NOT_FOUND, "danger")
    return redirect(url_for("settings.index"))


@settings_bp.route("/settings/recovery-key", methods=["POST"])
@login_required
@require_grant("settings.change")
def regenerate_recovery_key():
    """
    Terbitkan kunci pemulihan baru untuk DEK yang sama dan tampilkan sekali.

    Respons memakai Cache-Control: no-store. Kunci tidak masuk cookie, flash,
    URL, log, maupun basis data; hanya ada di HTML respons ini.
    """
    user_id = session["user_id"]
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        flash(MSG.SESSION_EXPIRED, "warning")
        return redirect(url_for("auth.login"))

    try:
        hasil = rewrap_recovery_key(dek, user_id)
    except (TypeError, ValueError):
        flash(MSG.SETTINGS_RECOVERY_FAILED, "danger")
        return redirect(url_for("settings.index"))
    finally:
        del dek

    with get_db() as db:
        db.execute(
            "UPDATE users SET recovery_wrapped_dek=? WHERE id=?",
            (hasil["recovery_wrapped_dek"], user_id),
        )
        db.commit()

    add_block(user_id, "RECOVERY_ROTATE", "auth:recovery",
              content_hash(str(user_id).encode("utf-8")))

    user = get_user_by_id(user_id)
    return _respon_tanpa_simpan(
        "settings.html",
        **_konteks(user, recovery_key_baru=hasil["recovery_key"]),
    )


@settings_bp.route("/settings/session-timeout", methods=["POST"])
@login_required
@require_grant("settings.change")
def session_timeout():
    """Simpan batas diam sesi pilihan pengguna dan terapkan pada sesi aktif."""
    try:
        menit = int(request.form.get("session_timeout_minutes", ""))
    except (TypeError, ValueError):
        flash(MSG.SETTINGS_SESSION_TIMEOUT_INVALID, "danger")
        return redirect(url_for("settings.index"))

    if menit not in _SESSION_TIMEOUT_PILIHAN:
        flash(MSG.SETTINGS_SESSION_TIMEOUT_INVALID, "danger")
        return redirect(url_for("settings.index"))

    user_id = session["user_id"]
    with get_db() as db:
        db.execute(
            "UPDATE users SET session_timeout_minutes=? WHERE id=?",
            (menit, user_id),
        )
        db.commit()
    session_keys.set_timeout(session.get("session_id", ""), menit)

    add_block(user_id, "SESSION_TIMEOUT", "auth:session",
              content_hash(str(user_id).encode("utf-8")))
    flash(MSG.SETTINGS_SESSION_TIMEOUT_SAVED, "success")
    return redirect(url_for("settings.index"))
