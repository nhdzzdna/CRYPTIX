"""
routes/dashboard_routes.py
────────────────────────────
Dashboard overview page.

Menampilkan ringkasan aset, status dongle, metode biometrik terdaftar,
hasil verifikasi rantai terakhir beserta jangkar kepala, dan aktivitas
terbaru milik pengguna sendiri.
"""

import os

from flask import Blueprint, render_template, session

import config
from routes.auth_routes import login_required
from database.db import get_db
from modules.authentication import biometrics, usb_authentication
from modules.authentication.face_recognition import template_ada
from modules.authentication.webauthn import kredensial_pengguna
from modules.blockchain.blockchain import (
    get_chain_stats,
    get_head_info,
    get_last_verification,
    get_recent_blocks,
)

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
def index():
    user_id = session["user_id"]
    with get_db() as db:
        file_count = db.execute(
            "SELECT COUNT(*) FROM vault_files "
            "WHERE user_id=? AND deleted_at IS NULL", (user_id,)
        ).fetchone()[0]
        note_count = db.execute(
            "SELECT COUNT(*) FROM secure_notes "
            "WHERE user_id=? AND deleted_at IS NULL", (user_id,)
        ).fetchone()[0]
        account_count = db.execute(
            "SELECT COUNT(*) FROM account_vault "
            "WHERE user_id=? AND deleted_at IS NULL", (user_id,)
        ).fetchone()[0]
        stego_count = db.execute(
            "SELECT COUNT(*) FROM stego_images "
            "WHERE user_id=? AND deleted_at IS NULL", (user_id,)
        ).fetchone()[0]

    # Disk usage of encrypted files
    enc_dir = config.ENCRYPTED_FILES_DIR
    total_bytes = 0
    if os.path.isdir(enc_dir):
        for f in os.listdir(enc_dir):
            fpath = os.path.join(enc_dir, f)
            if os.path.isfile(fpath):
                total_bytes += os.path.getsize(fpath)

    # Status faktor kedua: dongle dan biometrik yang benar-benar terdaftar.
    dongle_connected = usb_authentication.dongle_pengguna_terpasang(user_id)
    biometric_methods = biometrics.metode_untuk_pengguna(user_id)
    webauthn_credentials = len(kredensial_pengguna(user_id))
    face_enrolled = template_ada(user_id)

    recent_blocks = get_recent_blocks(user_id, limit=5)
    chain_stats   = get_chain_stats()
    last_verified = get_last_verification(user_id)
    head          = get_head_info()

    return render_template(
        "dashboard.html",
        file_count=file_count,
        note_count=note_count,
        account_count=account_count,
        stego_count=stego_count,
        total_bytes=total_bytes,
        recent_blocks=recent_blocks,
        chain_stats=chain_stats,
        dongle_connected=dongle_connected,
        biometric_methods=biometric_methods,
        webauthn_credentials=webauthn_credentials,
        face_enrolled=face_enrolled,
        last_verified=last_verified,
        head=head,
    )
