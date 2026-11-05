"""
routes/dashboard_routes.py
────────────────────────────
Dashboard overview page.
"""

import os
import sys
from flask import Blueprint, render_template, session

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from routes.auth_routes import login_required
from database.db import get_db
from modules.blockchain.blockchain import get_recent_blocks, get_chain_stats
import config

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
def index():
    user_id = session["user_id"]
    db = get_db()
    try:
        file_count = db.execute(
            "SELECT COUNT(*) FROM vault_files WHERE user_id=?", (user_id,)
        ).fetchone()[0]
        note_count = db.execute(
            "SELECT COUNT(*) FROM secure_notes WHERE user_id=?", (user_id,)
        ).fetchone()[0]
        account_count = db.execute(
            "SELECT COUNT(*) FROM account_vault WHERE user_id=?", (user_id,)
        ).fetchone()[0]
        stego_count = db.execute(
            "SELECT COUNT(*) FROM stego_images WHERE user_id=?", (user_id,)
        ).fetchone()[0]
    finally:
        db.close()

    # Disk usage of encrypted files
    enc_dir = config.ENCRYPTED_FILES_DIR
    total_bytes = 0
    if os.path.isdir(enc_dir):
        for f in os.listdir(enc_dir):
            fpath = os.path.join(enc_dir, f)
            if os.path.isfile(fpath):
                total_bytes += os.path.getsize(fpath)

    recent_blocks = get_recent_blocks(limit=5)
    chain_stats   = get_chain_stats()

    return render_template(
        "dashboard.html",
        file_count=file_count,
        note_count=note_count,
        account_count=account_count,
        stego_count=stego_count,
        total_bytes=total_bytes,
        recent_blocks=recent_blocks,
        chain_stats=chain_stats,
    )
