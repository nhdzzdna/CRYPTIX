"""
routes/security_routes.py
──────────────────────────
Security Center: blockchain integrity verification and activity log.
Tampilan blok dibatasi blok milik pengguna; status keutuhan rantai global.
"""

from flask import Blueprint, render_template, session

from routes.auth_routes import login_required
from modules.blockchain.blockchain import verify_chain, get_recent_blocks, get_chain_stats

security_bp = Blueprint("security", __name__)


@security_bp.route("/security-center")
@login_required
def index():
    recent = get_recent_blocks(session["user_id"], limit=50)
    stats  = get_chain_stats()
    return render_template("security_center.html", blocks=recent, stats=stats, verified=None)


@security_bp.route("/security-center/verify", methods=["POST"])
@login_required
def verify():
    chain_result = verify_chain()
    stats = get_chain_stats()
    # Status keutuhan dihitung atas seluruh rantai (global), tetapi yang
    # ditampilkan hanya blok milik pengguna ini.
    tampered_count = sum(1 for b in chain_result if b["tampered"])
    milik_pengguna = [
        b for b in chain_result if b["user_id"] == session["user_id"]
    ]
    return render_template(
        "security_center.html",
        blocks=milik_pengguna,
        stats=stats,
        verified=True,
        tampered_count=tampered_count,
    )
