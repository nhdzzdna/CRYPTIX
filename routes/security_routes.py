"""
routes/security_routes.py
──────────────────────────
Security Center: blockchain integrity verification and activity log.
Tampilan blok dibatasi blok milik pengguna; status keutuhan rantai global.
"""

from flask import Blueprint, render_template, session

from routes.auth_routes import login_required
from modules.blockchain.blockchain import (
    get_chain_stats,
    get_head_info,
    get_last_verification,
    get_recent_blocks,
    record_verification,
    verify_assets,
    verify_chain,
)

security_bp = Blueprint("security", __name__)


def _konteks_dasar(user_id: int) -> dict:
    """Data yang selalu ditampilkan: blok milik pengguna, statistik, jangkar."""
    return {
        "blocks": get_recent_blocks(user_id, limit=50),
        "stats": get_chain_stats(),
        "head": get_head_info(),
        "last_verified": get_last_verification(user_id),
        "verified": None,
        "assets": None,
        "tampered_count": 0,
        "chain_valid": None,
    }


@security_bp.route("/security-center")
@login_required
def index():
    return render_template("security_center.html", **_konteks_dasar(session["user_id"]))


@security_bp.route("/security-center/verify", methods=["POST"])
@login_required
def verify():
    """
    Jalankan verifikasi rantai global dan seluruh aset milik pengguna.

    Status keutuhan dihitung atas seluruh rantai, tetapi blok yang ditampilkan
    hanya blok milik pengguna ini. Daftar aset juga hanya milik pengguna.
    """
    user_id = session["user_id"]
    chain_result = verify_chain()
    assets = verify_assets(user_id)
    hasil = record_verification(user_id, chain_result)

    tampered_count = sum(1 for b in chain_result if b["tampered"])
    milik_pengguna = [b for b in chain_result if b["user_id"] == user_id]

    konteks = _konteks_dasar(user_id)
    konteks.update({
        "blocks": milik_pengguna[::-1],
        "verified": True,
        "assets": assets,
        "tampered_count": tampered_count,
        "chain_valid": tampered_count == 0,
        "last_verified": hasil,
    })
    return render_template("security_center.html", **konteks)
