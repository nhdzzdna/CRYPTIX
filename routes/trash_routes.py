"""
routes/trash_routes.py
───────────────────────
Halaman Sampah: daftar item yang dihapus lunak, pulihkan, hapus permanen
(grant ``trash.purge``), dan kosongkan sampah.

Semua operasi hanya menyentuh item milik pengguna sesi. Respons berbentuk
JSON bila permintaan datang sebagai JSON/XHR; selain itu 302 + flash agar
form biasa kembali ke halaman Sampah.
"""

import json

from flask import (
    Blueprint, render_template, request, redirect, url_for, session,
    flash, jsonify, abort,
)

import config
from modules.strings import MSG
from modules.authentication.reauth import require_grant
from modules.rate_limit import limiter, REVEAL_LIMIT, user_or_ip_key
from routes.auth_routes import login_required
from database.db import get_db
from modules.cryptography import session_keys
from modules.cryptography.key_management import purpose_key
from modules import trash

trash_bp = Blueprint("trash", __name__)


def _db_key() -> bytes:
    """Kunci field = purpose_key(DEK sesi, "database")."""
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        abort(403)
    return purpose_key(dek, "database")


def _ingin_json() -> bool:
    """True bila klien mengharapkan respons JSON (permintaan API)."""
    return request.is_json or (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )


def _galat(pesan: str, alasan: str, status: int = 400):
    return jsonify({"success": False, "error": pesan, "reason": alasan}), status


def _daftar_items() -> list[tuple[str, int]] | None:
    """
    Ubah masukan ``items`` (field form JSON string atau badan JSON) menjadi
    daftar pasangan ``(jenis, id)``; None bila bentuknya tidak sah/kosong.
    """
    mentah = None
    if request.is_json:
        mentah = (request.get_json(silent=True) or {}).get("items")
    else:
        mentah = request.form.get("items")
    if isinstance(mentah, str):
        try:
            mentah = json.loads(mentah)
        except ValueError:
            return None
    if not isinstance(mentah, list) or not mentah:
        return None
    hasil = []
    for entri in mentah:
        if not isinstance(entri, dict):
            return None
        jenis = str(entri.get("jenis", "")).strip().lower()
        if jenis not in trash.TABEL_SAMPAH:
            return None
        try:
            item_id = int(entri.get("id"))
        except (TypeError, ValueError):
            return None
        hasil.append((jenis, item_id))
    return hasil


def _selesai(pesan: str, kategori: str, jumlah: int):
    """Respons JSON untuk API, atau 302 + flash untuk form biasa."""
    if _ingin_json():
        return jsonify({"success": True, "message": pesan, "count": jumlah})
    flash(pesan, kategori)
    return redirect(url_for("trash.index"))


# ── Halaman Sampah ────────────────────────────────────────────────────────────

@trash_bp.route("/sampah")
@login_required
def index():
    # Retensi diperiksa setiap kali halaman dibuka; tanpa scheduler.
    dibersihkan = trash.bersihkan_kedaluwarsa(session["user_id"])
    if dibersihkan:
        flash(MSG.TRASH_AUTO_PURGED.format(count=dibersihkan), "info")
    items = trash.daftar_sampah(session["user_id"], _db_key())
    return render_template(
        "sampah.html",
        items=items,
        retention_days=config.TRASH_RETENTION_DAYS,
    )


# ── Pulihkan ──────────────────────────────────────────────────────────────────

@trash_bp.route("/api/sampah/pulihkan", methods=["POST"])
@limiter.limit(REVEAL_LIMIT, key_func=user_or_ip_key)
@login_required
def pulihkan():
    items = _daftar_items()
    if items is None:
        return _galat(MSG.TRASH_ITEMS_INVALID, "items")
    with get_db() as db:
        hasil = trash.pulihkan_banyak(db, items, session["user_id"])
    if hasil is None:
        return _galat(MSG.TRASH_ITEM_NOT_FOUND, "not_found", 404)
    return _selesai(
        MSG.TRASH_RESTORED.format(count=len(hasil)), "success", len(hasil)
    )


# ── Hapus permanen (grant trash.purge) ───────────────────────────────────────

@trash_bp.route("/api/sampah/hapus-permanen", methods=["POST"])
@limiter.limit(REVEAL_LIMIT, key_func=user_or_ip_key)
@login_required
@require_grant("trash.purge")
def hapus_permanen():
    items = _daftar_items()
    if items is None:
        return _galat(MSG.TRASH_ITEMS_INVALID, "items")
    with get_db() as db:
        hasil = trash.hapus_permanen_banyak(db, items, session["user_id"])
    if hasil is None:
        return _galat(MSG.TRASH_ITEM_NOT_FOUND, "not_found", 404)
    return _selesai(
        MSG.TRASH_PURGED.format(count=len(hasil)), "info", len(hasil)
    )


# ── Kosongkan sampah (grant trash.purge) ─────────────────────────────────────

@trash_bp.route("/api/sampah/kosongkan", methods=["POST"])
@limiter.limit(REVEAL_LIMIT, key_func=user_or_ip_key)
@login_required
@require_grant("trash.purge")
def kosongkan():
    with get_db() as db:
        hasil = trash.kosongkan_sampah(db, session["user_id"])
    if hasil:
        pesan = MSG.TRASH_PURGED.format(count=len(hasil))
    else:
        pesan = MSG.TRASH_EMPTIED
    return _selesai(pesan, "info", len(hasil))
