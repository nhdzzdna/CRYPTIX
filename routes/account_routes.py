"""
routes/account_routes.py
─────────────────────────
Account Vault: store and retrieve encrypted credentials.
"""

import os
import sys
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from routes.auth_routes import login_required
from database.db import get_db
from modules.cryptography.key_management import master_key_from_hex, get_db_encryption_key
from modules.cryptography.database_encryption import encrypt_field, decrypt_field
from modules.blockchain.blockchain import add_block
import hashlib

account_bp = Blueprint("account", __name__)


def _db_key() -> bytes:
    mk = master_key_from_hex(session["master_key_hex"])
    return get_db_encryption_key(mk)


@account_bp.route("/account-vault")
@login_required
def index():
    db = get_db()
    try:
        rows = db.execute(
            "SELECT * FROM account_vault WHERE user_id=? ORDER BY created_at DESC",
            (session["user_id"],),
        ).fetchall()
    finally:
        db.close()

    key = _db_key()
    entries = []
    for r in rows:
        try:
            entries.append({
                "id": r["id"],
                "site_name": decrypt_field(r["site_name_enc"], key),
                "username":  decrypt_field(r["username_enc"],  key),
                "password":  decrypt_field(r["password_enc"],  key),
                "url":       decrypt_field(r["url_enc"],       key) if r["url_enc"]   else "",
                "notes":     decrypt_field(r["notes_enc"],     key) if r["notes_enc"] else "",
                "updated_at": r["updated_at"],
            })
        except Exception:
            entries.append({"id": r["id"], "site_name": "[Decryption Error]",
                            "username": "", "password": "", "url": "", "notes": "",
                            "updated_at": r["updated_at"]})
    return render_template("account_vault.html", entries=entries)


@account_bp.route("/account-vault/add", methods=["POST"])
@login_required
def add():
    site  = request.form.get("site_name", "")
    uname = request.form.get("username",  "")
    pwd   = request.form.get("password",  "")
    url   = request.form.get("url",   "")
    notes = request.form.get("notes", "")

    if not site or not uname or not pwd:
        flash("Site, username, and password are required.", "danger")
        return redirect(url_for("account.index"))

    key = _db_key()
    db = get_db()
    try:
        import os as _os
        nonce_placeholder = _os.urandom(12).hex()   # stored per field in token
        db.execute(
            """INSERT INTO account_vault
               (user_id, site_name_enc, username_enc, password_enc, url_enc, notes_enc, nonce, tag)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                session["user_id"],
                encrypt_field(site,  key),
                encrypt_field(uname, key),
                encrypt_field(pwd,   key),
                encrypt_field(url,   key) if url   else "",
                encrypt_field(notes, key) if notes else "",
                nonce_placeholder, "n/a",   # nonce/tag embedded in each field token
            ),
        )
        db.commit()
    finally:
        db.close()

    add_block(session["user_id"], "UPLOAD", hashlib.sha256(site.encode()).hexdigest())
    flash("Credential added.", "success")
    return redirect(url_for("account.index"))


@account_bp.route("/account-vault/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete(entry_id: int):
    db = get_db()
    try:
        row = db.execute(
            "SELECT * FROM account_vault WHERE id=? AND user_id=?",
            (entry_id, session["user_id"]),
        ).fetchone()
        if not row:
            abort(404)
        db.execute("DELETE FROM account_vault WHERE id=?", (entry_id,))
        db.commit()
    finally:
        db.close()
    add_block(session["user_id"], "DELETE", hashlib.sha256(str(entry_id).encode()).hexdigest())
    flash("Credential deleted.", "info")
    return redirect(url_for("account.index"))
