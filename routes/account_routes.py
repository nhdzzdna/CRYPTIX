"""
routes/account_routes.py
─────────────────────────
Account Vault: store and retrieve encrypted credentials.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.utils import secure_filename

from modules.strings import MSG
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
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM account_vault WHERE user_id=? ORDER BY created_at DESC",
            (session["user_id"],),
        ).fetchall()

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
        flash(MSG.ACCOUNT_FIELDS_REQUIRED, "danger")
        return redirect(url_for("account.index"))

    import os as _os
    key = _db_key()
    nonce_placeholder = _os.urandom(12).hex()   # stored per field in token
    with get_db() as db:
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

    add_block(session["user_id"], "UPLOAD", hashlib.sha256(site.encode()).hexdigest())
    flash(MSG.ACCOUNT_ADDED, "success")
    return redirect(url_for("account.index"))


@account_bp.route("/account-vault/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete(entry_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM account_vault WHERE id=? AND user_id=?",
            (entry_id, session["user_id"]),
        ).fetchone()
        if not row:
            abort(404)
        db.execute("DELETE FROM account_vault WHERE id=?", (entry_id,))
        db.commit()
    add_block(session["user_id"], "DELETE", hashlib.sha256(str(entry_id).encode()).hexdigest())
    flash(MSG.ACCOUNT_DELETED, "info")
    return redirect(url_for("account.index"))
