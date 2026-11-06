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
from modules.cryptography import session_keys
from modules.cryptography.key_management import purpose_key
from modules.cryptography.database_encryption import decrypt_record, encrypt_record
from modules.blockchain.blockchain import add_block, account_hash, content_hash

account_bp = Blueprint("account", __name__)


def _db_key() -> bytes:
    """Kunci field = purpose_key(DEK sesi, "database")."""
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        abort(403)
    return purpose_key(dek, "database")


@account_bp.route("/account-vault")
@login_required
def index():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM account_vault WHERE user_id=? ORDER BY created_at DESC",
            (session["user_id"],),
        ).fetchall()

    key = _db_key()
    uid = session["user_id"]
    entries = []
    for r in rows:
        try:
            dec = decrypt_record(
                {
                    "site_name_enc": r["site_name_enc"],
                    "username_enc": r["username_enc"],
                    "password_enc": r["password_enc"],
                    "url_enc": r["url_enc"],
                    "notes_enc": r["notes_enc"],
                },
                key, uid, "account_vault",
            )
        except Exception:
            entries.append({"id": r["id"], "site_name": "[Decryption Error]",
                            "username": "", "password": "", "url": "", "notes": "",
                            "updated_at": r["updated_at"]})
            continue
        entries.append({
            "id": r["id"],
            "site_name": dec["site_name_enc"],
            "username":  dec["username_enc"],
            "password":  dec["password_enc"],
            "url":       dec["url_enc"],
            "notes":     dec["notes_enc"],
            "updated_at": r["updated_at"],
        })
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

    key = _db_key()
    enc = encrypt_record(
        {
            "site_name_enc": site,
            "username_enc": uname,
            "password_enc": pwd,
            "url_enc": url,
            "notes_enc": notes,
        },
        key, session["user_id"], "account_vault",
    )
    with get_db() as db:
        cursor = db.execute(
            """INSERT INTO account_vault
               (user_id, site_name_enc, username_enc, password_enc, url_enc, notes_enc)
               VALUES (?,?,?,?,?,?)""",
            (
                session["user_id"],
                enc["site_name_enc"],
                enc["username_enc"],
                enc["password_enc"],
                enc["url_enc"],
                enc["notes_enc"],
            ),
        )
        entry_id = cursor.lastrowid
        db.commit()

    add_block(session["user_id"], "UPLOAD", f"cred:{entry_id}",
              account_hash(enc["site_name_enc"], enc["username_enc"],
                           enc["password_enc"]))
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
    add_block(session["user_id"], "DELETE", f"cred:{entry_id}",
              content_hash(str(entry_id).encode("utf-8")))
    flash(MSG.ACCOUNT_DELETED, "info")
    return redirect(url_for("account.index"))
