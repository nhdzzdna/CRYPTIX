"""
routes/notes_routes.py
───────────────────────
Secure Notes: encrypted text notes stored in SQLite.
"""

import os
import hashlib
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, abort

from modules.strings import MSG
from routes.auth_routes import login_required
from database.db import get_db
from modules.cryptography.key_management import master_key_from_hex, get_db_encryption_key
from modules.cryptography.database_encryption import encrypt_field, decrypt_field
from modules.blockchain.blockchain import add_block

notes_bp = Blueprint("notes", __name__)


def _db_key() -> bytes:
    mk = master_key_from_hex(session["master_key_hex"])
    return get_db_encryption_key(mk)


@notes_bp.route("/secure-notes")
@login_required
def index():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM secure_notes WHERE user_id=? ORDER BY updated_at DESC",
            (session["user_id"],),
        ).fetchall()

    key = _db_key()
    notes = []
    for r in rows:
        try:
            notes.append({
                "id": r["id"],
                "title":   decrypt_field(r["title_enc"],   key),
                "content": decrypt_field(r["content_enc"], key),
                "updated_at": r["updated_at"],
            })
        except Exception:
            notes.append({"id": r["id"], "title": "[Error]", "content": "",
                          "updated_at": r["updated_at"]})

    return render_template("secure_notes.html", notes=notes)


@notes_bp.route("/secure-notes/add", methods=["POST"])
@login_required
def add():
    title   = request.form.get("title",   "").strip()
    content = request.form.get("content", "").strip()
    if not title or not content:
        flash(MSG.NOTES_FIELDS_REQUIRED, "danger")
        return redirect(url_for("notes.index"))

    import os as _os
    key = _db_key()
    with get_db() as db:
        db.execute(
            """INSERT INTO secure_notes (user_id, title_enc, content_enc, nonce, tag)
               VALUES (?,?,?,?,?)""",
            (session["user_id"],
             encrypt_field(title, key),
             encrypt_field(content, key),
             _os.urandom(12).hex(), "n/a"),
        )
        db.commit()

    add_block(session["user_id"], "UPLOAD", hashlib.sha256(title.encode()).hexdigest())
    flash(MSG.NOTES_SAVED, "success")
    return redirect(url_for("notes.index"))


@notes_bp.route("/secure-notes/edit/<int:note_id>", methods=["POST"])
@login_required
def edit(note_id: int):
    title   = request.form.get("title",   "").strip()
    content = request.form.get("content", "").strip()
    if not title or not content:
        flash(MSG.NOTES_FIELDS_REQUIRED, "danger")
        return redirect(url_for("notes.index"))

    key = _db_key()
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM secure_notes WHERE id=? AND user_id=?",
            (note_id, session["user_id"]),
        ).fetchone()
        if not row:
            abort(404)
        db.execute(
            """UPDATE secure_notes
               SET title_enc=?, content_enc=?, updated_at=datetime('now')
               WHERE id=?""",
            (encrypt_field(title, key), encrypt_field(content, key), note_id),
        )
        db.commit()

    add_block(session["user_id"], "MODIFY", hashlib.sha256(title.encode()).hexdigest())
    flash(MSG.NOTES_UPDATED, "success")
    return redirect(url_for("notes.index"))


@notes_bp.route("/secure-notes/delete/<int:note_id>", methods=["POST"])
@login_required
def delete(note_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM secure_notes WHERE id=? AND user_id=?",
            (note_id, session["user_id"]),
        ).fetchone()
        if not row:
            abort(404)
        db.execute("DELETE FROM secure_notes WHERE id=?", (note_id,))
        db.commit()

    add_block(session["user_id"], "DELETE", hashlib.sha256(str(note_id).encode()).hexdigest())
    flash(MSG.NOTES_DELETED, "info")
    return redirect(url_for("notes.index"))
