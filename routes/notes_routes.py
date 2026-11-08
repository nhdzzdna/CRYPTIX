"""
routes/notes_routes.py
───────────────────────
Secure Notes: encrypted text notes stored in SQLite.
"""

from flask import (
    Blueprint, render_template, request, redirect, url_for, session, flash, abort,
    jsonify,
)

from modules.strings import MSG
from modules.authentication.reauth import require_grant
from routes.auth_routes import login_required
from database.db import get_db
from modules.cryptography import session_keys
from modules.cryptography.key_management import purpose_key
from modules.cryptography.database_encryption import decrypt_record, encrypt_record
from modules.cryptography.super_encryption import super_decrypt, super_encrypt
from modules.blockchain.blockchain import add_block, content_hash

notes_bp = Blueprint("notes", __name__)


def _dek() -> bytes:
    """DEK sesi aktif; dipakai untuk Super Encryption isi catatan."""
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        abort(403)
    return dek


def _db_key() -> bytes:
    """Kunci field = purpose_key(DEK sesi, "database")."""
    return purpose_key(_dek(), "database")


@notes_bp.route("/secure-notes")
@login_required
def index():
    with get_db() as db:
        rows = db.execute(
            """SELECT id, title_enc, updated_at FROM secure_notes
               WHERE user_id=? ORDER BY updated_at DESC""",
            (session["user_id"],),
        ).fetchall()

    key = _db_key()
    uid = session["user_id"]
    notes = []
    for r in rows:
        try:
            dec = decrypt_record({"title_enc": r["title_enc"]}, key, uid,
                                 "secure_notes")
        except Exception:
            notes.append({"id": r["id"], "title": "[Error]",
                          "updated_at": r["updated_at"]})
            continue
        notes.append({
            "id": r["id"],
            "title": dec["title_enc"],
            "updated_at": r["updated_at"],
        })

    return render_template("secure_notes.html", notes=notes)


@notes_bp.route("/secure-notes/add", methods=["POST"])
@login_required
def add():
    title   = request.form.get("title",   "").strip()
    content = request.form.get("content", "").strip()
    if not title or not content:
        flash(MSG.NOTES_FIELDS_REQUIRED, "danger")
        return redirect(url_for("notes.index"))

    key = _db_key()
    isi_super = super_encrypt(content, master_key=_dek())
    enc = encrypt_record(
        {"title_enc": title, "content_enc": isi_super},
        key, session["user_id"], "secure_notes",
    )
    with get_db() as db:
        cursor = db.execute(
            """INSERT INTO secure_notes (user_id, title_enc, content_enc)
               VALUES (?,?,?)""",
            (session["user_id"], enc["title_enc"], enc["content_enc"]),
        )
        note_id = cursor.lastrowid
        db.commit()

    add_block(session["user_id"], "UPLOAD", f"note:{note_id}",
              content_hash(enc["content_enc"].encode("utf-8")))
    flash(MSG.NOTES_SAVED, "success")
    return redirect(url_for("notes.index"))


@notes_bp.route("/secure-notes/open/<int:resource_id>", methods=["POST"])
@login_required
@require_grant("note.open")
def open_note(resource_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM secure_notes WHERE id=? AND user_id=?",
            (resource_id, session["user_id"]),
        ).fetchone()
    if not row:
        abort(404)

    dec = decrypt_record(
        {"title_enc": row["title_enc"], "content_enc": row["content_enc"]},
        _db_key(), session["user_id"], "secure_notes",
    )
    return jsonify({
        "success": True,
        "id": resource_id,
        "title": dec["title_enc"],
        "content": super_decrypt(dec["content_enc"], master_key=_dek()),
    })


@notes_bp.route("/secure-notes/edit/<int:resource_id>", methods=["POST"])
@login_required
@require_grant("note.edit")
def edit(resource_id: int):
    title   = request.form.get("title",   "").strip()
    content = request.form.get("content", "").strip()
    if not title or not content:
        flash(MSG.NOTES_FIELDS_REQUIRED, "danger")
        return redirect(url_for("notes.index"))

    key = _db_key()
    isi_super = super_encrypt(content, master_key=_dek())
    enc = encrypt_record(
        {"title_enc": title, "content_enc": isi_super},
        key, session["user_id"], "secure_notes",
    )
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM secure_notes WHERE id=? AND user_id=?",
            (resource_id, session["user_id"]),
        ).fetchone()
        if not row:
            abort(404)
        db.execute(
            """UPDATE secure_notes
               SET title_enc=?, content_enc=?, updated_at=datetime('now')
               WHERE id=? AND user_id=?""",
            (enc["title_enc"], enc["content_enc"], resource_id,
             session["user_id"]),
        )
        db.commit()

    add_block(session["user_id"], "MODIFY", f"note:{resource_id}",
              content_hash(enc["content_enc"].encode("utf-8")))
    flash(MSG.NOTES_UPDATED, "success")
    return redirect(url_for("notes.index"))


@notes_bp.route("/secure-notes/delete/<int:resource_id>", methods=["POST"])
@login_required
@require_grant("item.delete")
def delete(resource_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM secure_notes WHERE id=? AND user_id=?",
            (resource_id, session["user_id"]),
        ).fetchone()
        if not row:
            abort(404)
        db.execute("DELETE FROM secure_notes WHERE id=? AND user_id=?",
                   (resource_id, session["user_id"]))
        db.commit()

    add_block(session["user_id"], "DELETE", f"note:{resource_id}",
              content_hash(str(resource_id).encode("utf-8")))
    flash(MSG.NOTES_DELETED, "info")
    return redirect(url_for("notes.index"))
