"""
routes/document_routes.py
───────────────────────────
Documents: view encrypted documents stored in My Vault.
Filters vault_files to file_type = 'document'.
"""

from flask import Blueprint, render_template, session

from routes.auth_routes import login_required
from database.db import get_db
from modules.cryptography.key_management import master_key_from_hex, purpose_key
from modules.cryptography.database_encryption import decrypt_field, field_aad

document_bp = Blueprint("documents", __name__)


def _display_name(row, db_key: bytes) -> str:
    """Buka nama asli dokumen untuk daftar; token gagal ditandai aman."""
    try:
        return decrypt_field(
            row["original_name"], db_key,
            field_aad(row["user_id"], "vault_files", "original_name"),
        )
    except ValueError:
        return "[Nama tidak terbaca]"


@document_bp.route("/documents")
@login_required
def index():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM vault_files WHERE user_id=? AND file_type='document' ORDER BY uploaded_at DESC",
            (session["user_id"],),
        ).fetchall()

    mk = master_key_from_hex(session["master_key_hex"])
    db_key = purpose_key(mk, "database")
    files = []
    for r in rows:
        row = dict(r)
        row["original_name"] = _display_name(r, db_key)
        files.append(row)
    return render_template("documents.html", files=files)
