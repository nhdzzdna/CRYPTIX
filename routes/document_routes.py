"""
routes/document_routes.py
──────────────────────────
Documents: view encrypted documents stored in My Vault.
Filters vault_files to file_type = 'document'.
"""

from flask import Blueprint, render_template, session

from routes.auth_routes import login_required
from database.db import get_db

document_bp = Blueprint("documents", __name__)


@document_bp.route("/documents")
@login_required
def index():
    with get_db() as db:
        files = db.execute(
            "SELECT * FROM vault_files WHERE user_id=? AND file_type='document' ORDER BY uploaded_at DESC",
            (session["user_id"],),
        ).fetchall()
    return render_template("documents.html", files=files)
