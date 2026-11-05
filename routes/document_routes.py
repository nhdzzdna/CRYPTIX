"""
routes/document_routes.py
──────────────────────────
Documents: view encrypted documents stored in My Vault.
Filters vault_files to file_type = 'document'.
"""

import os
import sys
from flask import Blueprint, render_template, session

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from routes.auth_routes import login_required
from database.db import get_db

document_bp = Blueprint("documents", __name__)


@document_bp.route("/documents")
@login_required
def index():
    db = get_db()
    try:
        files = db.execute(
            "SELECT * FROM vault_files WHERE user_id=? AND file_type='document' ORDER BY uploaded_at DESC",
            (session["user_id"],),
        ).fetchall()
    finally:
        db.close()
    return render_template("documents.html", files=files)
