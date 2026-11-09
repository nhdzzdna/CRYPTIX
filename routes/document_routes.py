"""
routes/document_routes.py
───────────────────────────
Halaman Dokumen (alias lama /documents): hanya berkas file_type='document',
dikelompokkan dalam folder kind='dokumen' beserta Tanpa folder.
"""

from flask import Blueprint, render_template, session, abort

from routes.auth_routes import login_required
from routes.collection_shared import halaman_koleksi
from routes.vault_routes import _dokumen_msg
from database.db import get_db
from modules.cryptography import session_keys
from modules.cryptography.key_management import purpose_key

document_bp = Blueprint("documents", __name__)


@document_bp.route("/documents")
@login_required
def index():
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        abort(403)
    db_key = purpose_key(dek, "database")
    with get_db() as db:
        data = halaman_koleksi(
            db, session["user_id"], "dokumen", ("document",), db_key,
        )
    return render_template(
        "vault.html",
        folders=data["folders"],
        unfiled=data["unfiled"],
        msg=_dokumen_msg(),
    )
