"""
routes/collection_routes.py
───────────────────────────
Koleksi dan album Media Vault: buat, ganti nama, hapus, kunci, pindahkan
berkas, ubah status item, dan ganti nama berkas.

Semua operasi memakai user_id pemilik sesi. Nama koleksi disimpan
terenkripsi mengikuti pola vault_files.original_name
(encrypt_field + field_aad). Respons galat memakai bentuk JSON proyek:
``{"success": false, "error": ..., "reason": ...}``.
"""

import os

from flask import (
    Blueprint, jsonify, request, session, abort, url_for,
)

from database.db import get_db
from modules.strings import MSG
from modules.authentication.reauth import (
    require_grant, consume_grant, find_active_grant,
)
from routes.auth_routes import login_required
from modules.cryptography import session_keys
from modules.cryptography.key_management import purpose_key
from modules.cryptography.database_encryption import (
    encrypt_field, decrypt_field, field_aad,
)
from modules.blockchain.blockchain import add_block, content_hash

collection_bp = Blueprint("collection", __name__)

KINDS = frozenset({"album", "musik", "dokumen"})
STATES = frozenset({"normal", "locked", "hidden"})
_NAMA_MAKS = 120


def _db_key() -> bytes | None:
    dek = session_keys.get(session.get("session_id", ""))
    if dek is None:
        return None
    return purpose_key(dek, "database")


def _aad(user_id) -> bytes:
    return field_aad(user_id, "collections", "name_enc")


def _galat(pesan: str, alasan: str, status: int = 400):
    return jsonify({"success": False, "error": pesan, "reason": alasan}), status


def _badan() -> dict:
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    return request.form.to_dict()


def _daftar_id(nilai) -> list[int]:
    """Ubah input file_ids menjadi daftar int unik tanpa nilai tak sah."""
    if isinstance(nilai, str):
        nilai = [bagian for bagian in nilai.split(",") if bagian.strip()]
    if not isinstance(nilai, list):
        return []
    hasil = []
    for item in nilai:
        try:
            angka = int(item)
        except (TypeError, ValueError):
            continue
        if angka not in hasil:
            hasil.append(angka)
    return hasil


def _koleksi(db, collection_id: int, user_id: int):
    return db.execute(
        "SELECT * FROM collections WHERE id=? AND user_id=?",
        (collection_id, user_id),
    ).fetchone()


def nama_koleksi(row, db_key: bytes) -> str:
    """Buka nama koleksi; token gagal ditandai aman."""
    try:
        return decrypt_field(row["name_enc"], db_key, _aad(row["user_id"]))
    except ValueError:
        return "[Nama tidak terbaca]"


def _grant_sah(scope: str, resource_id) -> bool:
    """Periksa grant lewat header atau grant aktif berulang."""
    session_id = session.get("session_id", "")
    token = request.headers.get("X-Reauth-Grant") or ""
    if not token:
        token = find_active_grant(session_id, scope, resource_id) or ""
    sah, _ = consume_grant(token, session_id, scope, resource_id)
    return sah


def _butuh_grant_koleksi(row) -> bool:
    """True bila koleksi terkunci tetapi grant album.unlock tidak tersedia."""
    if not row["locked"]:
        return False
    return not _grant_sah("album.unlock", row["id"])


# ── Buat koleksi ──────────────────────────────────────────────────────────────

@collection_bp.route("/api/collections", methods=["POST"])
@login_required
def create_collection():
    data = _badan()
    nama = str(data.get("name", "")).strip()
    kind = str(data.get("kind", "album")).strip().lower() or "album"
    if not nama:
        return _galat(MSG.COLLECTION_NAME_REQUIRED, "name")
    if len(nama) > _NAMA_MAKS:
        return _galat(MSG.COLLECTION_NAME_TOO_LONG, "name")
    if kind not in KINDS:
        return _galat(MSG.COLLECTION_KIND_INVALID, "kind")

    db_key = _db_key()
    if db_key is None:
        return _galat(MSG.ERROR_UNAUTHORIZED, "session", 401)

    token = encrypt_field(nama, db_key, _aad(session["user_id"]))
    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO collections (user_id, kind, name_enc, locked) VALUES (?,?,?,?)",
            (session["user_id"], kind, token, 1 if data.get("locked") else 0),
        )
        collection_id = cursor.lastrowid
        db.commit()

    add_block(session["user_id"], "UPLOAD", f"collection:{collection_id}",
              content_hash(f"{session['user_id']}:{kind}:{nama}".encode("utf-8")))
    return jsonify({
        "success": True,
        "message": MSG.COLLECTION_CREATED,
        "collection": {"id": collection_id, "name": nama, "kind": kind,
                       "locked": bool(data.get("locked"))},
    }), 201


# ── Ganti nama ────────────────────────────────────────────────────────────────

@collection_bp.route("/api/collections/<int:resource_id>/rename", methods=["POST"])
@login_required
def rename_collection(resource_id: int):
    data = _badan()
    nama = str(data.get("name", "")).strip()
    if not nama:
        return _galat(MSG.COLLECTION_NAME_REQUIRED, "name")
    if len(nama) > _NAMA_MAKS:
        return _galat(MSG.COLLECTION_NAME_TOO_LONG, "name")

    db_key = _db_key()
    if db_key is None:
        return _galat(MSG.ERROR_UNAUTHORIZED, "session", 401)

    with get_db() as db:
        row = _koleksi(db, resource_id, session["user_id"])
        if row is None:
            return _galat(MSG.COLLECTION_NOT_FOUND, "not_found", 404)
        if _butuh_grant_koleksi(row):
            return _galat(MSG.REAUTH_REQUIRED, "missing", 401)
        token = encrypt_field(nama, db_key, _aad(session["user_id"]))
        db.execute(
            "UPDATE collections SET name_enc=? WHERE id=? AND user_id=?",
            (token, resource_id, session["user_id"]),
        )
        db.commit()

    return jsonify({"success": True, "message": MSG.COLLECTION_RENAMED,
                    "collection": {"id": resource_id, "name": nama}})


# ── Hapus koleksi (isi menjadi Tanpa album) ───────────────────────────────────

@collection_bp.route("/api/collections/<int:resource_id>/delete", methods=["POST"])
@login_required
def delete_collection(resource_id: int):
    with get_db() as db:
        row = _koleksi(db, resource_id, session["user_id"])
        if row is None:
            return _galat(MSG.COLLECTION_NOT_FOUND, "not_found", 404)
        if _butuh_grant_koleksi(row):
            return _galat(MSG.REAUTH_REQUIRED, "missing", 401)
        # ON DELETE CASCADE menghapus baris collection_items sehingga isi
        # kembali menjadi Tanpa album; vault_files tidak disentuh.
        db.execute("DELETE FROM collections WHERE id=? AND user_id=?",
                   (resource_id, session["user_id"]))
        db.commit()

    return jsonify({"success": True, "message": MSG.COLLECTION_DELETED})


# ── Kunci / buka kunci ────────────────────────────────────────────────────────

@collection_bp.route("/api/collections/<int:resource_id>/lock", methods=["POST"])
@login_required
@require_grant("album.unlock")
def lock_collection(resource_id: int):
    data = _badan()
    locked = 1 if data.get("locked") in (True, 1, "1", "true", "on") else 0
    with get_db() as db:
        row = _koleksi(db, resource_id, session["user_id"])
        if row is None:
            return _galat(MSG.COLLECTION_NOT_FOUND, "not_found", 404)
        db.execute(
            "UPDATE collections SET locked=? WHERE id=? AND user_id=?",
            (locked, resource_id, session["user_id"]),
        )
        db.commit()

    return jsonify({"success": True, "message": MSG.COLLECTION_LOCK_CHANGED,
                    "locked": bool(locked)})


# ── Pindahkan banyak berkas ───────────────────────────────────────────────────

@collection_bp.route("/api/collections/move", methods=["POST"])
@login_required
def move_items():
    data = _badan()
    file_ids = _daftar_id(data.get("file_ids"))
    if not file_ids:
        return _galat(MSG.COLLECTION_FILE_NOT_FOUND, "file_ids")

    target = data.get("collection_id")
    collection_id = None
    if target not in (None, "", "null"):
        try:
            collection_id = int(target)
        except (TypeError, ValueError):
            return _galat(MSG.COLLECTION_NOT_FOUND, "not_found", 404)

    with get_db() as db:
        if collection_id is not None:
            row = _koleksi(db, collection_id, session["user_id"])
            if row is None:
                return _galat(MSG.COLLECTION_NOT_FOUND, "not_found", 404)
            if _butuh_grant_koleksi(row):
                return _galat(MSG.REAUTH_REQUIRED, "missing", 401)

        dimiliki = {
            baris["id"] for baris in db.execute(
                "SELECT id FROM vault_files WHERE user_id=? AND id IN (%s)"
                % ",".join("?" for _ in file_ids),
                (session["user_id"], *file_ids),
            )
        }
        if len(dimiliki) != len(file_ids):
            return _galat(MSG.COLLECTION_FILE_NOT_FOUND, "file_ids", 404)

        if collection_id is None:
            db.executemany(
                "DELETE FROM collection_items WHERE file_id=?",
                ((fid,) for fid in file_ids),
            )
        else:
            db.executemany(
                """INSERT INTO collection_items (file_id, collection_id, state)
                   VALUES (?,?, 'normal')
                   ON CONFLICT(file_id) DO UPDATE SET
                       collection_id=excluded.collection_id,
                       state='normal'""",
                ((fid, collection_id) for fid in file_ids),
            )
        db.commit()

    return jsonify({"success": True, "message": MSG.COLLECTION_MOVED,
                    "count": len(file_ids)})


# ── Ubah status item ──────────────────────────────────────────────────────────

@collection_bp.route("/api/collections/<int:resource_id>/items/state",
                     methods=["POST"])
@login_required
@require_grant("album.unlock")
def set_item_state(resource_id: int):
    data = _badan()
    state = str(data.get("state", "")).strip().lower()
    if state not in STATES:
        return _galat(MSG.COLLECTION_STATE_INVALID, "state")
    file_ids = _daftar_id(data.get("file_ids"))
    if not file_ids:
        return _galat(MSG.COLLECTION_FILE_NOT_FOUND, "file_ids")

    with get_db() as db:
        row = _koleksi(db, resource_id, session["user_id"])
        if row is None:
            return _galat(MSG.COLLECTION_NOT_FOUND, "not_found", 404)
        milik = {
            baris["file_id"] for baris in db.execute(
                """SELECT ci.file_id FROM collection_items ci
                   JOIN vault_files vf ON vf.id = ci.file_id
                   WHERE vf.user_id=? AND ci.collection_id=?
                     AND ci.file_id IN (%s)"""
                % ",".join("?" for _ in file_ids),
                (session["user_id"], resource_id, *file_ids),
            )
        }
        if len(milik) != len(file_ids):
            return _galat(MSG.COLLECTION_FILE_NOT_FOUND, "file_ids", 404)
        db.executemany(
            "UPDATE collection_items SET state=? WHERE file_id=? AND collection_id=?",
            ((state, fid, resource_id) for fid in file_ids),
        )
        db.commit()

    return jsonify({"success": True, "message": MSG.COLLECTION_STATE_CHANGED,
                    "state": state, "count": len(file_ids)})


# ── Daftar isi album untuk halaman bergaya galeri ─────────────────────────────

def _file_json(row, db_key: bytes, state: str) -> dict:
    """Data tampilan aman satu berkas; thumbnail dihilangkan bila terkunci."""
    try:
        nama = decrypt_field(
            row["original_name"], db_key,
            field_aad(row["user_id"], "vault_files", "original_name"),
        )
    except ValueError:
        nama = "[Nama tidak terbaca]"
    jenis = row["file_type"]
    if jenis == "image":
        ikon = "📷"
    elif jenis == "video":
        ikon = "🎬"
    else:
        ikon = "🎵"
    tampil_thumb = jenis == "image" and state == "normal"
    return {
        "id": row["id"],
        "name": nama,
        "file_type": jenis,
        "icon": ikon,
        "state": state,
        "view_url": url_for("media.view", file_id=row["id"]),
        "thumb_url": (url_for("media.thumb", file_id=row["id"])
                      if tampil_thumb else None),
    }


@collection_bp.route("/api/collections/<int:resource_id>/items")
@login_required
def list_items(resource_id: int):
    """Isi album yang dapat dilihat; item tersembunyi dikecualikan."""
    db_key = _db_key()
    if db_key is None:
        return _galat(MSG.ERROR_UNAUTHORIZED, "session", 401)

    with get_db() as db:
        row = _koleksi(db, resource_id, session["user_id"])
        if row is None:
            return _galat(MSG.COLLECTION_NOT_FOUND, "not_found", 404)
        if row["locked"] and not _grant_sah("album.unlock", resource_id):
            return _galat(MSG.REAUTH_REQUIRED, "missing", 401)
        baris = db.execute(
            """SELECT vf.*, ci.state AS item_state
               FROM collection_items ci
               JOIN vault_files vf ON vf.id = ci.file_id
               WHERE ci.collection_id=? AND vf.user_id=?
               ORDER BY ci.added_at, ci.file_id""",
            (resource_id, session["user_id"]),
        ).fetchall()
        tersembunyi = db.execute(
            """SELECT COUNT(*) AS n FROM collection_items
               WHERE collection_id=? AND state='hidden'""",
            (resource_id,),
        ).fetchone()["n"]

    terlihat = [
        _file_json(r, db_key, r["item_state"])
        for r in baris if r["item_state"] != "hidden"
    ]
    return jsonify({
        "success": True,
        "collection": {"id": row["id"], "name": nama_koleksi(row, db_key),
                       "kind": row["kind"], "locked": bool(row["locked"])},
        "items": terlihat,
        "hidden_count": int(tersembunyi),
    })


@collection_bp.route("/api/collections/<int:resource_id>/hidden")
@login_required
@require_grant("album.unlock")
def list_hidden(resource_id: int):
    """Item tersembunyi; hanya setelah grant album.unlock untuk album ini."""
    db_key = _db_key()
    if db_key is None:
        return _galat(MSG.ERROR_UNAUTHORIZED, "session", 401)

    with get_db() as db:
        row = _koleksi(db, resource_id, session["user_id"])
        if row is None:
            return _galat(MSG.COLLECTION_NOT_FOUND, "not_found", 404)
        baris = db.execute(
            """SELECT vf.*, ci.state AS item_state
               FROM collection_items ci
               JOIN vault_files vf ON vf.id = ci.file_id
               WHERE ci.collection_id=? AND vf.user_id=? AND ci.state='hidden'
               ORDER BY ci.added_at, ci.file_id""",
            (resource_id, session["user_id"]),
        ).fetchall()

    return jsonify({
        "success": True,
        "items": [_file_json(r, db_key, r["item_state"]) for r in baris],
    })


# ── Ganti nama berkas ─────────────────────────────────────────────────────────

@collection_bp.route("/api/media/<int:file_id>/rename", methods=["POST"])
@login_required
def rename_file(file_id: int):
    data = _badan()
    nama = str(data.get("name", "")).strip()
    nama = os.path.basename(nama.replace("\\", "/")).strip()
    if not nama:
        return _galat(MSG.FILE_NAME_REQUIRED, "name")
    if len(nama) > 255:
        return _galat(MSG.COLLECTION_NAME_TOO_LONG, "name")

    db_key = _db_key()
    if db_key is None:
        return _galat(MSG.ERROR_UNAUTHORIZED, "session", 401)

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=? AND user_id=?",
            (file_id, session["user_id"]),
        ).fetchone()
        if row is None:
            return _galat(MSG.ERROR_NOT_FOUND, "not_found", 404)
        aad = field_aad(row["user_id"], "vault_files", "original_name")
        token = encrypt_field(nama, db_key, aad)
        db.execute(
            "UPDATE vault_files SET original_name=? WHERE id=? AND user_id=?",
            (token, file_id, session["user_id"]),
        )
        db.commit()

    return jsonify({"success": True, "message": MSG.FILE_RENAMED,
                    "file": {"id": file_id, "name": nama}})
