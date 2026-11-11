"""
routes/collection_shared.py
───────────────────────────
Helper bersama halaman koleksi (album Media, Musik, Dokumen).

Koleksi memakai tabel ``collections`` dengan kolom ``kind``; helper di sini
menyaring koleksi menurut kind, menghitung isi, dan menyusun daftar "Semua"
yang mengecualikan isi koleksi terkunci. Nama berkas dan nama koleksi
didekripsi di server; nilai mentah tidak pernah dikirim ke template.
"""

import os

from flask import request, session, url_for

from database.db import get_db
from modules.authentication.reauth import consume_grant, find_active_grant
from modules.strings import MSG
from modules.cryptography.database_encryption import (
    decrypt_field, field_aad,
)

PLAYABLE_EXTENSIONS = frozenset({
    "mp4", "webm", "mp3", "wav", "ogg", "m4a", "flac",
})
DOWNLOAD_ONLY_EXTENSIONS = frozenset({"avi", "mkv", "mov"})

IKON = {
    "image": "📷",
    "video": "🎬",
    "audio": "🎵",
    "document": "📄",
}


def extension(filename: str) -> str:
    """Ekstensi huruf kecil tanpa titik; string kosong bila tidak ada."""
    return os.path.splitext(filename or "")[1].lower().lstrip(".")


def display_name(row, db_key: bytes) -> str:
    """Buka nama asli berkas; token gagal ditandai aman."""
    try:
        return decrypt_field(
            row["original_name"], db_key,
            field_aad(row["user_id"], "vault_files", "original_name"),
        )
    except ValueError:
        return "[Nama tidak terbaca]"


def collection_name(row, db_key: bytes) -> str:
    """Buka nama koleksi; token gagal ditandai aman."""
    try:
        return decrypt_field(
            row["name_enc"], db_key,
            field_aad(row["user_id"], "collections", "name_enc"),
        )
    except ValueError:
        return "[Nama tidak terbaca]"


def file_info(row, db_key: bytes) -> dict:
    """Bentuk data tampilan aman untuk satu berkas koleksi."""
    nama = display_name(row, db_key)
    ext = extension(nama)
    jenis = row["file_type"]
    return {
        "id": row["id"],
        "original_name": nama,
        "file_type": jenis,
        "extension": ext,
        "icon": IKON.get(jenis, "📄"),
        "state": None,
        "collection_id": None,
        "view_url": url_for("media.view", file_id=row["id"]),
        "thumb_url": (url_for("media.thumb", file_id=row["id"])
                      if jenis == "image" else None),
        "stream_url": url_for("media.stream", file_id=row["id"]),
        "playable": ext in PLAYABLE_EXTENSIONS,
        "download_only": ext in DOWNLOAD_ONLY_EXTENSIONS,
        "file_size": row["file_size"],
        "uploaded_at": row["uploaded_at"],
    }


def grant_sah(scope: str, resource_id) -> bool:
    """
    Periksa grant lewat header atau grant aktif berulang.

    Token header diuji lebih dulu; bila tidak cocok untuk scope ini
    (misalnya header membawa token ``doc.preview`` sedangkan cek ini
    untuk ``album.unlock``), kembali dicari grant berulang yang aktif
    untuk sesi ini. Scope sekali pakai tetap tidak dapat dipakai ulang
    karena ``find_active_grant`` hanya mengembalikan grant berulang.
    """
    session_id = session.get("session_id", "")
    token = request.headers.get("X-Reauth-Grant") or ""
    sah, _ = consume_grant(token, session_id, scope, resource_id)
    if sah:
        return True
    token = find_active_grant(session_id, scope, resource_id) or ""
    sah, _ = consume_grant(token, session_id, scope, resource_id)
    return sah


def akses_item(row, file_id: int, scope_item: str = "item.view"):
    """
    Periksa aturan akses berdasarkan kunci koleksi dan state item.

    Koleksi terkunci dicek lebih dulu (grant ``album.unlock`` untuk id
    koleksi), lalu state item ``locked`` (grant ``item.view`` untuk id
    berkas, atau scope pengganti untuk pratinjau dokumen). Item di luar
    koleksi (Tanpa album) tidak dapat dikunci dan selalu lolos.

    Returns
    -------
    None bila boleh, atau ``(pesan, status)`` untuk penolakan JSON.
    """
    with get_db() as db:
        item = db.execute(
            """SELECT ci.state AS state, ci.collection_id AS collection_id,
                      c.locked AS collection_locked
               FROM collection_items ci
               JOIN collections c ON c.id = ci.collection_id
               WHERE ci.file_id=? AND c.user_id=?""",
            (file_id, row["user_id"]),
        ).fetchone()

    if item is None:
        return None
    if item["collection_locked"]:
        if not grant_sah("album.unlock", item["collection_id"]):
            return MSG.COLLECTION_LOCKED_NOTE, 403
    if item["state"] == "locked":
        sah = grant_sah("item.view", file_id)
        if not sah and scope_item != "item.view":
            sah = grant_sah(scope_item, file_id)
        if not sah:
            return MSG.ITEM_LOCKED, 403
    return None


def halaman_koleksi(db, user_id: int, kind: str, file_types, db_key: bytes) -> dict:
    """
    Muat koleksi satu kind beserta isi yang dapat ditampilkan.

    ``item_map`` memuat seluruh keanggotaan koleksi milik pengguna agar berkas
    yang berada di koleksi kind lain tidak muncul sebagai "Tanpa folder".
    ``semua`` adalah gabungan Tanpa folder + isi koleksi yang terbuka;
    isi koleksi terkunci hanya disertakan bila grant ``album.unlock``
    untuk koleksi itu sedang aktif di sesi.
    """
    jenis = tuple(file_types)
    tanda = ",".join("?" for _ in jenis)
    rows = db.execute(
        f"SELECT * FROM vault_files WHERE user_id=? "
        f"AND deleted_at IS NULL AND file_type IN ({tanda}) "
        "ORDER BY uploaded_at DESC, id DESC",
        (user_id, *jenis),
    ).fetchall()
    koleksi_rows = db.execute(
        "SELECT * FROM collections WHERE user_id=? AND kind=? "
        "ORDER BY created_at, id",
        (user_id, kind),
    ).fetchall()
    item_rows = db.execute(
        """SELECT ci.file_id, ci.collection_id, ci.state, c.locked
           FROM collection_items ci
           JOIN collections c ON c.id = ci.collection_id
           WHERE c.user_id=? ORDER BY ci.added_at""",
        (user_id,),
    ).fetchall()

    info = {r["id"]: file_info(r, db_key) for r in rows}
    item_map = {r["file_id"]: r for r in item_rows}
    for fid, item in item_map.items():
        if fid in info:
            info[fid]["state"] = item["state"]
            info[fid]["collection_id"] = item["collection_id"]

    session_id = session.get("session_id", "")
    koleksi_terbuka = {}
    folders = []
    folder_by_id = {}
    for k in koleksi_rows:
        terbuka = not k["locked"] or bool(
            find_active_grant(session_id, "album.unlock", k["id"])
        )
        koleksi_terbuka[k["id"]] = terbuka
        folder = {
            "id": k["id"], "name": collection_name(k, db_key),
            "kind": k["kind"], "locked": bool(k["locked"]),
            "cover": None, "jumlah": 0,
        }
        folder_by_id[k["id"]] = folder
        folders.append(folder)

    for fid, item in item_map.items():
        folder = folder_by_id.get(item["collection_id"])
        if folder is None:
            continue
        folder["jumlah"] += 1
        berkas = info.get(fid)
        if (folder["cover"] is None and berkas is not None
                and berkas["file_type"] == "image"):
            folder["cover"] = berkas["thumb_url"]

    unfiled = [info[fid] for fid in info if fid not in item_map]
    semua = [
        info[fid] for fid in info
        if fid not in item_map
        or koleksi_terbuka.get(item_map[fid]["collection_id"], False)
    ]
    return {
        "folders": folders,
        "unfiled": unfiled,
        "semua": semua,
        "info": info,
        "item_map": item_map,
    }
