"""
routes/collection_shared.py
───────────────────────────
Helper bersama halaman koleksi (album Media, Musik, Dokumen).

Koleksi memakai tabel ``collections`` dengan kolom ``kind``; helper di sini
menyaring koleksi menurut kind dan menghitung isi yang tidak tersembunyi.
Nama berkas dan nama koleksi didekripsi di server; nilai mentah tidak pernah
dikirim ke template.
"""

import os

from flask import url_for

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
        "view_url": url_for("media.view", file_id=row["id"]),
        "thumb_url": (url_for("media.thumb", file_id=row["id"])
                      if jenis == "image" else None),
        "stream_url": url_for("media.stream", file_id=row["id"]),
        "playable": ext in PLAYABLE_EXTENSIONS,
        "download_only": ext in DOWNLOAD_ONLY_EXTENSIONS,
        "file_size": row["file_size"],
        "uploaded_at": row["uploaded_at"],
    }


def halaman_koleksi(db, user_id: int, kind: str, file_types, db_key: bytes) -> dict:
    """
    Muat koleksi satu kind beserta isi yang dapat ditampilkan.

    ``item_map`` memuat seluruh keanggotaan koleksi milik pengguna agar berkas
    yang berada di koleksi kind lain tidak muncul sebagai "Tanpa folder".
    """
    jenis = tuple(file_types)
    tanda = ",".join("?" for _ in jenis)
    rows = db.execute(
        f"SELECT * FROM vault_files WHERE user_id=? "
        f"AND file_type IN ({tanda}) ORDER BY uploaded_at DESC, id DESC",
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

    folders = []
    folder_by_id = {}
    for k in koleksi_rows:
        folder = {
            "id": k["id"], "name": collection_name(k, db_key),
            "kind": k["kind"], "locked": bool(k["locked"]),
            "cover": None, "jumlah": 0,
        }
        folder_by_id[k["id"]] = folder
        folders.append(folder)

    for fid, item in item_map.items():
        folder = folder_by_id.get(item["collection_id"])
        if folder is None or item["state"] == "hidden":
            continue
        folder["jumlah"] += 1
        berkas = info.get(fid)
        if (folder["cover"] is None and berkas is not None
                and berkas["file_type"] == "image"):
            folder["cover"] = berkas["thumb_url"]

    unfiled = [info[fid] for fid in info if fid not in item_map]
    return {
        "folders": folders,
        "unfiled": unfiled,
        "info": info,
        "item_map": item_map,
    }
