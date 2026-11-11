"""
modules/trash.py
─────────────────
Fitur Sampah CRYPTIX: penghapusan lunak (soft delete), pemulihan, dan
penghapusan permanen ber-grant untuk berkas, catatan, kredensial, dan
gambar stego.

Perilaku:
  • ``pindah_ke_sampah``  — menandai baris dengan ``deleted_at``; berkas
    terenkripsi tetap di disk dan aset tetap diverifikasi oleh rantai.
  • ``pulihkan_dari_sampah`` — mengosongkan ``deleted_at`` sehingga item
    kembali tampil di daftar dan statistik.
  • ``hapus_permanen`` — menghapus baris basis data, berkas terenkripsi
    di disk, dan relasi ``collection_items``; dicatat sebagai blok DELETE.
  • ``bersihkan_kedaluwarsa`` — menghapus permanen item yang berada di
    sampah lebih lama dari ``config.TRASH_RETENTION_DAYS``; dipanggil
    saat startup dan saat halaman Sampah dibuka (tanpa scheduler).

Kunci jenis item mengikuti prefix ``asset_ref`` blockchain:
``file``, ``note``, ``cred``, ``stego``.
"""

import hashlib
import os
from datetime import datetime, timedelta, timezone

import config
from database.db import get_db
from modules.logger import get_logger
from modules.strings import MSG
from modules.blockchain.blockchain import add_block, content_hash
from modules.cryptography.database_encryption import (
    decrypt_field, decrypt_record, field_aad,
)

_logger = get_logger(__name__)

# Jenis item sampah → tabel penyimpanannya. Koleksi/album tidak masuk sampah.
TABEL_SAMPAH: dict[str, str] = {
    "file": "vault_files",
    "note": "secure_notes",
    "cred": "account_vault",
    "stego": "stego_images",
}

LABEL_JENIS: dict[str, str] = {
    "file": MSG.TRASH_KIND_FILE,
    "note": MSG.TRASH_KIND_NOTE,
    "cred": MSG.TRASH_KIND_CRED,
    "stego": MSG.TRASH_KIND_STEGO,
}

NAMA_TIDAK_TERBACA = "[Nama tidak terbaca]"


def _validasi_jenis(jenis: str) -> str:
    """Pastikan jenis dikenal; kembalikan bentuk kanoniknya."""
    hasil = str(jenis or "").strip().lower()
    if hasil not in TABEL_SAMPAH:
        raise ValueError(f"Jenis item sampah tidak dikenal: {jenis}")
    return hasil


def _sekarang_utc_naif() -> datetime:
    """Waktu UTC tanpa tzinfo, seformat dengan datetime('now') SQLite."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def sisa_hari(deleted_at: str | None) -> int:
    """Sisa hari sebelum item dibersihkan otomatis; minimal 0."""
    if not deleted_at:
        return 0
    try:
        dihapus = datetime.strptime(str(deleted_at)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return 0
    batas = dihapus + timedelta(days=config.TRASH_RETENTION_DAYS)
    return max(0, (batas - _sekarang_utc_naif()).days)


def _cutoff_retensi() -> str:
    """Waktu batas: item dengan deleted_at <= nilai ini dihapus permanen."""
    return (
        _sekarang_utc_naif() - timedelta(days=config.TRASH_RETENTION_DAYS)
    ).strftime("%Y-%m-%d %H:%M:%S")


def hash_aset(jenis: str, row) -> str:
    """
    Hash aset untuk blok rantai TRASH_MOVE/DELETE, mengikuti konvensi
    tiap jenis: berkas = SHA-256 ciphertext, catatan = HMAC isi terenkripsi,
    kredensial = HMAC id, gambar stego = SHA-256 berkas tersimpan.
    """
    if jenis == "file":
        return row["sha256_ciphertext"]
    if jenis == "note":
        return content_hash(row["content_enc"].encode("utf-8"))
    if jenis == "cred":
        return content_hash(str(row["id"]).encode("utf-8"))
    path = os.path.join(config.STEGO_IMAGES_DIR, row["stored_name"])
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return "0" * 64


def _cari_baris(db, jenis: str, item_id: int, user_id: int, di_sampah: bool):
    """Cari baris item milik pengguna, di dalam atau di luar sampah."""
    tabel = TABEL_SAMPAH[jenis]
    syarat = "deleted_at IS NOT NULL" if di_sampah else "deleted_at IS NULL"
    row = db.execute(
        f"SELECT * FROM {tabel} WHERE id=? AND user_id=? AND {syarat}",
        (item_id, user_id),
    ).fetchone()
    return dict(row) if row else None


def _hapus_baris(db, jenis: str, row) -> None:
    """Hapus baris, berkas fisik, dan relasi koleksi (tanpa commit)."""
    tabel = TABEL_SAMPAH[jenis]
    if jenis == "file":
        path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        if os.path.exists(path):
            os.remove(path)
        db.execute("DELETE FROM collection_items WHERE file_id=?",
                   (row["id"],))
    elif jenis == "stego":
        path = os.path.join(config.STEGO_IMAGES_DIR, row["stored_name"])
        if os.path.exists(path):
            os.remove(path)
    db.execute(f"DELETE FROM {tabel} WHERE id=?", (row["id"],))


def pindah_ke_sampah(db, jenis: str, item_id: int, user_id: int) -> dict | None:
    """
    Tandai item milik pengguna sebagai sampah (soft delete).

    Kembalikan baris item untuk pencatatan blok TRASH_MOVE, atau None bila
    item tidak ada, bukan milik pengguna, atau sudah berada di sampah.
    """
    jenis = _validasi_jenis(jenis)
    row = _cari_baris(db, jenis, item_id, user_id, di_sampah=False)
    if row is None:
        return None
    tabel = TABEL_SAMPAH[jenis]
    db.execute(
        f"UPDATE {tabel} SET deleted_at=datetime('now') WHERE id=? AND user_id=?",
        (item_id, user_id),
    )
    db.commit()
    return row


def pulihkan_dari_sampah(db, jenis: str, item_id: int, user_id: int) -> dict | None:
    """
    Batalkan soft delete pada satu item.

    Kembalikan baris item, atau None bila item tidak ada / bukan milik
    pengguna / tidak sedang berada di sampah.
    """
    jenis = _validasi_jenis(jenis)
    row = _cari_baris(db, jenis, item_id, user_id, di_sampah=True)
    if row is None:
        return None
    tabel = TABEL_SAMPAH[jenis]
    db.execute(
        f"UPDATE {tabel} SET deleted_at=NULL WHERE id=? AND user_id=?",
        (item_id, user_id),
    )
    db.commit()
    return row


def pulihkan_banyak(db, items, user_id: int) -> list[tuple[str, dict]] | None:
    """
    Pulihkan beberapa item sekaligus (all-or-nothing).

    ``items`` adalah daftar pasangan ``(jenis, id)``. Kembalikan daftar
    pasangan ``(jenis, baris)`` yang dipulihkan, atau None bila ada satu
    saja item yang tidak berada di sampah (tidak ada yang diubah).
    """
    terpilih = []
    for jenis, item_id in items:
        jenis = _validasi_jenis(jenis)
        row = _cari_baris(db, jenis, item_id, user_id, di_sampah=True)
        if row is None:
            return None
        terpilih.append((jenis, row))
    for jenis, row in terpilih:
        tabel = TABEL_SAMPAH[jenis]
        db.execute(f"UPDATE {tabel} SET deleted_at=NULL WHERE id=?",
                   (row["id"],))
    db.commit()
    return terpilih


def hapus_permanen(db, jenis: str, item_id: int, user_id: int) -> dict | None:
    """
    Hapus permanen satu item sampah milik pengguna.

    Kembalikan baris yang dihapus, atau None bila item tidak ada / bukan
    milik pengguna / tidak sedang berada di sampah.
    """
    hasil = hapus_permanen_banyak(db, [(jenis, item_id)], user_id)
    if hasil is None:
        return None
    return hasil[0][1]


def hapus_permanen_banyak(db, items, user_id: int) -> list[tuple[str, dict]] | None:
    """
    Hapus permanen beberapa item sampah sekaligus (all-or-nothing).

    Menghapus baris basis data, berkas terenkripsi di disk, dan relasi
    ``collection_items``, lalu mencatat blok DELETE per item. Kembalikan
    daftar pasangan ``(jenis, baris)`` yang dihapus, atau None bila ada
    item yang tidak berada di sampah (tidak ada yang dihapus).
    """
    terpilih = []
    for jenis, item_id in items:
        jenis = _validasi_jenis(jenis)
        row = _cari_baris(db, jenis, item_id, user_id, di_sampah=True)
        if row is None:
            return None
        # Hash dihitung sebelum berkas fisik dihapus.
        terpilih.append((jenis, row, hash_aset(jenis, row)))
    for jenis, row, _ in terpilih:
        _hapus_baris(db, jenis, row)
    db.commit()
    for jenis, row, hash_item in terpilih:
        add_block(user_id, "DELETE", f"{jenis}:{row['id']}", hash_item)
    return [(jenis, row) for jenis, row, _ in terpilih]


def kosongkan_sampah(db, user_id: int) -> list[tuple[str, dict]]:
    """Hapus permanen seluruh item sampah milik pengguna + blok DELETE."""
    terpilih = []
    for jenis, tabel in TABEL_SAMPAH.items():
        rows = db.execute(
            f"SELECT * FROM {tabel} WHERE user_id=? AND deleted_at IS NOT NULL",
            (user_id,),
        ).fetchall()
        for row in rows:
            terpilih.append((jenis, dict(row), hash_aset(jenis, row)))
    for jenis, row, _ in terpilih:
        _hapus_baris(db, jenis, row)
    if terpilih:
        db.commit()
        for jenis, row, hash_item in terpilih:
            add_block(user_id, "DELETE", f"{jenis}:{row['id']}", hash_item)
    return [(jenis, row) for jenis, row, _ in terpilih]


def bersihkan_kedaluwarsa(user_id: int | None = None) -> int:
    """
    Hapus permanen item sampah yang melewati masa retensi.

    Dipanggil saat startup (``user_id=None`` untuk seluruh pengguna) dan
    saat halaman Sampah dibuka (hanya milik pengguna itu). Kembalikan
    jumlah item yang dibersihkan.
    """
    cutoff = _cutoff_retensi()
    terpilih = []
    with get_db() as db:
        for jenis, tabel in TABEL_SAMPAH.items():
            if user_id is None:
                rows = db.execute(
                    f"SELECT * FROM {tabel} "
                    "WHERE deleted_at IS NOT NULL AND deleted_at <= ?",
                    (cutoff,),
                ).fetchall()
            else:
                rows = db.execute(
                    f"SELECT * FROM {tabel} "
                    "WHERE user_id=? AND deleted_at IS NOT NULL AND deleted_at <= ?",
                    (user_id, cutoff),
                ).fetchall()
            for row in rows:
                # Hash dihitung sebelum berkas fisik dihapus.
                terpilih.append(
                    (jenis, dict(row), row["user_id"], hash_aset(jenis, row))
                )
        if terpilih:
            for jenis, row, _, _ in terpilih:
                _hapus_baris(db, jenis, row)
            db.commit()
    for jenis, row, pemilik, hash_aset_item in terpilih:
        add_block(pemilik, "DELETE", f"{jenis}:{row['id']}", hash_aset_item)
    if terpilih:
        _logger.info(
            "Pembersihan sampah: %d item melewati retensi %d hari",
            len(terpilih), config.TRASH_RETENTION_DAYS,
        )
    return len(terpilih)


def _nama_item(jenis: str, row, user_id: int, db_key: bytes) -> str:
    """Buka nama item untuk daftar sampah; gagal dekripsi ditandai aman."""
    try:
        if jenis == "file":
            return decrypt_field(
                row["original_name"], db_key,
                field_aad(user_id, "vault_files", "original_name"),
            )
        if jenis == "stego":
            return decrypt_field(
                row["original_name"], db_key,
                field_aad(user_id, "stego_images", "original_name"),
            )
        if jenis == "note":
            return decrypt_record(
                {"title_enc": row["title_enc"]}, db_key, user_id, "secure_notes",
            )["title_enc"]
        return decrypt_record(
            {"site_name_enc": row["site_name_enc"]}, db_key, user_id,
            "account_vault",
        )["site_name_enc"]
    except Exception:
        return NAMA_TIDAK_TERBACA


def daftar_sampah(user_id: int, db_key: bytes) -> list[dict]:
    """
    Daftar item sampah milik pengguna, terbaru lebih dahulu.

    Nama item didekripsi di server memakai kunci field sesi; nilai mentah
    tidak pernah dikirim ke template.
    """
    hasil = []
    with get_db() as db:
        for jenis, tabel in TABEL_SAMPAH.items():
            rows = db.execute(
                f"SELECT * FROM {tabel} WHERE user_id=? AND deleted_at IS NOT NULL",
                (user_id,),
            ).fetchall()
            for row in rows:
                hasil.append({
                    "jenis": jenis,
                    "id": row["id"],
                    "nama": _nama_item(jenis, row, user_id, db_key),
                    "label": LABEL_JENIS[jenis],
                    "deleted_at": row["deleted_at"],
                    "sisa_hari": sisa_hari(row["deleted_at"]),
                })
    hasil.sort(key=lambda i: (i["deleted_at"] or "", i["id"]), reverse=True)
    return hasil
