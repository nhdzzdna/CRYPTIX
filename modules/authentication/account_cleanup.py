"""
modules/authentication/account_cleanup.py
──────────────────────────────────────────
Penghapusan data akun secara terpusat.

Dipakai oleh Settings (reset data dan hapus akun) serta halaman pemulihan
(hapus akun tanpa masuk). Seluruh penghapusan baris basis data dilakukan
dalam satu transaksi eksplisit agar tidak ada data yang terhapus sebagian.

Berkas terenkripsi dan gambar stego dihapus setelah transaksi berhasil.
Penghapusan berkas bersifat upaya terbaik: kegagalan sistem berkas dicatat
di log dan tidak mengembalikan baris yang sudah dihapus.
"""

from __future__ import annotations

import os

import config
from database.db import get_db
from modules.logger import get_logger

_logger = get_logger(__name__)

# Tabel opsional dari modul trash/UB yang mungkin digabung kemudian.
_TABEL_TRASH_OPSIONAL = ("trash_items", "trash", "deleted_items")


def _tabel_ada(db, nama: str) -> bool:
    """True bila tabel ``nama`` ada pada basis data aktif."""
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (nama,)
    ).fetchone() is not None


def _kolom_ada(db, tabel: str, kolom: str) -> bool:
    """True bila tabel ``tabel`` memiliki kolom ``kolom``."""
    return any(
        baris[1] == kolom
        for baris in db.execute(f"PRAGMA table_info({tabel})")
    )


def _hapus_berkas_aman(path: str) -> bool:
    """Hapus satu berkas; kegagalan sistem berkas hanya dicatat di log."""
    try:
        if path and os.path.exists(path):
            os.remove(path)
        return True
    except OSError as exc:
        _logger.warning("Berkas gagal dihapus: %s (%s)", path, exc)
        return False


def hapus_berkas_terenkripsi(stored_names) -> None:
    """Hapus berkas terenkripsi milik pengguna dari penyimpanan."""
    for nama in stored_names:
        if not nama:
            continue
        _hapus_berkas_aman(
            os.path.join(config.ENCRYPTED_FILES_DIR, os.path.basename(str(nama)))
        )


def hapus_berkas_stego(stored_names) -> None:
    """Hapus gambar stego milik pengguna dari penyimpanan."""
    for nama in stored_names:
        if not nama:
            continue
        _hapus_berkas_aman(
            os.path.join(config.STEGO_IMAGES_DIR, os.path.basename(str(nama)))
        )


def hapus_data_pengguna(user_id: int, hapus_akun: bool = False) -> dict:
    """
    Hapus data milik ``user_id`` dalam satu transaksi.

    ``hapus_akun=False`` (reset data) mempertahankan baris pengguna, kunci,
    dongle, kredensial WebAuthn, dan templat wajah. ``hapus_akun=True``
    menghapus baris pengguna beserta seluruh turunannya.

    Returns
    -------
    dict dengan ``success``, ``encrypted_files``, ``stego_files``,
    ``username``, ``usb_token_id``, dan ``error`` bila gagal.
    """
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            baris = db.execute(
                "SELECT username, usb_token_id FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if baris is None:
                db.rollback()
                return {
                    "success": False,
                    "error": "Akun tidak ditemukan.",
                    "encrypted_files": [],
                    "stego_files": [],
                    "username": None,
                    "usb_token_id": None,
                }

            berkas = [
                r["stored_name"] for r in db.execute(
                    "SELECT stored_name FROM vault_files WHERE user_id = ?",
                    (user_id,),
                ).fetchall()
            ]
            stego = [
                r["stored_name"] for r in db.execute(
                    "SELECT stored_name FROM stego_images WHERE user_id = ?",
                    (user_id,),
                ).fetchall()
            ]

            # Tabel trash opsional (UB): hapus lebih dahulu bila tersedia.
            for tabel in _TABEL_TRASH_OPSIONAL:
                if _tabel_ada(db, tabel) and _kolom_ada(db, tabel, "user_id"):
                    db.execute(f"DELETE FROM {tabel} WHERE user_id = ?", (user_id,))

            db.execute(
                "DELETE FROM collection_items WHERE collection_id IN "
                "(SELECT id FROM collections WHERE user_id = ?)",
                (user_id,),
            )
            db.execute("DELETE FROM collections WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM account_vault WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM secure_notes WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM stego_images WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM vault_files WHERE user_id = ?", (user_id,))

            if hapus_akun:
                db.execute(
                    "DELETE FROM webauthn_credentials WHERE user_id = ?", (user_id,)
                )
                db.execute(
                    "DELETE FROM biometric_templates WHERE user_id = ?", (user_id,)
                )
                db.execute("DELETE FROM users WHERE id = ?", (user_id,))

            db.commit()
        except Exception:
            db.rollback()
            raise

    return {
        "success": True,
        "error": None,
        "encrypted_files": berkas,
        "stego_files": stego,
        "username": baris["username"],
        "usb_token_id": baris["usb_token_id"],
    }
