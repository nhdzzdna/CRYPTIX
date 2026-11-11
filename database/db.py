"""
database/db.py
──────────────
SQLite connection helper for CRYPTIX.
Provides a context-manager get_db() factory and init_db() bootstrapper.
"""

import contextlib
import sqlite3
import os

import config
from modules.logger import get_logger

_logger = get_logger(__name__)

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

# Kolom users yang dibuat oleh skema baru; basis data lama dilengkapi agar
# gerbang dongle dan hierarki kunci tidak gagal membaca baris lama.
_KOLOM_BARU_USERS: tuple[tuple[str, str], ...] = (
    ("kek_salt", "TEXT"),
    ("wrapped_dek", "TEXT"),
    ("recovery_wrapped_dek", "TEXT"),
    ("usb_token_id", "TEXT"),
    ("usb_verifier", "TEXT"),
    ("usb_volume_serial", "TEXT"),
    ("failed_attempts", "INTEGER NOT NULL DEFAULT 0"),
    ("locked_until", "TEXT"),
    ("session_timeout_minutes", "INTEGER"),
)

# Tabel yang diberi kolom deleted_at oleh fitur sampah; basis data lama
# dilengkapi agar soft delete tidak gagal pada baris yang sudah ada.
_TABEL_SAMPAH: tuple[str, ...] = (
    "vault_files", "secure_notes", "account_vault", "stego_images",
)


def _tambah_kolom_users(conn: sqlite3.Connection) -> None:
    """Lengkapi tabel users pada basis data yang dibuat sebelum skema ini."""
    ada = {baris[1] for baris in conn.execute("PRAGMA table_info(users)")}
    for nama, jenis in _KOLOM_BARU_USERS:
        if nama not in ada:
            conn.execute(f"ALTER TABLE users ADD COLUMN {nama} {jenis}")
            _logger.info("Kolom tabel users ditambahkan: %s", nama)


def _tambah_kolom_sampah(conn: sqlite3.Connection) -> None:
    """Lengkapi kolom deleted_at untuk fitur sampah (idempoten)."""
    for tabel in _TABEL_SAMPAH:
        kolom = {baris[1] for baris in conn.execute(f"PRAGMA table_info({tabel})")}
        if "deleted_at" not in kolom:
            conn.execute(f"ALTER TABLE {tabel} ADD COLUMN deleted_at TEXT")
            _logger.info("Kolom deleted_at ditambahkan pada tabel %s", tabel)


def _migrasi_state_item(conn: sqlite3.Connection) -> None:
    """
    Ubah state item 'hidden' lama menjadi 'locked' (UB: kunci item).

    State 'hidden' dihapus total; basis data lama dimigrasi saat startup
    sehingga item yang dulu disembunyikan kini memerlukan item.view.
    Idempoten: UPDATE tidak mengubah baris yang sudah 'locked'/'normal'.
    """
    diubah = conn.execute(
        "UPDATE collection_items SET state='locked' WHERE state='hidden'"
    ).rowcount
    if diubah:
        _logger.info(
            "State item 'hidden' lama diubah menjadi 'locked': %d baris", diubah
        )


@contextlib.contextmanager
def get_db():
    """
    Context-manager that yields an open SQLite connection and closes it on exit.

    Usage::

        with get_db() as db:
            db.execute(...)
    """
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Create all tables from schema.sql if they don't exist yet."""
    os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    with get_db() as conn:
        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        _tambah_kolom_users(conn)
        _tambah_kolom_sampah(conn)
        _migrasi_state_item(conn)
        # Ensure schema_meta exists and has version row
        conn.execute(
            "INSERT OR IGNORE INTO schema_meta (version) VALUES (1)"
        )
        conn.commit()
    _logger.info("Database initialised at: %s", config.DATABASE_PATH)


def close_db(conn: sqlite3.Connection) -> None:
    """Close a connection. Kept for backward compatibility."""
    if conn:
        conn.close()
