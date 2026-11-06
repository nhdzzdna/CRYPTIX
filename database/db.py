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
