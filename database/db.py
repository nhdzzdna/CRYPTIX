"""
database/db.py
──────────────
SQLite connection helper for CRYPTIX.
Provides a thread-safe get_db() factory and init_db() bootstrapper.
"""

import sqlite3
import os
import sys

# Allow importing config from project root regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_db() -> sqlite3.Connection:
    """Open (or reuse) a SQLite connection with row_factory set to Row."""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create all tables from schema.sql if they don't exist yet."""
    os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    with get_db() as conn:
        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
    print("[db] Database initialised at:", config.DATABASE_PATH)


def close_db(conn: sqlite3.Connection) -> None:
    """Close a connection returned by get_db()."""
    if conn:
        conn.close()
