"""
modules/blockchain/blockchain.py
─────────────────────────────────
Simple hash-chain audit log stored in SQLite.

Each block contains:
  • block_index   — sequential integer
  • timestamp     — ISO 8601 UTC
  • user_id       — who performed the action
  • action        — UPLOAD / DECRYPT / MODIFY / DELETE / LOGIN / REGISTER
  • asset_hash    — SHA-256 of the asset (file, note, credential) at event time
  • previous_hash — hash of the immediately preceding block
  • block_hash    — SHA-256 of the concatenation of all above fields

Integrity verification:
  Re-compute each block_hash and check that previous_hash == hash of the
  prior block.  Any mismatch marks that block as TAMPERED.
"""

import hashlib
import json
from datetime import datetime, timezone

from database.db import get_db
import config


# ── Internal helpers ──────────────────────────────────────────────────────────

def _compute_block_hash(
    block_index: int,
    timestamp: str,
    user_id: int | None,
    action: str,
    asset_hash: str,
    previous_hash: str,
) -> str:
    """Compute SHA-256 of the concatenated block fields."""
    raw = json.dumps(
        {
            "block_index": block_index,
            "timestamp": timestamp,
            "user_id": user_id,
            "action": action,
            "asset_hash": asset_hash,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _genesis_hash() -> str:
    """Return the fixed hash for the genesis (previous_hash of block 0)."""
    return hashlib.sha256(b"CRYPTIX-GENESIS-BLOCK").hexdigest()


# ── Public API ────────────────────────────────────────────────────────────────

def add_block(
    user_id: int | None,
    action: str,
    asset_hash: str,
) -> int:
    """
    Append a new block to the chain.

    Parameters
    ----------
    user_id    : int or None  User performing the action.
    action     : str          One of UPLOAD/DECRYPT/MODIFY/DELETE/LOGIN/REGISTER.
    asset_hash : str          SHA-256 hex of the relevant asset.

    Returns
    -------
    int  The new block's index.
    """
    with get_db() as db:
        last = db.execute(
            "SELECT block_index, block_hash FROM blockchain_log ORDER BY block_index DESC LIMIT 1"
        ).fetchone()

        if last is None:
            block_index = 0
            previous_hash = _genesis_hash()
        else:
            block_index = last["block_index"] + 1
            previous_hash = last["block_hash"]

        timestamp = datetime.now(timezone.utc).isoformat()
        block_hash = _compute_block_hash(
            block_index, timestamp, user_id, action, asset_hash, previous_hash
        )

        db.execute(
            """INSERT INTO blockchain_log
               (block_index, timestamp, user_id, action, asset_hash, previous_hash, block_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (block_index, timestamp, user_id, action, asset_hash, previous_hash, block_hash),
        )
        db.commit()
        return block_index


def verify_chain() -> list[dict]:
    """
    Verify the integrity of the entire blockchain.

    Returns
    -------
    list of dicts, one per block, each with all block fields plus
    ``is_valid`` bool and ``tampered`` bool.
    """
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM blockchain_log ORDER BY block_index ASC"
        ).fetchall()

    results = []
    expected_previous = _genesis_hash()

    for row in rows:
        row = dict(row)
        recomputed = _compute_block_hash(
            row["block_index"],
            row["timestamp"],
            row["user_id"],
            row["action"],
            row["asset_hash"],
            row["previous_hash"],
        )
        hash_ok    = recomputed == row["block_hash"]
        chain_ok   = row["previous_hash"] == expected_previous
        row["is_valid"] = hash_ok and chain_ok
        row["tampered"] = not row["is_valid"]
        results.append(row)
        expected_previous = row["block_hash"]

    return results


def get_recent_blocks(limit: int = 20) -> list[dict]:
    """Return the most recent *limit* blocks (newest first)."""
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM blockchain_log ORDER BY block_index DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_chain_stats() -> dict:
    """Return summary statistics about the chain."""
    with get_db() as db:
        row = db.execute(
            "SELECT COUNT(*) as total, MAX(block_index) as last_index FROM blockchain_log"
        ).fetchone()
        return {"total_blocks": row["total"], "last_index": row["last_index"]}
