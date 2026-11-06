"""
tests/test_blockchain.py
─────────────────────────
Unit tests for the blockchain hash-chain.
Uses a fresh temp SQLite DB per test via a custom fixture.
"""

import sqlite3, tempfile, json, hashlib

import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def bc_fresh(tmp_path):
    """
    Returns a fresh blockchain module-level accessor backed by a temp DB.
    We monkey-patch the get_db used inside blockchain.py by re-importing
    after overriding config.DATABASE_PATH.
    """
    db_path = str(tmp_path / "bc_test.db")

    # Set the path before importing blockchain which calls get_db at runtime
    import config
    original = config.DATABASE_PATH
    config.DATABASE_PATH = db_path

    # Initialise schema
    from database.db import init_db
    init_db()

    # Return a helper that calls the blockchain functions while path is set
    import modules.blockchain.blockchain as bc
    yield bc

    config.DATABASE_PATH = original


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestBlockchain:
    def test_add_single_block(self, bc_fresh):
        idx = bc_fresh.add_block(1, "UPLOAD", "a" * 64)
        assert idx == 0

    def test_block_index_increments(self, bc_fresh):
        bc_fresh.add_block(1, "UPLOAD",  "a" * 64)
        bc_fresh.add_block(1, "DECRYPT", "b" * 64)
        idx = bc_fresh.add_block(1, "DELETE",  "c" * 64)
        assert idx == 2

    def test_verify_chain_valid(self, bc_fresh):
        for i in range(5):
            bc_fresh.add_block(1, "UPLOAD", "x" * 64)
        result = bc_fresh.verify_chain()
        assert len(result) == 5
        for blk in result:
            assert blk["is_valid"] is True
            assert blk["tampered"] is False

    def test_verify_chain_detects_tamper(self, bc_fresh):
        """Manually corrupt a block_hash and verify it is detected."""
        import config

        bc_fresh.add_block(1, "UPLOAD",  "a" * 64)
        bc_fresh.add_block(1, "DECRYPT", "b" * 64)
        bc_fresh.add_block(1, "DELETE",  "c" * 64)

        # Corrupt block 1's hash directly in SQLite
        conn = sqlite3.connect(config.DATABASE_PATH)
        conn.execute(
            "UPDATE blockchain_log SET block_hash=? WHERE block_index=1",
            ("deadbeef" * 8,),   # 64-char fake hash
        )
        conn.commit()
        conn.close()

        result = bc_fresh.verify_chain()
        # block 1 should be tampered AND block 2 (previous_hash mismatch)
        assert result[1]["tampered"] is True

    def test_get_recent_blocks(self, bc_fresh):
        for i in range(10):
            bc_fresh.add_block(1, "LOGIN", "z" * 64)
        recent = bc_fresh.get_recent_blocks(limit=3)
        assert len(recent) == 3

    def test_genesis_block_previous_hash(self, bc_fresh):
        bc_fresh.add_block(None, "REGISTER", "g" * 64)
        chain = bc_fresh.verify_chain()
        assert chain[0]["is_valid"] is True

    def test_chain_stats(self, bc_fresh):
        for i in range(4):
            bc_fresh.add_block(1, "UPLOAD", "h" * 64)
        stats = bc_fresh.get_chain_stats()
        assert stats["total_blocks"] == 4
        assert stats["last_index"] == 3
