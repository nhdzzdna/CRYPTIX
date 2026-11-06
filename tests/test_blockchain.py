"""
tests/test_blockchain.py
────────────────────────
Uji rantai hash: kolom sesuai skema, PoW, signature HMAC-SHA256, jangkar
head, add_block atomik, verifikasi aset, filter per pengguna, dan batas
laju LOGIN_FAIL. Basis data segar per tes via fixture.
"""

import hashlib
import json
import os
import sqlite3
import threading

import pytest

import config


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def bc_fresh(tmp_path, monkeypatch):
    """Modul rantai dengan basis data segar dan jangkar di folder tes."""
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "bc_test.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))

    from database.db import init_db
    init_db()

    import modules.blockchain.blockchain as bc
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    return bc


def _baris_asing(bc, user_id: int, tindakan: str = "UPLOAD") -> None:
    """Tulis blok milik pengguna lain untuk menguji penyaringan tampilan."""
    bc.add_block(user_id, tindakan, "file:99", "e" * 64)


# ── Blok dasar ───────────────────────────────────────────────────────────────

class TestBlokDasar:
    def test_satu_blok(self, bc_fresh):
        idx = bc_fresh.add_block(1, "UPLOAD", "file:1", "a" * 64)
        assert idx == 0

    def test_indeks_berturut(self, bc_fresh):
        bc_fresh.add_block(1, "UPLOAD",  "file:1", "a" * 64)
        bc_fresh.add_block(1, "DOWNLOAD", "file:1", "b" * 64)
        idx = bc_fresh.add_block(1, "DELETE", "file:1", "c" * 64)
        assert idx == 2

    def test_aksi_tidak_dikenal_ditolak(self, bc_fresh):
        with pytest.raises(ValueError):
            bc_fresh.add_block(1, "DECRYPT", "file:1", "a" * 64)

    def test_blok_berisi_kolom_wajib(self, bc_fresh):
        bc_fresh.add_block(1, "UPLOAD", "file:1", "a" * 64)
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = dict(conn.execute(
                "SELECT * FROM blockchain_log WHERE block_index=0"
            ).fetchone())
        for kolom in ("block_index", "timestamp", "user_id", "action",
                      "asset_ref", "asset_hash", "previous_hash", "nonce",
                      "block_hash", "signature"):
            assert kolom in row
        assert row["asset_ref"] == "file:1"
        assert len(row["signature"]) == 64

    def test_pow_nol_heksadesimal(self, bc_fresh):
        bc_fresh.add_block(1, "UPLOAD", "file:1", "a" * 64)
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            block_hash, nonce = conn.execute(
                "SELECT block_hash, nonce FROM blockchain_log"
            ).fetchone()
        assert block_hash.startswith("0" * config.POW_DIFFICULTY)
        assert nonce >= 0

    def test_jangkar_head_ditulis(self, bc_fresh):
        bc_fresh.add_block(1, "UPLOAD", "file:1", "a" * 64)
        bc_fresh.add_block(1, "UPLOAD", "file:2", "b" * 64)
        with open(bc_fresh.CHAIN_HEAD_PATH, encoding="utf-8") as handle:
            anchor = json.load(handle)
        assert anchor["database"] == config.DATABASE_PATH
        assert anchor["block_index"] == 1
        assert anchor["head_hash"] == bc_fresh.verify_chain()[-1]["block_hash"]


# ── Verifikasi rantai ────────────────────────────────────────────────────────

class TestVerifikasiRantai:
    def test_rantai_valid(self, bc_fresh):
        for _ in range(5):
            bc_fresh.add_block(1, "UPLOAD", "file:1", "x" * 64)
        result = bc_fresh.verify_chain()
        assert len(result) == 5
        for blk in result:
            assert blk["is_valid"] is True
            assert blk["tampered"] is False

    def test_suntik_hash_basi_terdeteksi(self, bc_fresh):
        bc_fresh.add_block(1, "UPLOAD",  "file:1", "a" * 64)
        bc_fresh.add_block(1, "DOWNLOAD", "file:1", "b" * 64)
        bc_fresh.add_block(1, "DELETE",  "file:1", "c" * 64)

        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute(
                "UPDATE blockchain_log SET block_hash=? WHERE block_index=1",
                ("deadbeef" * 8,),
            )
            conn.commit()

        result = bc_fresh.verify_chain()
        assert result[1]["tampered"] is True

    def test_pemalsuan_blok_tanpa_ulang_signature_terdeteksi(self, bc_fresh):
        """Pemalsu mengubah isi blok lalu menghitung ulang rantai tanpa
        kunci rantai: signature tidak cocok."""
        bc_fresh.add_block(1, "UPLOAD", "file:1", "a" * 64)
        bc_fresh.add_block(1, "DOWNLOAD", "file:1", "b" * 64)

        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.row_factory = sqlite3.Row
            blok0 = dict(conn.execute(
                "SELECT * FROM blockchain_log WHERE block_index=0"
            ).fetchone())
            blok1 = dict(conn.execute(
                "SELECT * FROM blockchain_log WHERE block_index=1"
            ).fetchone())

        # Pemalsu: ubah asset_hash blok 0, hitung ulang hash blok 0 dan 1
        # (tautan ikut diperbaiki) tetapi signature lama dibiarkan.
        blok0["asset_hash"] = "f" * 64
        hash0_baru = bc_fresh._hash_fields(blok0)
        blok1["previous_hash"] = hash0_baru
        base1 = {k: blok1[k] for k in (
            "block_index", "timestamp", "user_id", "action", "asset_ref",
            "asset_hash", "previous_hash",
        )}
        hash1_baru, nonce1 = bc_fresh._mine(base1, config.POW_DIFFICULTY)

        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute(
                "UPDATE blockchain_log SET asset_hash=?, block_hash=? "
                "WHERE block_index=0",
                (blok0["asset_hash"], hash0_baru),
            )
            conn.execute(
                "UPDATE blockchain_log SET previous_hash=?, nonce=?, "
                "block_hash=? WHERE block_index=1",
                (hash0_baru, nonce1, hash1_baru),
            )
            conn.commit()

        result = bc_fresh.verify_chain()
        assert result[0]["tampered"] is True
        assert result[1]["tampered"] is True

    def test_pemalsuan_signature_diuji_oleh_jangkar(self, bc_fresh):
        """Pemalsu yang sempat membaca kunci rantai (mis. dari disk) tetap
        tertangkap jangkar kepala walaupun signature ikut dihitung ulang."""
        bc_fresh.add_block(1, "UPLOAD", "file:1", "a" * 64)
        bc_fresh.add_block(1, "UPLOAD", "file:2", "b" * 64)

        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.row_factory = sqlite3.Row
            blok = dict(conn.execute(
                "SELECT * FROM blockchain_log WHERE block_index=1"
            ).fetchone())

        blok["asset_hash"] = "f" * 64
        base = {k: blok[k] for k in (
            "block_index", "timestamp", "user_id", "action", "asset_ref",
            "asset_hash", "previous_hash",
        )}
        hash_baru, nonce = bc_fresh._mine(base, config.POW_DIFFICULTY)
        signature_baru = bc_fresh._sign(bc_fresh._chain_key(), hash_baru)

        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute(
                """UPDATE blockchain_log
                   SET asset_hash=?, nonce=?, block_hash=?, signature=?
                   WHERE block_index=1""",
                (blok["asset_hash"], nonce, hash_baru, signature_baru),
            )
            conn.commit()

        result = bc_fresh.verify_chain()
        assert result[-1]["tampered"] is True

    def test_jangkar_beda_basis_data_diabaikan(self, bc_fresh):
        bc_fresh.add_block(1, "UPLOAD", "file:1", "a" * 64)
        with open(bc_fresh.CHAIN_HEAD_PATH, "w", encoding="utf-8") as handle:
            json.dump({"database": "/tmp/db_lain.db", "block_index": 99,
                       "head_hash": "0" * 64}, handle)
        result = bc_fresh.verify_chain()
        assert result[0]["tampered"] is False


# ── Tampilan per pengguna dan statistik global ───────────────────────────────

class TestTampilanPengguna:
    def test_get_recent_blocks_hanya_milik_pengguna(self, bc_fresh):
        for i in range(4):
            bc_fresh.add_block(1, "LOGIN", "auth:login", "z" * 64)
        _baris_asing(bc_fresh, 2)
        recent = bc_fresh.get_recent_blocks(1, limit=10)
        assert len(recent) == 4
        assert all(b["user_id"] == 1 for b in recent)

        assert bc_fresh.get_recent_blocks(2, limit=10)[0]["user_id"] == 2

    def test_statistik_rantai_global(self, bc_fresh):
        bc_fresh.add_block(1, "UPLOAD", "file:1", "h" * 64)
        _baris_asing(bc_fresh, 2)
        stats = bc_fresh.get_chain_stats()
        assert stats["total_blocks"] == 2
        assert stats["last_index"] == 1

    def test_blok_genesis_sebelumnya_valid(self, bc_fresh):
        bc_fresh.add_block(None, "REGISTER", "auth:register", "g" * 64)
        chain = bc_fresh.verify_chain()
        assert chain[0]["is_valid"] is True


# ── Batas laju LOGIN_FAIL ────────────────────────────────────────────────────

class TestLoginFail:
    def test_login_fail_dibatasi_laju(self, bc_fresh):
        hasil = [
            bc_fresh.add_block(3, "LOGIN_FAIL", "auth:login", "h" * 64)
            for _ in range(5)
        ]
        assert hasil[:3] == [0, 1, 2]
        assert hasil[3:] == [None, None]

    def test_login_fail_pengguna_lain_terpisah(self, bc_fresh):
        for _ in range(3):
            assert bc_fresh.add_block(3, "LOGIN_FAIL", "auth:login",
                                      "h" * 64) is not None
        assert bc_fresh.add_block(4, "LOGIN_FAIL", "auth:login",
                                  "h" * 64) is not None


# ── Verifikasi aset ──────────────────────────────────────────────────────────

class TestVerifyAset:
    @pytest.fixture()
    def berkas_tercatat(self, bc_fresh):
        """Satu berkas terenkripsi di disk dengan blok UPLOAD yang cocok."""
        os.makedirs(config.ENCRYPTED_FILES_DIR, exist_ok=True)
        isi = b"ciphertext-berkas-uji"
        stored = "abc123.bin"
        with open(os.path.join(config.ENCRYPTED_FILES_DIR, stored), "wb") as f:
            f.write(isi)
        sha = hashlib.sha256(isi).hexdigest()
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute(
                """INSERT INTO vault_files
                   (user_id, original_name, stored_name, file_type, file_size,
                    sha256_hash, sha256_ciphertext)
                   VALUES (?,?,?,?,?,?,?)""",
                (1, "v1:aa:bb", stored, "document", len(isi),
                 hashlib.sha256(b"pl").hexdigest(), sha),
            )
            conn.commit()
        bc_fresh.add_block(1, "UPLOAD", "file:1", sha)
        return stored

    def _status(self, bc_fresh, ref: str) -> str:
        entries = bc_fresh.verify_assets(1)
        cocok = [e for e in entries if e["ref"] == ref]
        return cocok[0]["status"] if cocok else None

    def test_berkas_ok(self, bc_fresh, berkas_tercatat):
        assert self._status(bc_fresh, "file:1") == "OK"

    def test_berkas_ciphertext_diubah_terdeteksi(self, bc_fresh, berkas_tercatat):
        path = os.path.join(config.ENCRYPTED_FILES_DIR, berkas_tercatat)
        with open(path, "wb") as f:
            f.write(b"ciphertext-yang-diubah")
        assert self._status(bc_fresh, "file:1") == "DIUBAH"

    def test_berkas_hilang(self, bc_fresh, berkas_tercatat):
        os.remove(os.path.join(config.ENCRYPTED_FILES_DIR, berkas_tercatat))
        assert self._status(bc_fresh, "file:1") == "HILANG"

    def test_berkas_tanpa_catatan_blok(self, bc_fresh, berkas_tercatat):
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute("DELETE FROM blockchain_log")
            conn.commit()
        assert self._status(bc_fresh, "file:1") == "TANPA CATATAN"

    def test_catatan_ok_lalu_diubah(self, bc_fresh):
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute(
                """INSERT INTO secure_notes
                   (user_id, title_enc, content_enc) VALUES (?,?,?)""",
                (1, "v1:aa:bb", "v1:cc:dd"),
            )
            conn.commit()
        bc_fresh.add_block(1, "UPLOAD", "note:1",
                           bc_fresh.content_hash(b"v1:cc:dd"))
        assert self._status(bc_fresh, "note:1") == "OK"

        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute(
                "UPDATE secure_notes SET content_enc='v1:ee:ff' WHERE id=1"
            )
            conn.commit()
        assert self._status(bc_fresh, "note:1") == "DIUBAH"

    def test_akun_ok_lalu_diubah(self, bc_fresh):
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute(
                """INSERT INTO account_vault
                   (user_id, site_name_enc, username_enc, password_enc)
                   VALUES (?,?,?,?)""",
                (1, "v1:a:1", "v1:b:2", "v1:c:3"),
            )
            conn.commit()
        bc_fresh.add_block(1, "UPLOAD", "cred:1",
                           bc_fresh.account_hash("v1:a:1", "v1:b:2", "v1:c:3"))
        assert self._status(bc_fresh, "cred:1") == "OK"

        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute(
                "UPDATE account_vault SET password_enc='v1:x:9' WHERE id=1"
            )
            conn.commit()
        assert self._status(bc_fresh, "cred:1") == "DIUBAH"

    def test_aset_pengguna_lain_tidak_diperiksa(self, bc_fresh, berkas_tercatat):
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            conn.execute("UPDATE vault_files SET user_id=2")
            conn.commit()
        assert bc_fresh.verify_assets(1) == []
        assert len(bc_fresh.verify_assets(2)) == 1


# ── Kunci rantai ─────────────────────────────────────────────────────────────

class TestKunciRantai:
    def test_content_hash_bukan_sha256_polo(self, bc_fresh):
        data = b"isi-catatan-rahasia"
        assert bc_fresh.content_hash(data) != hashlib.sha256(data).hexdigest()
        assert bc_fresh.content_hash(data) == bc_fresh.content_hash(data)

    def test_kunci_rantai_stabil_dan_di_luar_db(self, bc_fresh):
        kunci = bc_fresh._chain_key()
        assert len(kunci) == 32
        assert bc_fresh._chain_key() == kunci
        assert os.path.isfile(bc_fresh.CHAIN_KEY_PATH)

        # Kunci tidak pernah tersimpan di dalam basis data.
        with open(config.DATABASE_PATH, "rb") as handle:
            isi_db = handle.read()
        assert kunci not in isi_db
        assert kunci.hex().encode() not in isi_db


# ── Penulisan bersamaan ──────────────────────────────────────────────────────

class TestPenulisanBersamaan:
    def test_dua_penulis_indeks_tetap_urut(self, bc_fresh):
        hasil, galat = [], []

        def kerja():
            try:
                for i in range(3):
                    hasil.append(
                        bc_fresh.add_block(1, "UPLOAD", f"file:{i}", "a" * 64)
                    )
            except Exception as exc:      # pragma: no cover - saksi kegagalan
                galat.append(exc)

        pembuat = [threading.Thread(target=kerja) for _ in range(2)]
        for t in pembuat:
            t.start()
        for t in pembuat:
            t.join()

        assert galat == []
        assert sorted(hasil) == [0, 1, 2, 3, 4, 5]
        result = bc_fresh.verify_chain()
        assert all(b["is_valid"] for b in result)
