"""
tests/test_encrypted_storage.py
────────────────────────────────
Uji integrasi rute penyimpanan: kolom nonce/tag palsu hilang, nama berkas serta
isi catatan/kredensial terenkripsi, berkas per chunk terverifikasi setelah
dekripsi, dan pemodifan tercatat sebagai blok TAMPER_DETECTED.
"""

import hashlib
import io
import re

import pytest
from PIL import Image

import config
from app import create_app
from database.db import get_db, init_db
from modules.cryptography import session_keys

MASTER_HEX = hashlib.sha256(b"kunci-sesi-uji").hexdigest()
KATA_SANDI = "kata-sandi-uji-tersimpan"
JUDUL = "Judul Catatan Rahasia"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "uji.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted_files"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego_images"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary_files"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pengujingsatu"), (2, "pengujingdua")):
            db.execute(
                """INSERT OR IGNORE INTO users
                   (id, username, email, password_hash, salt) VALUES (?,?,?,?,?)""",
                (uid, nama, f"{nama}@contoh.test", "hash-tidak-dipakai", "garam"),
            )
        db.commit()

    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "pengujingsatu"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, bytes.fromhex(MASTER_HEX))
    return c


def _csrf(client, halaman: str) -> str:
    """Ambil token CSRF dari halaman; sekaligus membuktikan halaman terbuka."""
    page = client.get(halaman)
    assert page.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True))
    assert match, "token CSRF tidak ditemukan"
    return match.group(1)


def _kolom(tabel: str) -> set[str]:
    with get_db() as db:
        return {baris["name"] for baris in db.execute(f"PRAGMA table_info({tabel})")}


def _blok() -> list[str]:
    with get_db() as db:
        return [
            b["action"]
            for b in db.execute("SELECT action FROM blockchain_log ORDER BY block_index")
        ]


class TestSkema:
    @pytest.mark.parametrize("tabel", ["account_vault", "secure_notes", "vault_files"])
    def test_kolom_nonce_tag_palsu_sudah_dihapus(self, app, tabel):
        kolom = _kolom(tabel)
        assert "nonce" not in kolom
        assert "tag" not in kolom

    def test_vault_files_menyimpan_dua_hash(self, app):
        assert {"sha256_hash", "sha256_ciphertext"} <= _kolom("vault_files")


class TestSecureNotes:
    def test_catatan_tersimpan_terenkripsi(self, client):
        token = _csrf(client, "/secure-notes")
        resp = client.post("/secure-notes/add", data={
            "csrf_token": token, "title": JUDUL, "content": f"Isi {KATA_SANDI}",
        })
        assert resp.status_code == 302

        with get_db() as db:
            row = db.execute("SELECT * FROM secure_notes WHERE user_id=1").fetchone()
        assert row["title_enc"].startswith("v1:")
        assert JUDUL not in row["title_enc"]
        assert KATA_SANDI not in row["content_enc"]

    def test_daftar_menampilkan_isi_setelah_dekripsi(self, client):
        token = _csrf(client, "/secure-notes")
        client.post("/secure-notes/add", data={
            "csrf_token": token, "title": "Catatan Terlihat", "content": "Isi terlihat",
        })
        body = client.get("/secure-notes").get_data(as_text=True)
        assert "Catatan Terlihat" in body
        assert "Isi terlihat" in body

    def test_catatan_dipindah_ke_pengguna_lain_tidak_terbaca(self, client):
        token = _csrf(client, "/secure-notes")
        client.post("/secure-notes/add", data={
            "csrf_token": token, "title": JUDUL, "content": "Isi pindah pengguna",
        })
        with get_db() as db:
            db.execute("UPDATE secure_notes SET user_id=2 WHERE user_id=1")
            db.commit()

        milik_satu = client.get("/secure-notes").get_data(as_text=True)
        assert JUDUL not in milik_satu

        with client.session_transaction() as sess:
            sess["user_id"] = 2
        milik_dua = client.get("/secure-notes").get_data(as_text=True)
        assert JUDUL not in milik_dua
        assert "[Error]" in milik_dua

    def test_tanpa_csrf_ditolak(self, client):
        resp = client.post("/secure-notes/add", data={"title": "x", "content": "y"})
        assert resp.status_code == 400


class TestAccountVault:
    def test_kredensial_terenkripsi_dan_terbaca_kembali(self, client):
        token = _csrf(client, "/account-vault")
        resp = client.post("/account-vault/add", data={
            "csrf_token": token,
            "site_name": "Situs Uji Kredensial",
            "username": "pengguna-rahasia",
            "password": KATA_SANDI,
            "url": "https://contoh.test",
            "notes": "catatan akun",
        })
        assert resp.status_code == 302

        with get_db() as db:
            row = db.execute("SELECT * FROM account_vault WHERE user_id=1").fetchone()
        assert row["password_enc"].startswith("v1:")
        assert KATA_SANDI not in row["password_enc"]
        assert "pengguna-rahasia" not in row["username_enc"]

        body = client.get("/account-vault").get_data(as_text=True)
        assert "Situs Uji Kredensial" in body
        assert "pengguna-rahasia" in body


def _unggah(client, nama: str, isi: bytes):
    token = _csrf(client, "/vault")
    return client.post("/vault/upload", data={
        "csrf_token": token,
        "file": (io.BytesIO(isi), nama),
    }, content_type="multipart/form-data")


class TestVaultFiles:
    @pytest.fixture()
    def unggahan(self, client):
        isi = b"isi dokumen uji terenkripsi " * 40
        resp = _unggah(client, "laporan-rahasia.pdf", isi)
        assert resp.status_code == 302
        with get_db() as db:
            row = db.execute("SELECT * FROM vault_files WHERE user_id=1").fetchone()
        return dict(row), isi

    def test_nama_simpan_acak_dan_nama_asli_terenkripsi(self, unggahan):
        row, isi = unggahan
        assert re.fullmatch(r"[0-9a-f]{32}\.bin", row["stored_name"])
        assert ".pdf" not in row["stored_name"]
        assert row["original_name"].startswith("v1:")
        assert "laporan-rahasia.pdf" not in row["original_name"]
        assert row["file_type"] == "document"
        assert row["file_size"] == len(isi)

    def test_dua_hash_disimpan_dan_sesuai_kenyataan(self, unggahan):
        row, isi = unggahan
        with open(f"{config.ENCRYPTED_FILES_DIR}/{row['stored_name']}", "rb") as f:
            blob = f.read()
        assert blob[:8] == b"CRYPTIX1"
        assert row["sha256_hash"] == hashlib.sha256(isi).hexdigest()
        assert row["sha256_ciphertext"] == hashlib.sha256(blob).hexdigest()

    def test_daftar_menampilkan_nama_asli(self, unggahan, client):
        body = client.get("/vault").get_data(as_text=True)
        assert "laporan-rahasia.pdf" in body
        assert "v1:" not in body

    def test_dokumen_terlihat_di_daftar_dokumen(self, unggahan, client):
        body = client.get("/documents").get_data(as_text=True)
        assert "laporan-rahasia.pdf" in body

    def test_unduhan_mengembalikan_plaintext_asli(self, unggahan, client):
        row, isi = unggahan
        resp = client.get(f"/vault/decrypt/{row['id']}")
        assert resp.status_code == 200
        assert resp.data == isi
        assert "laporan-rahasia.pdf" in resp.headers.get("Content-Disposition", "")

    def test_pemodifan_isi_berkas_dicatat_sebagai_tamper(self, unggahan, client):
        row, _isi = unggahan
        path = f"{config.ENCRYPTED_FILES_DIR}/{row['stored_name']}"
        with open(path, "rb") as f:
            blob = bytearray(f.read())
        blob[50] ^= 0xFF
        with open(path, "wb") as f:
            f.write(bytes(blob))

        resp = client.get(f"/vault/decrypt/{row['id']}")
        assert resp.status_code == 302
        assert "TAMPER_DETECTED" in _blok()

    def test_hash_plaintext_beda_dicatat_sebagai_tamper(self, unggahan, client):
        row, _isi = unggahan
        with get_db() as db:
            db.execute(
                "UPDATE vault_files SET sha256_hash=? WHERE id=?",
                ("0" * 64, row["id"]),
            )
            db.commit()

        resp = client.get(f"/vault/decrypt/{row['id']}")
        assert resp.status_code == 302
        assert "TAMPER_DETECTED" in _blok()


class TestStegoOriginalName:
    @pytest.fixture()
    def gambar(self, tmp_path):
        img = Image.new("RGB", (160, 160), color=(12, 90, 200))
        jalur = tmp_path / "gambar-pribadi.png"
        img.save(jalur, format="PNG")
        return jalur

    def test_nama_gambar_terenkripsi_dan_terbuka_kembali(self, client, gambar):
        token = _csrf(client, "/steganography")
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(gambar.read_bytes()), "gambar-pribadi.png"),
            "message": "pesan tersembunyi",
        }, content_type="multipart/form-data")
        assert resp.status_code == 302

        with get_db() as db:
            row = db.execute("SELECT * FROM stego_images WHERE user_id=1").fetchone()
        assert row["original_name"].startswith("v1:")
        assert "gambar-pribadi.png" not in row["original_name"]

        body = client.get("/steganography").get_data(as_text=True)
        assert "gambar-pribadi.png" in body

        unduhan = client.get(f"/steganography/download/{row['id']}")
        assert unduhan.status_code == 200
        assert "gambar-pribadi.png" in unduhan.headers.get("Content-Disposition", "")
