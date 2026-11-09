"""
tests/test_n3b_musik_dokumen.py
───────────────────────────────
Uji halaman Musik dan Dokumen yang memakai mekanisme koleksi N3a:
CRUD folder, IDOR antar pengguna, pemisahan audio/dokumen antarahalaman,
folder terkunci tanpa grant, pemindahan banyak berkas, item tersembunyi,
serta penanda pencarian dan pengurutan.
"""

import io
import os
import re
import sqlite3

import pytest
from PIL import Image

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth
from modules.cryptography import session_keys
from modules.cryptography.database_encryption import (
    encrypt_field, decrypt_field, field_aad,
)
from modules.cryptography.file_encryption import (
    encrypt_stream, file_aad, generate_stored_name,
)
from modules.cryptography.key_management import purpose_key

DEK = bytes(range(32))
ISI_AUDIO = b"ID3" + bytes(range(256)) * 4
ISI_DOKUMEN = b"%PDF-1.4 dokumen uji n3b"


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (60, 40), (10, 120, 90)).save(buf, format="PNG")
    return buf.getvalue()


def _tipe_berkas(nama: str) -> str:
    ext = os.path.splitext(nama)[1].lower()
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}:
        return "image"
    if ext in {".mp3", ".wav", ".flac", ".ogg", ".m4a"}:
        return "audio"
    if ext in {".mp4", ".webm", ".avi", ".mkv", ".mov"}:
        return "video"
    return "document"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "n3b.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-tidak-ada.exe"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pemilikn3b"), (2, "lainn3b")):
            db.execute(
                """INSERT OR IGNORE INTO users
                   (id, username, email, password_hash, salt) VALUES (?,?,?,?,?)""",
                (uid, nama, f"{nama}@contoh.test", "hash", "garam"),
            )
        db.commit()
    application = create_app()
    application.config["TESTING"] = True
    reauth.clear()
    return application


def _client(app, user_id: int, nama: str):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = nama
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, DEK)
    return c


@pytest.fixture()
def client(app):
    return _client(app, 1, "pemilikn3b")


@pytest.fixture()
def client2(app):
    return _client(app, 2, "lainn3b")


def _csrf(client, halaman: str = "/musik") -> str:
    page = client.get(halaman)
    assert page.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"',
                      page.get_data(as_text=True))
    assert match
    return match.group(1)


def _grant(client, scope: str, resource_id=None) -> str:
    with client.session_transaction() as sess:
        sid = sess["session_id"]
    return reauth.issue_grant(sid, scope, resource_id)["token"]


def _buat_berkas(user_id: int, nama: str, data: bytes) -> int:
    stored_name = generate_stored_name()
    path = os.path.join(config.ENCRYPTED_FILES_DIR, stored_name)
    os.makedirs(config.ENCRYPTED_FILES_DIR, exist_ok=True)
    hasil = encrypt_stream(
        io.BytesIO(data), path,
        purpose_key(DEK, "file"), file_aad(user_id, stored_name),
    )
    token = encrypt_field(
        nama, purpose_key(DEK, "database"),
        field_aad(user_id, "vault_files", "original_name"),
    )
    with get_db() as db:
        cursor = db.execute(
            """INSERT INTO vault_files
               (user_id, original_name, stored_name, file_type, file_size,
                sha256_hash, sha256_ciphertext)
               VALUES (?,?,?,?,?,?,?)""",
            (user_id, token, stored_name, _tipe_berkas(nama), len(data),
             hasil["sha256_plaintext"], hasil["sha256_ciphertext"]),
        )
        db.commit()
        return cursor.lastrowid


def _buat_koleksi(client, nama: str, kind: str, locked: bool = False) -> int:
    token = _csrf(client)
    resp = client.post("/api/collections", json={
        "name": nama, "kind": kind, "locked": locked,
    }, headers={"X-CSRFToken": token})
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return resp.get_json()["collection"]["id"]


def _pindah(client, collection_id, file_ids, grant=None):
    headers = {"X-CSRFToken": _csrf(client)}
    if grant:
        headers["X-Reauth-Grant"] = grant
    return client.post("/api/collections/move", json={
        "collection_id": collection_id, "file_ids": file_ids,
    }, headers=headers)


def _ubah_state(client, collection_id, file_ids, state, grant=None):
    headers = {"X-CSRFToken": _csrf(client)}
    if grant:
        headers["X-Reauth-Grant"] = grant
    return client.post(f"/api/collections/{collection_id}/items/state", json={
        "file_ids": file_ids, "state": state,
    }, headers=headers)


class TestFolderCrud:
    def test_crud_folder_musik(self, client):
        cid = _buat_koleksi(client, "Koleksi Lagu", "musik")
        with get_db() as db:
            row = db.execute("SELECT * FROM collections WHERE id=?",
                             (cid,)).fetchone()
        assert row["kind"] == "musik"
        assert "Koleksi Lagu" not in row["name_enc"]

        token = _csrf(client)
        resp = client.post(f"/api/collections/{cid}/rename", json={
            "name": "Koleksi Baru",
        }, headers={"X-CSRFToken": token})
        assert resp.status_code == 200

        fid = _buat_berkas(1, "lagu.mp3", ISI_AUDIO)
        assert _pindah(client, cid, [fid]).status_code == 200
        resp = client.post(f"/api/collections/{cid}/delete", json={},
                           headers={"X-CSRFToken": token})
        assert resp.status_code == 200
        with get_db() as db:
            assert db.execute("SELECT COUNT(*) AS n FROM collections").fetchone()["n"] == 0
            assert db.execute(
                "SELECT COUNT(*) AS n FROM collection_items").fetchone()["n"] == 0
            assert db.execute("SELECT COUNT(*) AS n FROM vault_files WHERE id=?",
                              (fid,)).fetchone()["n"] == 1

    def test_crud_folder_dokumen(self, client):
        cid = _buat_koleksi(client, "Arsip", "dokumen")
        fid = _buat_berkas(1, "laporan.pdf", ISI_DOKUMEN)
        assert _pindah(client, cid, [fid]).status_code == 200
        body = client.get("/vault").get_data(as_text=True)
        assert "Arsip" in body
        assert "laporan.pdf" not in body

        data = client.get(f"/api/collections/{cid}/items").get_json()
        assert [i["name"] for i in data["items"]] == ["laporan.pdf"]


class TestIdor:
    def test_pengguna_lain_tidak_dapat_mengubah(self, client, client2):
        cid = _buat_koleksi(client, "Musik Pribadi", "musik")
        fid = _buat_berkas(1, "lagu.mp3", ISI_AUDIO)
        token2 = _csrf(client2, "/musik")

        for url, body in (
            (f"/api/collections/{cid}/rename", {"name": "Bajakan"}),
            (f"/api/collections/{cid}/delete", {}),
        ):
            resp = client2.post(
                url, json=body,
                headers={"X-CSRFToken": token2,
                         "X-Reauth-Grant": _grant(client2, "album.unlock", cid)},
            )
            assert resp.status_code == 404, url

        resp = client2.post("/api/collections/move", json={
            "collection_id": cid, "file_ids": [fid],
        }, headers={"X-CSRFToken": token2})
        assert resp.status_code == 404

        data = client2.get(f"/api/collections/{cid}/items")
        assert data.status_code == 404


class TestPemisahanHalaman:
    def test_audio_hanya_di_musik_dan_dokumen_hanya_dokumen(self, client):
        audio = _buat_berkas(1, "lagu-n3b.mp3", ISI_AUDIO)
        video = _buat_berkas(1, "klip-n3b.mp4", ISI_AUDIO)
        dokumen = _buat_berkas(1, "surat-n3b.pdf", ISI_DOKUMEN)
        foto = _buat_berkas(1, "foto-n3b.png", _png())

        musik = client.get("/musik").get_data(as_text=True)
        media = client.get("/media-vault").get_data(as_text=True)
        vault = client.get("/vault").get_data(as_text=True)
        documents = client.get("/documents").get_data(as_text=True)

        assert "lagu-n3b.mp3" in musik
        assert f'data-file-id="{audio}"' in musik
        assert 'id="music-audio"' in musik

        assert "lagu-n3b.mp3" not in media
        assert f'data-file-id="{audio}"' not in media
        assert "<audio controls" not in media
        assert "klip-n3b.mp4" in media
        assert f'data-file-id="{video}"' in media
        assert f'data-file-id="{foto}"' in media

        assert "surat-n3b.pdf" in vault
        assert "lagu-n3b.mp3" not in vault
        assert "klip-n3b.mp4" not in vault
        assert "foto-n3b.png" not in vault
        assert "surat-n3b.pdf" in documents

    def test_penanda_pencarian_dan_pengurutan(self, client):
        body = client.get("/vault").get_data(as_text=True)
        assert 'id="document-search"' in body
        assert 'id="document-sort"' in body


class TestFolderTerkunci:
    def test_tanpa_grant_isi_tidak_dimuat(self, client):
        cid = _buat_koleksi(client, "Rahasia", "musik", locked=True)
        fid = _buat_berkas(1, "rahasia.mp3", ISI_AUDIO)
        assert _pindah(client, cid, [fid],
                       _grant(client, "album.unlock", cid)).status_code == 200
        reauth.clear()

        body = client.get("/musik").get_data(as_text=True)
        assert "Rahasia" in body
        assert "rahasia.mp3" not in body
        assert f"/media-vault/view/{fid}" not in body

        assert client.get(f"/api/collections/{cid}/items").status_code == 401

        token = _grant(client, "album.unlock", cid)
        data = client.get(
            f"/api/collections/{cid}/items",
            headers={"X-Reauth-Grant": token},
        )
        assert data.status_code == 200
        assert data.get_json()["items"][0]["id"] == fid

    def test_folder_dokumen_terkunci(self, client):
        cid = _buat_koleksi(client, "Arsip Rahasia", "dokumen", locked=True)
        fid = _buat_berkas(1, "rahasia.pdf", ISI_DOKUMEN)
        assert _pindah(client, cid, [fid],
                       _grant(client, "album.unlock", cid)).status_code == 200
        reauth.clear()
        body = client.get("/vault").get_data(as_text=True)
        assert "Arsip Rahasia" in body
        assert "rahasia.pdf" not in body
        assert client.get(f"/api/collections/{cid}/items").status_code == 401


class TestPindahDanTersembunyi:
    def test_pindah_banyak_berkas(self, client):
        cid = _buat_koleksi(client, "Album Musik", "musik")
        a = _buat_berkas(1, "satu.mp3", ISI_AUDIO)
        b = _buat_berkas(1, "dua.mp3", ISI_AUDIO)
        assert _pindah(client, cid, [a, b]).status_code == 200
        with get_db() as db:
            jumlah = db.execute(
                "SELECT COUNT(*) AS n FROM collection_items WHERE collection_id=?",
                (cid,)).fetchone()["n"]
        assert jumlah == 2

        assert _pindah(client, None, [a]).status_code == 200
        with get_db() as db:
            assert db.execute(
                "SELECT COUNT(*) AS n FROM collection_items WHERE file_id=?",
                (a,)).fetchone()["n"] == 0

    def test_hidden_tidak_muncul_di_daftar_biasa(self, client):
        cid = _buat_koleksi(client, "Musik", "musik")
        fid = _buat_berkas(1, "tersembunyi.mp3", ISI_AUDIO)
        _pindah(client, cid, [fid])
        grant = _grant(client, "album.unlock", cid)
        assert _ubah_state(client, cid, [fid], "hidden", grant).status_code == 200

        body = client.get("/musik").get_data(as_text=True)
        assert "tersembunyi.mp3" not in body
        data = client.get(f"/api/collections/{cid}/items").get_json()
        assert data["items"] == []
        assert data["hidden_count"] == 1

        tersembunyi = client.get(
            f"/api/collections/{cid}/hidden",
            headers={"X-Reauth-Grant": _grant(client, "album.unlock", cid)},
        )
        assert tersembunyi.status_code == 200
        assert tersembunyi.get_json()["items"][0]["id"] == fid


class TestUnggahMusik:
    def test_unggah_audio_dari_musik(self, client):
        token = _csrf(client, "/musik")
        resp = client.post("/vault/upload", data={
            "csrf_token": token,
            "kategori": "musik",
            "file": (io.BytesIO(ISI_AUDIO), "unggah-n3b.mp3"),
        }, content_type="multipart/form-data")
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/musik")
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM vault_files WHERE user_id=1 ORDER BY id DESC"
            ).fetchone()
        assert row["file_type"] == "audio"

    def test_unggah_non_audio_dari_musik_ditolak(self, client):
        before = client.get("/musik").get_data(as_text=True)
        assert "bukan-audio.pdf" not in before
        token = _csrf(client, "/musik")
        resp = client.post("/vault/upload", data={
            "csrf_token": token,
            "kategori": "musik",
            "file": (io.BytesIO(ISI_DOKUMEN), "bukan-audio.pdf"),
        }, content_type="multipart/form-data")
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/musik")
        with get_db() as db:
            assert db.execute(
                "SELECT COUNT(*) AS n FROM vault_files WHERE user_id=1"
            ).fetchone()["n"] == 0


class TestDatabaseLama:
    def test_init_db_tanpa_data_koleksi(self, tmp_path, monkeypatch):
        lama = tmp_path / "lama-n3b.db"
        conn = sqlite3.connect(lama)
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
                     "email TEXT, password_hash TEXT, salt TEXT)")
        conn.commit()
        conn.close()

        monkeypatch.setattr(config, "DATABASE_PATH", str(lama))
        init_db()

        conn = sqlite3.connect(lama)
        tabel = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        jumlah = conn.execute("SELECT COUNT(*) FROM collections").fetchone()[0]
        conn.close()
        assert "collections" in tabel
        assert "collection_items" in tabel
        assert jumlah == 0
