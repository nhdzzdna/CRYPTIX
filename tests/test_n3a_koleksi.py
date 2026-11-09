"""
tests/test_n3a_koleksi.py
─────────────────────────
Uji koleksi/album Media Vault: CRUD, IDOR antar pengguna, nama terenkripsi,
pemindahan banyak berkas, ganti nama berkas, album terkunci, grant
album.unlock berulang dan kedaluwarsa, HTTP Range pratinjau, item
tersembunyi, serta init_db pada basis data lama.
"""

import io
import os
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
ISI_AUDIO = b"ID3" + bytes(range(256)) * 8


def _tipe_berkas(nama: str) -> str:
    ext = os.path.splitext(nama)[1].lower()
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}:
        return "image"
    if ext in {".mp3", ".wav", ".flac", ".ogg", ".m4a"}:
        return "audio"
    if ext in {".mp4", ".webm", ".avi", ".mkv", ".mov"}:
        return "video"
    return "document"


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (120, 90), (20, 90, 180)).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "n3a.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-tidak-ada.exe"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pemilikn3a"), (2, "lainn3a")):
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
    return _client(app, 1, "pemilikn3a")


@pytest.fixture()
def client2(app):
    return _client(app, 2, "lainn3a")


def _csrf(client) -> str:
    page = client.get("/media-vault")
    assert page.status_code == 200
    import re
    match = re.search(r'name="csrf-token" content="([^"]+)"',
                      page.get_data(as_text=True))
    assert match
    return match.group(1)


def _grant(client, scope: str, resource_id=None) -> str:
    with client.session_transaction() as sess:
        sid = sess["session_id"]
    return reauth.issue_grant(sid, scope, resource_id)["token"]


def _buat_media(user_id: int, nama: str, data: bytes = ISI_AUDIO) -> int:
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


def _nama_berkas(file_id: int, user_id: int = 1) -> str:
    with get_db() as db:
        row = db.execute("SELECT * FROM vault_files WHERE id=?",
                         (file_id,)).fetchone()
    return decrypt_field(
        row["original_name"], purpose_key(DEK, "database"),
        field_aad(user_id, "vault_files", "original_name"),
    )


def _buat_koleksi(client, nama: str, locked: bool = False):
    token = _csrf(client)
    resp = client.post("/api/collections", json={
        "name": nama, "kind": "album", "locked": locked,
    }, headers={"X-CSRFToken": token})
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return resp.get_json()["collection"]["id"]


def _pindah(client, collection_id, file_ids, grant=None):
    token = _csrf(client)
    headers = {"X-CSRFToken": token}
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


class TestKoleksiCrud:
    def test_buat_ganti_nama_hapus(self, client):
        cid = _buat_koleksi(client, "Liburan")
        with get_db() as db:
            row = db.execute("SELECT * FROM collections WHERE id=?", (cid,)).fetchone()
        assert row["name_enc"].startswith("v1:")
        assert "Liburan" not in row["name_enc"]

        token = _csrf(client)
        resp = client.post(f"/api/collections/{cid}/rename", json={
            "name": "Liburan Baru",
        }, headers={"X-CSRFToken": token})
        assert resp.status_code == 200
        with get_db() as db:
            row = db.execute("SELECT * FROM collections WHERE id=?", (cid,)).fetchone()
        nama = decrypt_field(
            row["name_enc"], purpose_key(DEK, "database"),
            field_aad(1, "collections", "name_enc"),
        )
        assert nama == "Liburan Baru"

        fid = _buat_media(1, "foto.png", _png())
        assert _pindah(client, cid, [fid]).status_code == 200
        resp = client.post(f"/api/collections/{cid}/delete", json={},
                           headers={"X-CSRFToken": token})
        assert resp.status_code == 200
        with get_db() as db:
            assert db.execute("SELECT COUNT(*) AS n FROM collections").fetchone()["n"] == 0
            assert db.execute(
                "SELECT COUNT(*) AS n FROM collection_items").fetchone()["n"] == 0
            assert db.execute(
                "SELECT COUNT(*) AS n FROM vault_files WHERE id=?",
                (fid,)).fetchone()["n"] == 1


class TestIdor:
    def test_pengguna_lain_tidak_dapat_mengubah(self, client, client2):
        cid = _buat_koleksi(client, "Pribadi")
        fid = _buat_media(1, "lagu.mp3")
        token2 = _csrf(client2)

        for url, body in (
            (f"/api/collections/{cid}/rename", {"name": "Bajakan"}),
            (f"/api/collections/{cid}/delete", {}),
            (f"/api/collections/{cid}/lock", {"locked": 0}),
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

        resp = client2.get(f"/media-vault/view/{fid}")
        assert resp.status_code == 404


class TestPindahDanGantiNama:
    def test_pindah_banyak_dan_kembali_tanpa_album(self, client):
        cid = _buat_koleksi(client, "Kumpulan")
        a = _buat_media(1, "a.mp3")
        b = _buat_media(1, "b.mp3")
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

    def test_ganti_nama_berkas_tersimpan_terenkripsi(self, client):
        fid = _buat_media(1, "lama.mp3")
        token = _csrf(client)
        resp = client.post(f"/api/media/{fid}/rename", json={
            "name": "baru.mp3",
        }, headers={"X-CSRFToken": token})
        assert resp.status_code == 200
        assert _nama_berkas(fid) == "baru.mp3"
        with get_db() as db:
            row = db.execute("SELECT original_name FROM vault_files WHERE id=?",
                             (fid,)).fetchone()
        assert "baru.mp3" not in row["original_name"]


class TestAlbumTerkunci:
    def test_thumbnail_tidak_bocor_di_html(self, client):
        cid = _buat_koleksi(client, "Rahasia", locked=True)
        fid = _buat_media(1, "foto.png", _png())
        assert _pindah(client, cid, [fid],
                       _grant(client, "album.unlock", cid)).status_code == 200

        body = client.get("/media-vault").get_data(as_text=True)
        assert f"/media-vault/thumb/{fid}" not in body
        assert f"/media-vault/view/{fid}" not in body

    def test_tanpa_grant_ditolak(self, client):
        cid = _buat_koleksi(client, "Rahasia", locked=True)
        fid = _buat_media(1, "foto.png", _png())
        _pindah(client, cid, [fid], _grant(client, "album.unlock", cid))
        reauth.clear()

        assert client.get(f"/api/collections/{cid}/items").status_code == 401
        assert client.get(f"/media-vault/view/{fid}").status_code == 403
        assert client.get(f"/media-vault/thumb/{fid}").status_code == 403
        assert _ubah_state(client, cid, [fid], "hidden").status_code == 401
        assert client.post(f"/api/collections/{cid}/lock", json={"locked": 0},
                           headers={"X-CSRFToken": _csrf(client)}).status_code == 401

    def test_grant_berulang_lalu_kedaluwarsa(self, client, monkeypatch):
        cid = _buat_koleksi(client, "Rahasia", locked=True)
        fid = _buat_media(1, "foto.png", _png())
        _pindah(client, cid, [fid], _grant(client, "album.unlock", cid))
        reauth.clear()
        token = _grant(client, "album.unlock", cid)

        for _ in range(2):
            resp = client.get(
                f"/api/collections/{cid}/items",
                headers={"X-Reauth-Grant": token},
            )
            assert resp.status_code == 200

        sekarang = reauth._now()
        monkeypatch.setattr(reauth, "_now", lambda: sekarang + 901)
        resp = client.get(
            f"/api/collections/{cid}/items",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "expired"

    def test_view_memakai_grant_album(self, client):
        cid = _buat_koleksi(client, "Rahasia", locked=True)
        fid = _buat_media(1, "foto.png", _png())
        _pindah(client, cid, [fid], _grant(client, "album.unlock", cid))
        reauth.clear()
        token = _grant(client, "album.unlock", cid)
        resp = client.get(f"/media-vault/view/{fid}",
                          headers={"X-Reauth-Grant": token})
        assert resp.status_code == 200
        assert resp.data == _png()


class TestPratinjauRange:
    def test_range_206_dan_416(self, client):
        fid = _buat_media(1, "lagu.mp3")
        ok = client.get(f"/media-vault/view/{fid}",
                        headers={"Range": "bytes=2-9"})
        assert ok.status_code == 206
        assert ok.data == ISI_AUDIO[2:10]
        assert ok.headers["Content-Range"] == f"bytes 2-9/{len(ISI_AUDIO)}"
        assert "no-store" in ok.headers["Cache-Control"]

        salah = client.get(f"/media-vault/view/{fid}",
                           headers={"Range": "bytes=999999-"})
        assert salah.status_code == 416
        assert salah.headers["Content-Range"] == f"bytes */{len(ISI_AUDIO)}"


class TestTersembunyi:
    def test_hidden_tidak_muncul_di_daftar_biasa(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "lagu.mp3")
        _pindah(client, cid, [fid])
        grant = _grant(client, "album.unlock", cid)
        assert _ubah_state(client, cid, [fid], "hidden", grant).status_code == 200

        body = client.get("/media-vault").get_data(as_text=True)
        assert f'data-file-id="{fid}"' not in body

        data = client.get(f"/api/collections/{cid}/items").get_json()
        assert data["items"] == []
        assert data["hidden_count"] == 1

        reauth.clear()
        assert client.get(f"/media-vault/view/{fid}").status_code == 403
        grant = _grant(client, "album.unlock", cid)
        tersembunyi = client.get(
            f"/api/collections/{cid}/hidden",
            headers={"X-Reauth-Grant": grant},
        )
        assert tersembunyi.status_code == 200
        assert tersembunyi.get_json()["items"][0]["id"] == fid
        assert client.get(f"/media-vault/view/{fid}",
                          headers={"X-Reauth-Grant": grant}).status_code == 200


class TestDatabaseLama:
    def test_init_db_membuat_tabel_baru(self, tmp_path, monkeypatch):
        lama = tmp_path / "lama.db"
        conn = sqlite3.connect(lama)
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
                     "email TEXT, password_hash TEXT, salt TEXT)")
        conn.execute("INSERT INTO users (id, username, email, password_hash, salt) "
                     "VALUES (1,'lama','lama@contoh.test','h','g')")
        conn.commit()
        conn.close()

        monkeypatch.setattr(config, "DATABASE_PATH", str(lama))
        init_db()

        conn = sqlite3.connect(lama)
        tabel = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        assert "collections" in tabel
        assert "collection_items" in tabel
