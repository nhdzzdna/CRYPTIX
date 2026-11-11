"""
tests/test_u2_kunci_berkas.py
─────────────────────────────
Uji kunci tingkat berkas (U2): item di luar album dapat dikunci dan dilepas
kuncinya, migrasi state koleksi lama tersalin ke ``vault_files.locked``,
endpoint penyaji berkas menolak 403 "terkunci", grant ``item.view`` dan
``item.unlock`` berlaku, serta item di Sampah tetap tidak dapat diakses.
"""

import io
import os

import pytest
from PIL import Image

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth
from modules.cryptography import session_keys
from modules.cryptography.database_encryption import (
    encrypt_field, field_aad,
)
from modules.cryptography.file_encryption import (
    encrypt_stream, file_aad, generate_stored_name,
)
from modules.cryptography.key_management import purpose_key
from modules.strings import MSG

DEK = bytes(range(32))


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (80, 60), (30, 100, 200)).save(buf, format="PNG")
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
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "u2-kunci.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-tidak-ada.exe"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pemiliku2k"), (2, "lainu2k")):
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
    return _client(app, 1, "pemiliku2k")


def _csrf(client) -> str:
    import re
    page = client.get("/media-vault")
    assert page.status_code == 200
    match = re.search(r'name="csrf-token" content="([^"]+)"',
                      page.get_data(as_text=True))
    assert match
    return match.group(1)


def _grant(client, scope: str, resource_id=None) -> str:
    with client.session_transaction() as sess:
        sid = sess["session_id"]
    return reauth.issue_grant(sid, scope, resource_id)["token"]


def _buat_media(user_id: int, nama: str, data: bytes | None = None) -> int:
    data = _png() if data is None else data
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


def _kunci_berkas(client, file_id, state, grant=None):
    headers = {"X-CSRFToken": _csrf(client)}
    if grant:
        headers["X-Reauth-Grant"] = grant
    return client.post(f"/api/media/{file_id}/state", json={
        "state": state,
    }, headers=headers)


def _kunci_koleksi(client, collection_id, file_ids, state, grant=None):
    headers = {"X-CSRFToken": _csrf(client)}
    if grant:
        headers["X-Reauth-Grant"] = grant
    return client.post(f"/api/collections/{collection_id}/items/state", json={
        "file_ids": file_ids, "state": state,
    }, headers=headers)


def _locked(file_id: int) -> int:
    with get_db() as db:
        row = db.execute(
            "SELECT locked FROM vault_files WHERE id=?", (file_id,)
        ).fetchone()
    return row["locked"] if row else None


def _buat_koleksi(client, nama: str, kind: str = "album") -> int:
    resp = client.post("/api/collections", json={
        "name": nama, "kind": kind, "locked": False,
    }, headers={"X-CSRFToken": _csrf(client)})
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return resp.get_json()["collection"]["id"]


def _pindah(client, collection_id, file_ids):
    return client.post("/api/collections/move", json={
        "collection_id": collection_id, "file_ids": file_ids,
    }, headers={"X-CSRFToken": _csrf(client)})


class TestKunciTanpaAlbum:
    def test_kunci_lalu_tampil_dengan_penanda(self, client):
        fid = _buat_media(1, "catatan.png")
        assert _locked(fid) == 0

        resp = _kunci_berkas(client, fid, "locked")
        assert resp.status_code == 200
        assert resp.get_json()["state"] == "locked"
        assert _locked(fid) == 1

        body = client.get("/media-vault").get_data(as_text=True)
        assert f'data-file-id="{fid}"' in body
        assert 'data-locked="1"' in body
        assert "Terkunci" in body

    def test_konten_ditolak_saat_terkunci(self, client):
        fid = _buat_media(1, "rahasia.png")
        assert _kunci_berkas(client, fid, "locked").status_code == 200

        for jalur in (f"/media-vault/view/{fid}",
                      f"/media-vault/thumb/{fid}"):
            resp = client.get(jalur)
            assert resp.status_code == 403, jalur
            assert resp.get_json()["reason"] == "terkunci", jalur
            assert resp.get_json()["error"] == MSG.ITEM_LOCKED

    def test_grant_item_view_membuka_konten(self, client):
        fid = _buat_media(1, "rahasia.png")
        assert _kunci_berkas(client, fid, "locked").status_code == 200
        _grant(client, "item.view", fid)

        resp = client.get(f"/media-vault/view/{fid}")
        assert resp.status_code == 200

    def test_lepas_kunci_perlu_grant_item_unlock(self, client):
        fid = _buat_media(1, "rahasia.png")
        assert _kunci_berkas(client, fid, "locked").status_code == 200

        tanpa = _kunci_berkas(client, fid, "normal")
        assert tanpa.status_code == 401
        assert tanpa.get_json()["reason"] == "missing"
        assert _locked(fid) == 1

        salah_resource = _kunci_berkas(
            client, fid, "normal", _grant(client, "item.unlock", fid + 999),
        )
        assert salah_resource.status_code == 403
        assert salah_resource.get_json()["reason"] == "resource"
        assert _locked(fid) == 1

        sah = _kunci_berkas(
            client, fid, "normal", _grant(client, "item.unlock", fid),
        )
        assert sah.status_code == 200
        assert sah.get_json()["message"] == MSG.ITEM_UNLOCKED
        assert _locked(fid) == 0
        assert client.get(f"/media-vault/view/{fid}").status_code == 200

    def test_berkas_milik_pengguna_lain_ditolak(self, client, app):
        fid = _buat_media(2, "milik-lain.png")
        lain = _client(app, 1, "pemiliku2k")
        resp = _kunci_berkas(lain, fid, "locked")
        assert resp.status_code == 404
        assert resp.get_json()["reason"] == "not_found"
        assert _locked(fid) == 0

    def test_item_dalam_koleksi_memakai_endpoint_koleksi(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "album.png")
        assert _pindah(client, cid, [fid]).status_code == 200

        resp = _kunci_berkas(client, fid, "locked")
        assert resp.status_code == 409
        assert resp.get_json()["reason"] == "in_collection"
        assert _locked(fid) == 0

    def test_state_tidak_dikenal_ditolak(self, client):
        fid = _buat_media(1, "catatan.png")
        resp = _kunci_berkas(client, fid, "hidden")
        assert resp.status_code == 400
        assert resp.get_json()["reason"] == "state"


class TestSinkronKunciKoleksi:
    def test_kunci_koleksi_menyalin_ke_berkas(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "album.png")
        assert _pindah(client, cid, [fid]).status_code == 200

        assert _kunci_koleksi(client, cid, [fid], "locked").status_code == 200
        assert _locked(fid) == 1

        assert _kunci_koleksi(
            client, cid, [fid], "normal",
            _grant(client, "item.unlock", cid),
        ).status_code == 200
        assert _locked(fid) == 0

    def test_migrasi_state_lama_ke_kunci_berkas(self, client):
        cid = _buat_koleksi(client, "Album Lama")
        fid = _buat_media(1, "lama.png")
        assert _pindah(client, cid, [fid]).status_code == 200
        with get_db() as db:
            db.execute(
                "UPDATE collection_items SET state='locked' WHERE file_id=?",
                (fid,),
            )
            db.execute("UPDATE vault_files SET locked=0 WHERE id=?", (fid,))
            db.commit()
        assert _locked(fid) == 0

        init_db()
        assert _locked(fid) == 1
        init_db()
        assert _locked(fid) == 1

    def test_item_terkunci_di_sampah_tetap_tidak_terjangkau(self, client):
        fid = _buat_media(1, "hapus.png")
        assert _kunci_berkas(client, fid, "locked").status_code == 200

        resp = client.post(f"/vault/delete/{fid}",
                           data={"csrf_token": _csrf(client)})
        assert resp.status_code == 302

        assert client.get(f"/media-vault/view/{fid}").status_code == 404
        # Tanpa grant, pengecekan grant berjalan lebih dulu (401).
        assert _kunci_berkas(client, fid, "normal").status_code == 401
        # Dengan grant sah, item di Sampah tidak ditemukan (404).
        assert _kunci_berkas(
            client, fid, "normal", _grant(client, "item.unlock", fid),
        ).status_code == 404
