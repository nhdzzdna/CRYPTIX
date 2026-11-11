"""
tests/test_ub_kunci.py
──────────────────────
Uji fitur kunci item dan kunci album/folder (UB):
migrasi state 'hidden' lama ke 'locked', mengunci tanpa grant, item terkunci
tetap tampil dengan penanda, penolakan 403 JSON "terkunci" pada seluruh
endpoint penyaji berkas, grant ``item.view`` berulang, grant ``item.unlock``
sekali pakai dengan resource id koleksi, bagian "Semua" yang mengecualikan
isi album terkunci, serta interaksi dengan item di Sampah.
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
ISI_AUDIO = b"ID3" + bytes(range(256)) * 4


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
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "ub-kunci.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-tidak-ada.exe"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pemilikubk"), (2, "lainubk")):
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
    return _client(app, 1, "pemilikubk")


@pytest.fixture()
def client2(app):
    return _client(app, 2, "lainubk")


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


def _buat_koleksi(client, nama: str, kind: str = "album",
                  locked: bool = False) -> int:
    resp = client.post("/api/collections", json={
        "name": nama, "kind": kind, "locked": locked,
    }, headers={"X-CSRFToken": _csrf(client)})
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


def _state_item(file_id: int) -> str:
    with get_db() as db:
        row = db.execute(
            "SELECT state FROM collection_items WHERE file_id=?", (file_id,)
        ).fetchone()
    return row["state"] if row else None


# ── Migrasi state item lama ──────────────────────────────────────────────────


class TestMigrasiStateItem:
    def test_hidden_lama_menjadi_locked_idempoten(self, client):
        cid = _buat_koleksi(client, "Album Lama")
        fid = _buat_media(1, "lama.mp3")
        assert _pindah(client, cid, [fid]).status_code == 200
        with get_db() as db:
            db.execute(
                "UPDATE collection_items SET state='hidden' WHERE file_id=?",
                (fid,),
            )
            db.commit()
        assert _state_item(fid) == "hidden"

        init_db()
        assert _state_item(fid) == "locked"
        # Migrasi kedua tidak mengubah apa pun dan tidak galat.
        init_db()
        assert _state_item(fid) == "locked"

    def test_state_hidden_tidak_sah_lagi(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "lagu.mp3")
        _pindah(client, cid, [fid])
        for state in ("hidden", "bogus"):
            resp = _ubah_state(client, cid, [fid], state)
            assert resp.status_code == 400, state
            assert resp.get_json()["reason"] == "state"
        assert _state_item(fid) == "normal"


# ── Semantik kunci item ──────────────────────────────────────────────────────


class TestKunciItem:
    def test_mengunci_tidak_perlu_grant(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "foto.png", _png())
        _pindah(client, cid, [fid])

        resp = _ubah_state(client, cid, [fid], "locked")
        assert resp.status_code == 200
        assert resp.get_json()["message"] == MSG.COLLECTION_STATE_CHANGED
        assert _state_item(fid) == "locked"

    def test_item_bukan_anggota_ditolak(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "luar.mp3")
        # fid tidak dipindahkan ke album ini.
        assert _ubah_state(client, cid, [fid], "locked").status_code == 404
        # Koleksi tidak ada.
        assert _ubah_state(client, 9999, [fid], "locked").status_code == 404

    def test_item_terkunci_tetap_tampil_dengan_penanda(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "foto.png", _png())
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        body = client.get("/media-vault").get_data(as_text=True)
        assert f'data-file-id="{fid}"' in body
        assert 'data-locked="1"' in body
        assert "item-terkunci" in body
        assert "Terkunci" in body

        data = client.get(f"/api/collections/{cid}/items").get_json()
        assert data["items"][0]["id"] == fid
        assert data["items"][0]["state"] == "locked"
        assert "hidden_count" not in data

        # Endpoint daftar item tersembunyi lama sudah dihapus total.
        resp = client.get(f"/api/collections/{cid}/hidden",
                          headers={"X-Reauth-Grant": _grant(
                              client, "album.unlock", cid)})
        assert resp.status_code == 404


# ── Penolakan endpoint saat item terkunci ─────────────────────────────────────


class TestEndpointTerkunci:
    def test_view_dan_thumb_ditolak(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "foto.png", _png())
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        for url in (f"/media-vault/view/{fid}", f"/media-vault/thumb/{fid}"):
            resp = client.get(url)
            assert resp.status_code == 403, url
            assert resp.get_json()["reason"] == "terkunci"
            assert resp.get_json()["error"] == MSG.ITEM_LOCKED

    def test_stream_ditolak_walau_grant_stream(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "lagu.mp3")
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        resp = client.get(
            f"/media-vault/stream/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "media.stream", fid)},
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "terkunci"

    def test_play_ditolak_walau_grant_winamp(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "lagu.mp3")
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        resp = client.post(
            f"/media-vault/play/{fid}",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": _grant(client, "media.winamp", fid),
                "player": "html5",
            },
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "terkunci"

    def test_download_dan_decrypt_ditolak_walau_grant(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "lagu.mp3")
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        unduh = client.get(
            f"/media-vault/download/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "file.download", fid)},
        )
        assert unduh.status_code == 403
        assert unduh.get_json()["reason"] == "terkunci"

        buka = client.post(
            f"/vault/decrypt/{fid}",
            data={"csrf_token": _csrf(client)},
            headers={"X-Reauth-Grant": _grant(client, "file.download", fid)},
        )
        assert buka.status_code == 403
        assert buka.get_json()["reason"] == "terkunci"

    def test_item_view_membuka_seluruh_endpoint(self, client):
        cid = _buat_koleksi(client, "Album")
        foto = _buat_media(1, "foto.png", _png())
        lagu = _buat_media(1, "lagu.mp3")
        _pindah(client, cid, [foto, lagu])
        assert _ubah_state(client, cid, [foto, lagu], "locked").status_code == 200

        # Grant item.view berulang aktif di sesi tanpa header.
        _grant(client, "item.view", foto)
        _grant(client, "item.view", lagu)

        assert client.get(f"/media-vault/view/{foto}").data == _png()
        assert client.get(f"/media-vault/thumb/{foto}").status_code == 200
        assert client.get(
            f"/media-vault/stream/{lagu}",
            headers={"X-Reauth-Grant": _grant(client, "media.stream", lagu)},
        ).status_code == 200
        assert client.get(
            f"/media-vault/download/{lagu}",
            headers={"X-Reauth-Grant": _grant(client, "file.download", lagu)},
        ).status_code == 200
        assert client.post(
            f"/media-vault/play/{lagu}",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": _grant(client, "media.winamp", lagu),
                "player": "html5",
            },
        ).status_code == 302
        assert client.post(
            f"/vault/decrypt/{lagu}",
            data={"csrf_token": _csrf(client)},
            headers={"X-Reauth-Grant": _grant(client, "file.download", lagu)},
        ).status_code == 200


# ── Grant item.view berulang ─────────────────────────────────────────────────


class TestItemViewGrant:
    def test_reusable_lalu_kedaluwarsa(self, client, monkeypatch):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "foto.png", _png())
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        sekarang = reauth._now()
        _grant(client, "item.view", fid)
        for _ in range(3):
            resp = client.get(f"/media-vault/view/{fid}")
            assert resp.status_code == 200

        monkeypatch.setattr(reauth, "_now", lambda: sekarang + 901)
        resp = client.get(f"/media-vault/view/{fid}")
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "terkunci"

    def test_resource_harus_berkas(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "foto.png", _png())
        fid_lain = _buat_media(1, "lain.png", _png())
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        # Grant untuk berkas lain tidak membuka berkas ini.
        _grant(client, "item.view", fid_lain)
        resp = client.get(f"/media-vault/view/{fid}")
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "terkunci"


# ── Grant item.unlock sekali pakai ────────────────────────────────────────────


class TestItemUnlockGrant:
    def test_tanpa_grant_ditolak(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "lagu.mp3")
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        resp = _ubah_state(client, cid, [fid], "normal")
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"

    def test_salah_scope_ditolak(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "lagu.mp3")
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        resp = _ubah_state(client, cid, [fid], "normal",
                           _grant(client, "item.view", fid))
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "scope"

    def test_resource_adalah_id_koleksi(self, client):
        # Pengisi agar id koleksi dan id berkas tidak beririsan.
        _buat_koleksi(client, "Pengisi")
        cid = _buat_koleksi(client, "Album")
        cid_lain = _buat_koleksi(client, "Lainnya")
        fid = _buat_media(1, "lagu.mp3")
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        # resource id berkas tidak sah: grant terikat koleksi.
        resp = _ubah_state(client, cid, [fid], "normal",
                           _grant(client, "item.unlock", fid))
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "resource"

        # grant untuk koleksi lain juga tidak sah.
        resp = _ubah_state(client, cid, [fid], "normal",
                           _grant(client, "item.unlock", cid_lain))
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "resource"

    def test_sekali_pakai_dan_state_normal(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "foto.png", _png())
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        grant = _grant(client, "item.unlock", cid)
        resp = _ubah_state(client, cid, [fid], "normal", grant)
        assert resp.status_code == 200
        assert resp.get_json()["message"] == MSG.ITEM_UNLOCKED
        assert _state_item(fid) == "normal"

        body = client.get("/media-vault").get_data(as_text=True)
        assert f'data-file-id="{fid}"' in body
        assert 'data-locked="0"' in body

        # Token sekali pakai sudah hangus setelah dipakai.
        ulang = _ubah_state(client, cid, [fid], "normal", grant)
        assert ulang.status_code == 401
        assert ulang.get_json()["reason"] == "invalid"


# ── Bagian "Semua" vs album/folder terkunci ───────────────────────────────────


class TestSemua:
    def test_mengecualikan_isi_album_terkunci(self, client):
        cid = _buat_koleksi(client, "Rahasia", locked=True)
        fid = _buat_media(1, "foto.png", _png())
        assert _pindah(client, cid, [fid],
                      _grant(client, "album.unlock", cid)).status_code == 200
        reauth.clear()

        body = client.get("/media-vault").get_data(as_text=True)
        assert "Rahasia" in body
        assert f'data-file-id="{fid}"' not in body
        assert f"/media-vault/thumb/{fid}" not in body
        assert f"/media-vault/view/{fid}" not in body

        assert client.get(f"/api/collections/{cid}/items").status_code == 401

    def test_menyertakan_saat_grant_aktif(self, client):
        cid = _buat_koleksi(client, "Rahasia", locked=True)
        fid = _buat_media(1, "foto.png", _png())
        assert _pindah(client, cid, [fid],
                      _grant(client, "album.unlock", cid)).status_code == 200
        reauth.clear()

        _grant(client, "album.unlock", cid)
        body = client.get("/media-vault").get_data(as_text=True)
        assert f'data-file-id="{fid}"' in body

    def test_folder_musik_terkunci(self, client):
        cid = _buat_koleksi(client, "Rahasia", "musik", locked=True)
        fid = _buat_media(1, "rahasia.mp3")
        assert _pindah(client, cid, [fid],
                      _grant(client, "album.unlock", cid)).status_code == 200
        reauth.clear()

        body = client.get("/audio").get_data(as_text=True)
        assert "Rahasia" in body
        assert f'data-file-id="{fid}"' not in body

        _grant(client, "album.unlock", cid)
        body = client.get("/audio").get_data(as_text=True)
        assert f'data-file-id="{fid}"' in body

    def test_folder_dokumen_terkunci(self, client):
        cid = _buat_koleksi(client, "Arsip Rahasia", "dokumen", locked=True)
        fid = _buat_media(1, "rahasia.pdf", b"%PDF-1.4 rahasia")
        assert _pindah(client, cid, [fid],
                      _grant(client, "album.unlock", cid)).status_code == 200
        reauth.clear()

        body = client.get("/vault").get_data(as_text=True)
        assert "Arsip Rahasia" in body
        assert f'data-file-id="{fid}"' not in body

        _grant(client, "album.unlock", cid)
        body = client.get("/vault").get_data(as_text=True)
        assert f'data-file-id="{fid}"' in body


# ── Interaksi dengan Sampah (Bagian 1 tetap bekerja) ──────────────────────────


class TestSampah:
    def test_item_terkunci_di_sampah_tidak_dapat_diakses(self, client):
        cid = _buat_koleksi(client, "Album")
        fid = _buat_media(1, "foto.png", _png())
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        resp = client.post(f"/vault/delete/{fid}",
                           data={"csrf_token": _csrf(client)})
        assert resp.status_code == 302

        # Filter deleted_at lebih dulu: bukan 403 terkunci.
        assert client.get(f"/media-vault/view/{fid}").status_code == 404
        assert client.get(f"/media-vault/thumb/{fid}").status_code == 404
        # Walau grant item.unlock sah, item di sampah bukan anggota koleksi.
        assert _ubah_state(client, cid, [fid], "normal",
                           _grant(client, "item.unlock", cid)).status_code == 404

        body = client.get("/media-vault").get_data(as_text=True)
        assert f'data-file-id="{fid}"' not in body

    def test_item_di_sampah_walau_grant_ada(self, client):
        cid = _buat_koleksi(client, "Rahasia", locked=True)
        fid = _buat_media(1, "foto.png", _png())
        assert _pindah(client, cid, [fid],
                      _grant(client, "album.unlock", cid)).status_code == 200
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        resp = client.post(f"/vault/delete/{fid}",
                           data={"csrf_token": _csrf(client)})
        assert resp.status_code == 302

        # Grant album.unlock dan item.view aktif pun tidak memulihkan akses.
        _grant(client, "album.unlock", cid)
        _grant(client, "item.view", fid)
        assert client.get(f"/media-vault/view/{fid}").status_code == 404
