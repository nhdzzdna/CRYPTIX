"""
tests/test_l_reauth_plaintext.py
────────────────────────────────
Tes tambahan checklist 5.1 c–d:
  • download media/stego dan extract stego ditolak tanpa grant;
  • hasil ekstraksi steganografi tidak masuk flash maupun cookie sesi.
"""

import io
import re

import numpy as np
import pytest
from PIL import Image

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth
from modules.cryptography import session_keys

DEK = bytes(range(32))


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "l1r.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-tidak-ada.exe"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pengujil1"), (2, "penggunalainl1")):
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


@pytest.fixture()
def client(app):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "pengujil1"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, DEK)
    return c


def _csrf(client, halaman="/steganography") -> str:
    body = client.get(halaman).get_data(as_text=True)
    cocok = re.search(r'name="csrf_token" value="([^"]+)"', body)
    assert cocok, "token CSRF form tidak ditemukan"
    return cocok.group(1)


def _grant(client, scope: str, resource_id=None) -> str:
    with client.session_transaction() as sess:
        sid = sess["session_id"]
    return reauth.issue_grant(sid, scope, resource_id)["token"]


def _gambar_png(ukuran: int = 120) -> bytes:
    arr = np.full((ukuran, ukuran, 3), (12, 90, 200), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="PNG")
    return buf.getvalue()


class TestTanpaGrant:
    def test_download_stego_tanpa_grant_ditolak(self, client):
        resp = client.get("/steganography/download/1")
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"

    def test_extract_stego_tanpa_grant_ditolak(self, client):
        token = _csrf(client)
        resp = client.post(
            "/steganography/extract/1",
            data={"csrf_token": token},
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"

    def test_download_media_tanpa_grant_ditolak(self, client):
        resp = client.get("/media-vault/download/1")
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"


class TestHasilEkstraksiTidakBocor:
    def test_hasil_ekstraksi_tidak_masuk_flash_atau_cookie(self, app, client):
        rahasia = "PESAN-EKSTRAKSI-L1-9f3a"
        token = _csrf(client)
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_gambar_png()), "pembawa.png"),
            "payload_type": "text",
            "message": rahasia,
        }, content_type="multipart/form-data")
        assert resp.status_code == 302

        with get_db() as db:
            row = db.execute(
                "SELECT id FROM stego_images WHERE user_id=1"
            ).fetchone()
        assert row is not None

        token = _csrf(client)
        hasil = client.post(
            f"/steganography/extract/{row['id']}",
            data={
                "csrf_token": token,
                "reauth_grant": _grant(client, "stego.extract", row["id"]),
            },
        )
        assert hasil.status_code == 200
        assert hasil.get_json()["text"] == rahasia

        with client.session_transaction() as sess:
            assert rahasia not in str(dict(sess))
            assert rahasia not in str(sess.get("_flashes", []))

        kue = client.get_cookie("session")
        assert kue is not None
        isi = app.session_interface.get_signing_serializer(app).loads(kue.value)
        assert rahasia not in str(isi)
        assert rahasia not in kue.value
        assert rahasia not in (hasil.headers.get("Set-Cookie") or "")
