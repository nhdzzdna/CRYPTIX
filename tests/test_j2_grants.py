"""
tests/test_j2_grants.py
───────────────────────
Uji penerapan autentikasi ulang (step-up) pada Media Vault dan Steganografi:
stream tanpa grant, grant sah, rentang HTTP, pencarian grant aktif untuk
media.stream, penolakan grant resource/sesi lain, grant kedaluwarsa, serta
scope sekali pakai yang tidak dapat dipakai ulang.
"""

import io
import os
import re

import pytest
from PIL import Image
import numpy as np

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth
from modules.cryptography import session_keys
from modules.cryptography.database_encryption import encrypt_field, field_aad
from modules.cryptography.file_encryption import (
    encrypt_stream, file_aad, generate_stored_name,
)
from modules.cryptography.key_management import purpose_key

DEK = bytes(range(32))
ISI = b"ID3" + bytes(range(256)) * 12


def _tipe_berkas(nama: str) -> str:
    ext = os.path.splitext(nama)[1].lower()
    if ext in {".mp3", ".wav", ".flac", ".ogg", ".m4a"}:
        return "audio"
    if ext in {".mp4", ".webm", ".avi", ".mkv", ".mov"}:
        return "video"
    return "document"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "j2.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-tidak-ada.exe"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pengujij2"), (2, "penggunalain")):
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
        sess["username"] = "pengujij2"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, DEK)
    return c


def _csrf(client, halaman: str = "/media-vault") -> str:
    page = client.get(halaman)
    assert page.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True))
    assert match
    return match.group(1)


def _grant(client, scope: str, resource_id=None) -> str:
    with client.session_transaction() as sess:
        sid = sess["session_id"]
    return reauth.issue_grant(sid, scope, resource_id)["token"]


def _grant_sesi_lain(scope: str, resource_id=None) -> str:
    return reauth.issue_grant("sesi-lain-j2", scope, resource_id)["token"]


def _buat_media(user_id: int, nama: str, data: bytes = ISI):
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
            (
                user_id, token, stored_name, _tipe_berkas(nama), len(data),
                hasil["sha256_plaintext"], hasil["sha256_ciphertext"],
            ),
        )
        db.commit()
        return cursor.lastrowid


def _gambar_png(ukuran: int = 120) -> bytes:
    arr = np.full((ukuran, ukuran, 3), (10, 80, 190), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="PNG")
    return buf.getvalue()


def _buat_stego(client) -> int:
    """Sisipkan pesan lewat rute agar baris DB dan berkas PNG konsisten."""
    token = _csrf(client, "/steganography")
    resp = client.post("/steganography/embed", data={
        "csrf_token": token,
        "carrier_image": (io.BytesIO(_gambar_png()), "pembawa.png"),
        "payload_type": "text",
        "message": "pesan uji J2",
    }, content_type="multipart/form-data")
    assert resp.status_code == 302
    with get_db() as db:
        row = db.execute("SELECT id FROM stego_images WHERE user_id=1").fetchone()
    return row["id"]


class TestMediaStreamGrant:
    def test_tanpa_grant_ditolak(self, client):
        file_id = _buat_media(1, "lagu.mp3")
        resp = client.get(f"/media-vault/stream/{file_id}")
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"

    def test_dengan_grant_lolos(self, client):
        file_id = _buat_media(1, "lagu.mp3")
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={"X-Reauth-Grant": _grant(client, "media.stream", file_id)},
        )
        assert resp.status_code == 200
        assert resp.data == ISI

    def test_range_206_dan_416(self, client):
        file_id = _buat_media(1, "lagu.mp3")
        token = _grant(client, "media.stream", file_id)
        ok = client.get(
            f"/media-vault/stream/{file_id}",
            headers={"Range": "bytes=2-9", "X-Reauth-Grant": token},
        )
        assert ok.status_code == 206
        assert ok.data == ISI[2:10]

        salah = client.get(
            f"/media-vault/stream/{file_id}",
            headers={"Range": "bytes=999999-", "X-Reauth-Grant": token},
        )
        assert salah.status_code == 416

    def test_grant_resource_lain_ditolak(self, client):
        file_a = _buat_media(1, "a.mp3")
        file_b = _buat_media(1, "b.mp3")
        resp = client.get(
            f"/media-vault/stream/{file_b}",
            headers={"X-Reauth-Grant": _grant(client, "media.stream", file_a)},
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "resource"

    def test_grant_sesi_lain_ditolak(self, client):
        file_id = _buat_media(1, "lagu.mp3")
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={"X-Reauth-Grant": _grant_sesi_lain("media.stream", file_id)},
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "session"

    def test_grant_kedaluwarsa_ditolak(self, client, monkeypatch):
        file_id = _buat_media(1, "lagu.mp3")
        token = _grant(client, "media.stream", file_id)
        sekarang = reauth._now()
        monkeypatch.setattr(reauth, "_now", lambda: sekarang + 901)
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "expired"

    def test_grant_aktif_ditemukan_tanpa_header(self, client):
        file_id = _buat_media(1, "lagu.mp3")
        _grant(client, "media.stream", file_id)
        resp = client.get(f"/media-vault/stream/{file_id}")
        assert resp.status_code == 200
        assert resp.data == ISI

        # Grant berulang tetap terikat resource: resource lain tidak lolos.
        lain = _buat_media(1, "lain.mp3")
        resp = client.get(f"/media-vault/stream/{lain}")
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"

    def test_grant_aktif_sesi_lain_tidak_ditemukan(self, client):
        file_id = _buat_media(1, "lagu.mp3")
        _grant_sesi_lain("media.stream", file_id)
        resp = client.get(f"/media-vault/stream/{file_id}")
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"


class TestScopeSekaliPakai:
    def test_stego_extract_tidak_dapat_dipakai_ulang(self, client):
        img_id = _buat_stego(client)
        token = _grant(client, "stego.extract", img_id)
        csrf = _csrf(client, "/steganography")
        pertama = client.post(
            f"/steganography/extract/{img_id}",
            data={"csrf_token": csrf, "reauth_grant": token},
        )
        assert pertama.status_code == 200
        kedua = client.post(
            f"/steganography/extract/{img_id}",
            data={"csrf_token": csrf, "reauth_grant": token},
        )
        assert kedua.status_code == 401
        assert kedua.get_json()["reason"] == "invalid"

    def test_stego_download_tidak_dapat_dipakai_ulang(self, client):
        img_id = _buat_stego(client)
        token = _grant(client, "stego.download", img_id)
        pertama = client.get(
            f"/steganography/download/{img_id}",
            headers={"X-Reauth-Grant": token},
        )
        assert pertama.status_code == 200
        kedua = client.get(
            f"/steganography/download/{img_id}",
            headers={"X-Reauth-Grant": token},
        )
        assert kedua.status_code == 401
        assert kedua.get_json()["reason"] == "invalid"

    def test_media_winamp_tidak_dapat_dipakai_ulang(self, client):
        file_id = _buat_media(1, "lagu.mp3")
        token = _grant(client, "media.winamp", file_id)
        csrf = _csrf(client)
        pertama = client.post(
            f"/media-vault/play/{file_id}",
            data={"csrf_token": csrf, "reauth_grant": token, "player": "html5"},
        )
        assert pertama.status_code == 302
        kedua = client.post(
            f"/media-vault/play/{file_id}",
            data={"csrf_token": csrf, "reauth_grant": token, "player": "html5"},
        )
        assert kedua.status_code == 401
        assert kedua.get_json()["reason"] == "invalid"

    def test_file_download_tidak_dapat_dipakai_ulang(self, client):
        file_id = _buat_media(1, "lagu.mp3")
        token = _grant(client, "file.download", file_id)
        pertama = client.get(
            f"/media-vault/download/{file_id}",
            headers={"X-Reauth-Grant": token},
        )
        assert pertama.status_code == 200
        assert pertama.data == ISI
        assert "attachment" in pertama.headers["Content-Disposition"]
        kedua = client.get(
            f"/media-vault/download/{file_id}",
            headers={"X-Reauth-Grant": token},
        )
        assert kedua.status_code == 401
        assert kedua.get_json()["reason"] == "invalid"
