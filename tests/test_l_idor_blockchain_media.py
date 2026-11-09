"""
tests/test_l_idor_blockchain_media.py
Uji IDOR pada semua rute ber-id dan penandaan media yang hanya dapat diunduh.
"""

import io
import os
import re

import pytest

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
from modules.strings import MSG
from routes.media_routes import is_playable, mime_for

DEK = bytes(range(32))

RUTE_IDOR = [
    ("POST", "/account-vault/reveal/{id}", "account.reveal", "account_vault", "akun"),
    ("POST", "/account-vault/edit/{id}", "account.reveal", "account_vault", "akun"),
    ("POST", "/account-vault/delete/{id}", "item.delete", "account_vault", "akun"),
    ("POST", "/secure-notes/open/{id}", "note.open", "secure_notes", "catatan"),
    ("POST", "/secure-notes/edit/{id}", "note.edit", "secure_notes", "catatan"),
    ("POST", "/secure-notes/delete/{id}", "item.delete", "secure_notes", "catatan"),
    ("POST", "/vault/decrypt/{id}", "file.download", "vault_files", "berkas"),
    ("POST", "/vault/delete/{id}", "item.delete", "vault_files", "berkas"),
    ("GET", "/media-vault/stream/{id}", "media.stream", "vault_files", "berkas"),
    ("POST", "/media-vault/play/{id}", "media.winamp", "vault_files", "berkas"),
    ("GET", "/media-vault/download/{id}", "file.download", "vault_files", "berkas"),
    ("POST", "/steganography/extract/{id}", "stego.extract", "stego_images", "stego"),
    ("GET", "/steganography/download/{id}", "stego.download", "stego_images", "stego"),
    ("POST", "/steganography/delete/{id}", None, "stego_images", "stego"),
]


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "l2.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pengujansatu"), (2, "pengujandua")):
            db.execute(
                """INSERT INTO users
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
        sess["username"] = "pengujansatu"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, DEK)
    return c


@pytest.fixture()
def milik_b():
    """Satu baris milik pengguna 2 pada tiap tabel ber-id."""
    with get_db() as db:
        akun = db.execute(
            """INSERT INTO account_vault
               (user_id, site_name_enc, username_enc, password_enc)
               VALUES (?,?,?,?)""",
            (2, "v1:aa:bb", "v1:cc:dd", "v1:ee:ff"),
        ).lastrowid
        catatan = db.execute(
            """INSERT INTO secure_notes (user_id, title_enc, content_enc)
               VALUES (?,?,?)""",
            (2, "v1:11:22", "v1:33:44"),
        ).lastrowid
        berkas = db.execute(
            """INSERT INTO vault_files
               (user_id, original_name, stored_name, file_type, file_size,
                sha256_hash, sha256_ciphertext)
               VALUES (?,?,?,?,?,?,?)""",
            (2, "v1:55:66", "b-rahasia.bin", "audio", 32, "a" * 64, "b" * 64),
        ).lastrowid
        stego = db.execute(
            """INSERT INTO stego_images
               (user_id, original_name, stored_name, has_encryption)
               VALUES (?,?,?,?)""",
            (2, "v1:77:88", "b-stego.png", 1),
        ).lastrowid
        db.commit()
    return {"akun": akun, "catatan": catatan, "berkas": berkas, "stego": stego}


def _baris(tabel: str, resource_id: int) -> dict:
    with get_db() as db:
        row = db.execute(
            f"SELECT * FROM {tabel} WHERE id=?", (resource_id,)
        ).fetchone()
    assert row is not None
    return dict(row)


def _csrf(client) -> str:
    page = client.get("/media-vault")
    assert page.status_code == 200
    match = re.search(
        r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)
    )
    assert match, "token CSRF tidak ditemukan"
    return match.group(1)


def _grant(client, scope: str, resource_id) -> str:
    with client.session_transaction() as sess:
        sid = sess["session_id"]
    return reauth.issue_grant(sid, scope, resource_id)["token"]


def _kirim(client, metode: str, url: str, scope, resource_id) -> object:
    headers = {}
    if scope is not None:
        headers["X-Reauth-Grant"] = _grant(client, scope, resource_id)
    data = {
        "site_name": "Dibajak", "username": "penyusup",
        "password": "sandi-penyusup", "title": "Dibajak",
        "content": "Isi bajakan",
    }
    if metode == "POST":
        headers["X-CSRFToken"] = _csrf(client)
        return client.post(url, data=data, headers=headers)
    return client.get(url, headers=headers)


class TestIdorSemuaRuteBerId:
    @pytest.mark.parametrize("metode,rute,scope,tabel,kunci", RUTE_IDOR)
    def test_pengguna_a_ditolak_pada_sumber_daya_b(
        self, client, milik_b, metode, rute, scope, tabel, kunci
    ):
        resource_id = milik_b[kunci]
        sebelum = _baris(tabel, resource_id)
        resp = _kirim(
            client, metode, rute.format(id=resource_id), scope, resource_id
        )
        assert resp.status_code in (403, 404)
        assert _baris(tabel, resource_id) == sebelum


def _buat_media(nama: str) -> int:
    stored_name = generate_stored_name()
    os.makedirs(config.ENCRYPTED_FILES_DIR, exist_ok=True)
    path = os.path.join(config.ENCRYPTED_FILES_DIR, stored_name)
    isi = b"media-uji-" + nama.encode("utf-8")
    hasil = encrypt_stream(
        io.BytesIO(isi), path,
        purpose_key(DEK, "file"), file_aad(1, stored_name),
    )
    token = encrypt_field(
        nama, purpose_key(DEK, "database"),
        field_aad(1, "vault_files", "original_name"),
    )
    with get_db() as db:
        cursor = db.execute(
            """INSERT INTO vault_files
               (user_id, original_name, stored_name, file_type, file_size,
                sha256_hash, sha256_ciphertext)
               VALUES (?,?,?,?,?,?,?)""",
            (
                1, token, stored_name, "video", len(isi),
                hasil["sha256_plaintext"], hasil["sha256_ciphertext"],
            ),
        )
        db.commit()
        return cursor.lastrowid


class TestMediaUnduhSaja:
    @pytest.mark.parametrize("nama", ["video.avi", "video.mkv", "video.mov"])
    def test_ditandai_tidak_dapat_diputar(self, client, nama):
        _buat_media(nama)
        body = client.get("/media-vault").get_data(as_text=True)
        assert MSG.MEDIA_DOWNLOAD_ONLY in body
        assert "data-stream-url" not in body

    @pytest.mark.parametrize("nama,mime", [
        ("video.avi", "video/x-msvideo"),
        ("video.mkv", "video/x-matroska"),
        ("video.mov", "video/quicktime"),
    ])
    def test_mime_dan_status_putar(self, nama, mime):
        assert mime_for(nama) == mime
        assert is_playable(nama) is False
