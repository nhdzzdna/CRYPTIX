"""
tests/test_u2_nama_media.py
───────────────────────────
Uji tampilan nama asli media (U2): nama berkas didekripsi di server dan
ditampilkan pada daftar, sedangkan token yang gagal dibuka memakai nama
penyimpanan ringkas tanpa membocorkan token mentah.
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

DEK = bytes(range(32))


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (40, 30), (20, 120, 80)).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "u2-nama.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-tidak-ada.exe"))
    init_db()
    with get_db() as db:
        db.execute(
            """INSERT OR IGNORE INTO users
               (id, username, email, password_hash, salt) VALUES (?,?,?,?,?)""",
            (1, "pemiliku2n", "pemiliku2n@contoh.test", "hash", "garam"),
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
        sess["username"] = "pemiliku2n"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, DEK)
    return c


def _buat_media(nama: str) -> tuple[int, str]:
    data = _png()
    stored_name = generate_stored_name()
    path = os.path.join(config.ENCRYPTED_FILES_DIR, stored_name)
    os.makedirs(config.ENCRYPTED_FILES_DIR, exist_ok=True)
    hasil = encrypt_stream(
        io.BytesIO(data), path,
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
            (1, token, stored_name, "image", len(data),
             hasil["sha256_plaintext"], hasil["sha256_ciphertext"]),
        )
        db.commit()
        return cursor.lastrowid, stored_name


class TestNamaAsliMedia:
    def test_nama_asli_ditampilkan(self, client):
        fid, _ = _buat_media("foto liburan.png")
        body = client.get("/media-vault").get_data(as_text=True)
        assert f'data-file-id="{fid}"' in body
        assert "foto liburan.png" in body
        assert "[Nama tidak terbaca]" not in body

    def test_token_gagal_memakai_nama_penyimpanan(self, client):
        fid, stored = _buat_media("foto rusak.png")
        with get_db() as db:
            db.execute(
                "UPDATE vault_files SET original_name='v1:rusak' WHERE id=?",
                (fid,),
            )
            db.commit()

        body = client.get("/media-vault").get_data(as_text=True)
        assert f'data-file-id="{fid}"' in body
        assert f"[Berkas {stored[:8]}]" in body
        assert "[Nama tidak terbaca]" not in body
        assert "v1:rusak" not in body
