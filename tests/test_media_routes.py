"""
tests/test_media_routes.py
──────────────────────────
Uji Media Vault: streaming rentang HTTP, header 206/416, kepemilikan berkas,
MIME, pemain HTML5, penolakan format unduh-saja, dan deteksi pemodifan.
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

DEK = bytes(range(32))
DEK_LAIN = bytes(range(1, 33))


def _tipe_berkas(nama: str) -> str:
    ext = os.path.splitext(nama)[1].lower()
    if ext in {".mp3", ".wav", ".flac", ".ogg", ".m4a"}:
        return "audio"
    if ext in {".mp4", ".webm", ".avi", ".mkv", ".mov"}:
        return "video"
    return "document"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "media_uji.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted_files"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego_images"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary_files"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-tidak-ada.exe"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pengujimedia"), (2, "penggunalain")):
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
        sess["username"] = "pengujimedia"
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
    """Terbitkan grant untuk sesi klien uji tanpa lewat endpoint reauth."""
    with client.session_transaction() as sess:
        sid = sess["session_id"]
    return reauth.issue_grant(sid, scope, resource_id)["token"]


def _buat_media(user_id: int, nama: str, data: bytes, dek: bytes = DEK):
    """Enkripsi *data* seperti unggahan vault dan kembalikan (id, path)."""
    stored_name = generate_stored_name()
    path = os.path.join(config.ENCRYPTED_FILES_DIR, stored_name)
    os.makedirs(config.ENCRYPTED_FILES_DIR, exist_ok=True)
    hasil = encrypt_stream(
        io.BytesIO(data), path,
        purpose_key(dek, "file"), file_aad(user_id, stored_name),
    )
    token = encrypt_field(
        nama, purpose_key(dek, "database"),
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
        return cursor.lastrowid, path


ISI_AUDIO = b"ID3" + bytes(range(256)) * 20


class TestMediaStream:
    def test_stream_tanpa_range(self, client):
        file_id, _ = _buat_media(1, "lagu.mp3", ISI_AUDIO)
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={"X-Reauth-Grant": _grant(client, "media.stream", file_id)},
        )
        assert resp.status_code == 200
        assert resp.data == ISI_AUDIO
        assert resp.headers["Accept-Ranges"] == "bytes"
        assert int(resp.headers["Content-Length"]) == len(ISI_AUDIO)
        assert resp.headers["Content-Type"].startswith("audio/mpeg")

    def test_stream_range_valid_206(self, client):
        file_id, _ = _buat_media(1, "lagu.mp3", ISI_AUDIO)
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={
                "Range": "bytes=2-9",
                "X-Reauth-Grant": _grant(client, "media.stream", file_id),
            },
        )
        assert resp.status_code == 206
        assert resp.data == ISI_AUDIO[2:10]
        assert resp.headers["Content-Range"] == f"bytes 2-9/{len(ISI_AUDIO)}"
        assert resp.headers["Accept-Ranges"] == "bytes"
        assert resp.headers["Content-Length"] == "8"

    def test_stream_range_terbuka_dan_suffix(self, client):
        file_id, _ = _buat_media(1, "lagu.mp3", ISI_AUDIO)
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={
                "Range": "bytes=10-",
                "X-Reauth-Grant": _grant(client, "media.stream", file_id),
            },
        )
        assert resp.status_code == 206
        assert resp.data == ISI_AUDIO[10:]
        assert resp.headers["Content-Range"] == f"bytes 10-{len(ISI_AUDIO) - 1}/{len(ISI_AUDIO)}"

        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={
                "Range": "bytes=-10",
                "X-Reauth-Grant": _grant(client, "media.stream", file_id),
            },
        )
        assert resp.status_code == 206
        assert resp.data == ISI_AUDIO[-10:]

    @pytest.mark.parametrize("rentang", [
        "bytes=999999-",
        "bytes=abc",
        "bytes=0-1,3-4",
        "bytes=20-10",
        "bytes=-0",
    ])
    def test_stream_range_tidak_valid_416(self, client, rentang):
        file_id, _ = _buat_media(1, "lagu.mp3", ISI_AUDIO)
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={
                "Range": rentang,
                "X-Reauth-Grant": _grant(client, "media.stream", file_id),
            },
        )
        assert resp.status_code == 416
        assert resp.headers["Content-Range"] == f"bytes */{len(ISI_AUDIO)}"
        assert resp.headers["Accept-Ranges"] == "bytes"

    def test_pengguna_lain_tidak_boleh_mengakses(self, client):
        file_id, _ = _buat_media(2, "lagu.mp3", ISI_AUDIO)
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={"X-Reauth-Grant": _grant(client, "media.stream", file_id)},
        )
        assert resp.status_code == 404

    def test_plaintext_tidak_ditulis_ke_disk(self, client):
        file_id, _ = _buat_media(1, "lagu.mp3", ISI_AUDIO)
        sebelum = set(os.listdir(config.TEMPORARY_FILES_DIR))
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={
                "Range": "bytes=0-15",
                "X-Reauth-Grant": _grant(client, "media.stream", file_id),
            },
        )
        assert resp.status_code == 206
        sesudah = set(os.listdir(config.TEMPORARY_FILES_DIR))
        assert sesudah == sebelum
        assert not any(
            nama in sesudah
            for nama in sesudah
            if "lagu" in nama or "mp3" in nama
        )

    @pytest.mark.parametrize("nama,mime", [
        ("lagu.mp3", "audio/mpeg"),
        ("lagu.wav", "audio/wav"),
        ("lagu.flac", "audio/flac"),
        ("lagu.ogg", "audio/ogg"),
        ("lagu.m4a", "audio/mp4"),
        ("video.mp4", "video/mp4"),
        ("video.webm", "video/webm"),
    ])
    def test_mime_sesuai(self, client, nama, mime):
        file_id, _ = _buat_media(1, nama, ISI_AUDIO)
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={
                "Range": "bytes=0-3",
                "X-Reauth-Grant": _grant(client, "media.stream", file_id),
            },
        )
        assert resp.status_code == 206
        assert resp.headers["Content-Type"].startswith(mime)

    @pytest.mark.parametrize("nama", ["video.avi", "video.mkv", "video.mov"])
    def test_format_unduh_saja_ditolak_stream(self, client, nama):
        file_id, _ = _buat_media(1, nama, ISI_AUDIO)
        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={"X-Reauth-Grant": _grant(client, "media.stream", file_id)},
        )
        assert resp.status_code == 415

    def test_pemodifan_ciphertext_dicatat(self, client):
        file_id, path = _buat_media(1, "lagu.mp3", ISI_AUDIO)
        with open(path, "r+b") as handle:
            handle.seek(-1, os.SEEK_END)
            byte = handle.read(1)
            handle.seek(-1, os.SEEK_END)
            handle.write(bytes([byte[0] ^ 0xFF]))

        resp = client.get(
            f"/media-vault/stream/{file_id}",
            headers={
                "Range": "bytes=0-15",
                "X-Reauth-Grant": _grant(client, "media.stream", file_id),
            },
        )
        assert resp.status_code == 403
        with get_db() as db:
            aksi = [
                b["action"]
                for b in db.execute("SELECT action FROM blockchain_log")
            ]
        assert "TAMPER_DETECTED" in aksi


class TestMediaHalaman:
    def test_pemain_html5_dan_unduh_saja(self, client):
        _buat_media(1, "lagu.mp3", ISI_AUDIO)
        _buat_media(1, "video.mp4", ISI_AUDIO)
        _buat_media(1, "video.avi", ISI_AUDIO)

        body = client.get("/media-vault").get_data(as_text=True)
        assert "<video controls" in body
        assert "<audio controls" not in body
        assert "/media-vault/view/" in body
        assert MSG.MEDIA_DOWNLOAD_ONLY in body

    def test_play_html5_diarahkan_ke_stream(self, client):
        file_id, _ = _buat_media(1, "lagu.mp3", ISI_AUDIO)
        token = _csrf(client)
        resp = client.post(
            f"/media-vault/play/{file_id}",
            data={
                "csrf_token": token,
                "reauth_grant": _grant(client, "media.winamp", file_id),
                "player": "html5",
            },
        )
        assert resp.status_code == 302
        assert f"/media-vault/stream/{file_id}" in resp.headers["Location"]

    def test_winamp_menolak_video(self, app, client, tmp_path, monkeypatch):
        palsu = tmp_path / "winamp.exe"
        palsu.write_bytes(b"bukan biner sungguhan")
        monkeypatch.setattr(config, "WINAMP_PATH", str(palsu))

        file_id, _ = _buat_media(1, "video.mp4", ISI_AUDIO)
        token = _csrf(client)
        resp = client.post(
            f"/media-vault/play/{file_id}",
            data={
                "csrf_token": token,
                "reauth_grant": _grant(client, "media.winamp", file_id),
                "player": "winamp",
            },
        )
        assert resp.status_code == 400
