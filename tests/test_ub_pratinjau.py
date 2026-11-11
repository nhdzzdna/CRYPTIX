"""
tests/test_ub_pratinjau.py
──────────────────────────
Uji pratinjau dokumen (UB): deteksi jenis lewat magic bytes, PDF inline
dengan header pembatas frame khusus, gambar inline, teks sebagai JSON
(termasuk penanda terpotong), 415 untuk jenis lain, grant ``doc.preview``
berulang, penolakan item terkunci dan album terkunci, serta interaksi
dengan Sampah dan pengguna lain.
"""

import io
import os

import pytest

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
from routes.media_routes import MAX_TEXT_BYTES, _deteksi_jenis

DEK = bytes(range(32))

ISI_PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< >>\n%%EOF"
ISI_TEKS = "catatan uji pratinjau — baris kedahulu café naïve".encode("utf-8")
ISI_BINER = b"\x00\x01\x02\x03\x04biner-tanpa-pratinjau"

GAMBAR = (
    ("berkas-png", b"\x89PNG\r\n\x1a\n" + b"IDAT-uji", "image/png"),
    ("berkas-jpg", b"\xff\xd8\xff\xe0JFIF-uji", "image/jpeg"),
    ("berkas-gif87", b"GIF87a" + b"uji", "image/gif"),
    ("berkas-gif89", b"GIF89a" + b"uji", "image/gif"),
    ("berkas-bmp", b"BM" + b"\x36\x00uji", "image/bmp"),
    ("berkas-webp", b"RIFF\x24\x00\x00\x00WEBPVP8 uji", "image/webp"),
)


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "ub-pratinjau.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-tidak-ada.exe"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pemilikubp"), (2, "lainubp")):
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
    return _client(app, 1, "pemilikubp")


@pytest.fixture()
def client2(app):
    return _client(app, 2, "lainubp")


def _csrf(client, halaman="/vault") -> str:
    import re
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
            (user_id, token, stored_name, "document", len(data),
             hasil["sha256_plaintext"], hasil["sha256_ciphertext"]),
        )
        db.commit()
        return cursor.lastrowid


def _buat_koleksi(client, nama: str, kind: str, locked: bool = False) -> int:
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


# ── Deteksi jenis dari magic bytes ──────────────────────────────────────────


class TestDeteksiJenis:
    @pytest.mark.parametrize(
        "isi,jenis",
        [
            (ISI_PDF, "pdf"),
            *[(isi, "image") for _, isi, _ in GAMBAR],
            (ISI_TEKS, "text"),
        ],
    )
    def test_jenis_dikenali(self, isi, jenis):
        assert _deteksi_jenis(isi)[0] == jenis

    @pytest.mark.parametrize(
        "isi",
        [ISI_BINER, b"\xff\xfe\xfa"],
    )
    def test_jenis_tak_dikenal(self, isi):
        assert _deteksi_jenis(isi) is None


# ── Respons pratinjau per jenis ──────────────────────────────────────────────


class TestPratinjau:
    def test_tanpa_grant_ditolak(self, client):
        fid = _buat_berkas(1, "laporan.pdf", ISI_PDF)
        resp = client.get(f"/media-vault/preview/{fid}")
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"

    def test_salah_scope_ditolak(self, client):
        fid = _buat_berkas(1, "laporan.pdf", ISI_PDF)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "item.view", fid)},
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "scope"

    def test_pdf_inline_dengan_header_frame(self, client):
        fid = _buat_berkas(1, "laporan.pdf", ISI_PDF)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        )
        assert resp.status_code == 200
        assert resp.mimetype == "application/pdf"
        assert resp.data == ISI_PDF
        # Hanya rute ini yang boleh di-frame sendiri (penampil modal).
        assert resp.headers["X-Frame-Options"] == "SAMEORIGIN"
        assert resp.headers["Content-Security-Policy"] == "frame-ancestors 'self'"
        assert resp.headers["Content-Disposition"] == "inline"
        assert "no-store" in resp.headers["Cache-Control"]

    @pytest.mark.parametrize("nama,isi,mime", GAMBAR)
    def test_gambar_inline(self, client, nama, isi, mime):
        fid = _buat_berkas(1, f"{nama}.dat", isi)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        )
        assert resp.status_code == 200
        assert resp.mimetype == mime
        assert resp.data == isi
        assert resp.headers["Content-Disposition"] == "inline"

    def test_teks_sebagai_json(self, client):
        fid = _buat_berkas(1, "catatan.txt", ISI_TEKS)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        )
        assert resp.status_code == 200
        assert resp.mimetype == "application/json"
        data = resp.get_json()
        assert data["success"] is True
        assert data["name"] == "catatan.txt"
        assert data["kind"] == "text"
        assert data["size"] == len(ISI_TEKS)
        assert data["truncated"] is False
        assert data["text"] == ISI_TEKS.decode("utf-8")

    def test_teks_panjang_dipotong(self, client):
        isi = ("baris-uji " * 120_000).encode("utf-8")  # > 1 MB
        fid = _buat_berkas(1, "besar.txt", isi)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["size"] == len(isi)
        assert data["truncated"] is True
        assert len(data["text"]) == MAX_TEXT_BYTES

    def test_jenis_lain_415(self, client):
        fid = _buat_berkas(1, "arsip.zip", ISI_BINER)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        )
        assert resp.status_code == 415
        data = resp.get_json()
        assert data["success"] is False
        assert data["reason"] == "jenis"
        assert data["error"] == MSG.DOC_PREVIEW_UNSUPPORTED

    def test_doc_preview_reusable(self, client):
        fid = _buat_berkas(1, "laporan.pdf", ISI_PDF)
        assert client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        ).status_code == 200
        # Permintaan kedua tanpa header tetap lolos: grant berulang aktif.
        assert client.get(f"/media-vault/preview/{fid}").status_code == 200


# ── Pratinjau vs item terkunci dan album terkunci ────────────────────────────


class TestPratinjauTerkunci:
    def test_item_terkunci_dibuka_doc_preview(self, client):
        cid = _buat_koleksi(client, "Arsip", "dokumen")
        fid = _buat_berkas(1, "rahasia.pdf", ISI_PDF)
        assert _pindah(client, cid, [fid]).status_code == 200
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        # Tanpa grant: ditolak autentikasi ulang, bukan isi dokumen.
        resp = client.get(f"/media-vault/preview/{fid}")
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"

        # Grant item.view saja tidak cukup untuk pratinjau.
        _grant(client, "item.view", fid)
        assert client.get(f"/media-vault/preview/{fid}").status_code == 401

        # doc.preview berlaku sebagai pengganti item.view untuk dokumen.
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        )
        assert resp.status_code == 200
        assert resp.data == ISI_PDF

    def test_album_terkunci_butuh_album_unlock(self, client):
        cid = _buat_koleksi(client, "Arsip Rahasia", "dokumen", locked=True)
        fid = _buat_berkas(1, "rahasia.pdf", ISI_PDF)
        assert _pindah(client, cid, [fid],
                      _grant(client, "album.unlock", cid)).status_code == 200
        reauth.clear()

        # doc.preview untuk berkas lolos decorator, tetapi kunci koleksi
        # tetap menolak dengan 403 JSON "terkunci".
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "terkunci"

        # Grant album.unlock aktif di sesi (tanpa header) membuka pintu masuk
        # walau header membawa token doc.preview.
        _grant(client, "album.unlock", cid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        )
        assert resp.status_code == 200
        assert resp.data == ISI_PDF


# ── Isolasi dan Sampah ───────────────────────────────────────────────────────


class TestPratinjauIsolasi:
    def test_item_pengguna_lain_404(self, client, client2):
        fid = _buat_berkas(1, "milik-lain.pdf", ISI_PDF)
        resp = client2.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client2, "doc.preview", fid)},
        )
        assert resp.status_code == 404

    def test_item_di_sampah_404(self, client):
        fid = _buat_berkas(1, "terhapus.pdf", ISI_PDF)
        resp = client.post(f"/vault/delete/{fid}",
                           data={"csrf_token": _csrf(client)})
        assert resp.status_code == 302

        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        )
        assert resp.status_code == 404

    def test_berkas_dirusak_tamper(self, client):
        fid = _buat_berkas(1, "rusak.pdf", ISI_PDF)
        with get_db() as db:
            stored = db.execute(
                "SELECT stored_name FROM vault_files WHERE id=?", (fid,)
            ).fetchone()["stored_name"]
        path = os.path.join(config.ENCRYPTED_FILES_DIR, stored)
        with open(path, "wb") as f:
            f.write(b"bukan-ciphertext-sah")

        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": _grant(client, "doc.preview", fid)},
        )
        assert resp.status_code == 403
        with get_db() as db:
            blok = db.execute(
                "SELECT action FROM blockchain_log WHERE asset_ref=?",
                (f"file:{fid}",),
            ).fetchall()
        assert any(b["action"] == "TAMPER_DETECTED" for b in blok)
