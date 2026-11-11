"""
tests/test_ub_pratinjau.py
──────────────────────────
Uji pratinjau dokumen (UB): deteksi jenis lewat magic bytes, PDF inline
dengan header pembatas frame khusus, gambar inline, teks sebagai JSON
(termasuk penanda terpotong), 415 untuk jenis lain, grant ``doc.preview``
berulang, penolakan item terkunci dan album terkunci, serta interaksi
dengan Sampah dan pengguna lain.
"""

Uji fitur pratinjau dokumen (UB):
- Deteksi jenis berkas dari magic bytes (PDF, gambar, teks; bukan ekstensi).
- Header inline, no-store, serta SAMEORIGIN dan frame-ancestors 'self' khusus PDF.
- Format teks (txt/md/csv/json) disajikan sebagai JSON, batas teks dan penanda terpotong.
- Format yang tidak didukung mengembalikan 415 JSON reason 'jenis'.
- Autentikasi dan grant ``doc.preview`` berulang (reusable 15 menit).
- Penolakan item di Sampah (404), pengguna lain (404), dan item terkunci (403 reason 'terkunci').
- Integritas rusak memicu blok TAMPER_DETECTED dan penolakan 403.
"""

import hashlib
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
from routes.media_routes import _deteksi_jenis, MAX_TEXT_BYTES

DEK = bytes(range(32))

DATA_PDF = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
DATA_GIF87A = (
    b"GIF87a\x0a\x00\x0a\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
    b"!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x0a\x00\x0a\x00\x00\x02\x02\x44\x01\x00;"
)
DATA_WEBP = b"RIFF\x18\x00\x00\x00WEBPVP8 \x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def _sample_png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (200, 30, 30)).save(buf, format="PNG")
    return buf.getvalue()


def _sample_jpeg() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (30, 200, 30)).save(buf, format="JPEG")
    return buf.getvalue()


def _sample_gif89a() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (30, 30, 200)).save(buf, format="GIF")
    return buf.getvalue()


def _sample_bmp() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (120, 120, 120)).save(buf, format="BMP")
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


def _buat_berkas(user_id: int, nama: str, data: bytes) -> int:
def _buat_media(user_id: int, nama: str, data: bytes) -> int:
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
            (user_id, token, stored_name, _tipe_berkas(nama), len(data),
             hasil["sha256_plaintext"], hasil["sha256_ciphertext"]),
        )
        db.commit()
        return cursor.lastrowid


def _buat_koleksi(client, nama: str, kind: str, locked: bool = False) -> int:
def _buat_koleksi(client, nama: str, kind: str = "dokumen",
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
# ── 1. Deteksi Jenis (Magic Bytes) ───────────────────────────────────────────


class TestDeteksiJenis:
    def test_deteksi_pdf(self):
        assert _deteksi_jenis(DATA_PDF) == ("pdf", "application/pdf")

    def test_deteksi_png(self):
        assert _deteksi_jenis(_sample_png()) == ("image", "image/png")

    def test_deteksi_jpeg(self):
        assert _deteksi_jenis(_sample_jpeg()) == ("image", "image/jpeg")

    def test_deteksi_gif87a_dan_gif89a(self):
        assert _deteksi_jenis(DATA_GIF87A) == ("image", "image/gif")
        assert _deteksi_jenis(_sample_gif89a()) == ("image", "image/gif")

    def test_deteksi_bmp(self):
        assert _deteksi_jenis(_sample_bmp()) == ("image", "image/bmp")

    def test_deteksi_webp(self):
        assert _deteksi_jenis(DATA_WEBP) == ("image", "image/webp")

    def test_deteksi_teks_utf8_dan_whitespace(self):
        data = "Halo dunia!\nBaris kedua\tdengan tab.\r\n".encode("utf-8")
        assert _deteksi_jenis(data) == ("text", "text/plain; charset=utf-8")

    def test_deteksi_teks_kosong(self):
        assert _deteksi_jenis(b"") == ("text", "text/plain; charset=utf-8")

    def test_deteksi_svg_sebagai_teks(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="10"/></svg>'
        assert _deteksi_jenis(svg) == ("text", "text/plain; charset=utf-8")

    def test_deteksi_non_utf8_menghasilkan_none(self):
        assert _deteksi_jenis(b"\x80\x81\x82") is None

    def test_deteksi_byte_nul_dan_kontrol_menghasilkan_none(self):
        assert _deteksi_jenis(b"teks\x00dengan_nul") is None
        assert _deteksi_jenis(b"teks\x07dengan_bel") is None


# ── 2. Autentikasi dan Grant ─────────────────────────────────────────────────


class TestPratinjauGrant:
    def test_tanpa_login_dialihkan_ke_login(self, app):
        c = app.test_client()
        resp = c.get("/media-vault/preview/1")
        assert resp.status_code == 302
        assert resp.headers.get("Location") in {"/", "/login"}

    def test_tanpa_grant_ditolak_401(self, client):
        fid = _buat_media(1, "dokumen.pdf", DATA_PDF)
        resp = client.get(f"/media-vault/preview/{fid}")
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["success"] is False
        assert data["error"] == MSG.REAUTH_REQUIRED
        assert data["reason"] == "missing"

    def test_salah_scope_ditolak_403(self, client):
        fid = _buat_media(1, "dokumen.pdf", DATA_PDF)
        token_salah = _grant(client, "media.stream", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token_salah},
        )
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["reason"] == "scope"

    def test_salah_resource_ditolak_403(self, client):
        fid1 = _buat_media(1, "dokumen1.pdf", DATA_PDF)
        fid2 = _buat_media(1, "dokumen2.pdf", DATA_PDF)
        token_fid2 = _grant(client, "doc.preview", fid2)
        resp = client.get(
            f"/media-vault/preview/{fid1}",
            headers={"X-Reauth-Grant": token_fid2},
        )
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["reason"] == "resource"

    def test_grant_reusable_15_menit_bisa_berulang(self, client):
        fid = _buat_media(1, "dokumen.pdf", DATA_PDF)
        token = _grant(client, "doc.preview", fid)
        for _ in range(3):
            resp = client.get(
                f"/media-vault/preview/{fid}",
                headers={"X-Reauth-Grant": token},
            )
            assert resp.status_code == 200

    def test_grant_kedaluwarsa_setelah_15_menit(self, client, monkeypatch):
        fid = _buat_media(1, "dokumen.pdf", DATA_PDF)
        token = _grant(client, "doc.preview", fid)
        sekarang = reauth._now()

        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200

        # Lewat dari 15 menit (900 detik)
        monkeypatch.setattr(reauth, "_now", lambda: sekarang + 901)
        resp_kedaluwarsa = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp_kedaluwarsa.status_code == 401
        assert resp_kedaluwarsa.get_json()["error"] == MSG.REAUTH_INVALID
        assert resp_kedaluwarsa.get_json()["reason"] == "expired"


# ── 3. Penyajian Konten Pratinjau ────────────────────────────────────────────


class TestPratinjauKonten:
    def test_pratinjau_pdf_inline_dan_headers(self, client):
        fid = _buat_media(1, "laporan.pdf", DATA_PDF)
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200
        assert resp.mimetype == "application/pdf"
        assert resp.headers.get("Content-Disposition") == "inline"
        assert resp.headers.get("Cache-Control") == "no-store"
        assert resp.headers.get("Pragma") == "no-cache"
        assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"
        assert "frame-ancestors 'self'" in resp.headers.get("Content-Security-Policy", "")
        assert resp.data == DATA_PDF

    def test_pratinjau_gambar_png(self, client):
        png_data = _sample_png()
        fid = _buat_media(1, "gambar.png", png_data)
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200
        assert resp.mimetype == "image/png"
        assert resp.headers.get("Content-Disposition") == "inline"
        assert resp.headers.get("Cache-Control") == "no-store"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.data == png_data

    def test_pratinjau_gambar_jpeg(self, client):
        jpeg_data = _sample_jpeg()
        fid = _buat_media(1, "foto.jpeg", jpeg_data)
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200
        assert resp.mimetype == "image/jpeg"
        assert resp.headers.get("Content-Disposition") == "inline"
        assert resp.data == jpeg_data

    def test_pratinjau_gambar_gif(self, client):
        fid = _buat_media(1, "animasi.gif", DATA_GIF87A)
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200
        assert resp.mimetype == "image/gif"
        assert resp.data == DATA_GIF87A

    def test_pratinjau_gambar_bmp(self, client):
        bmp_data = _sample_bmp()
        fid = _buat_media(1, "peta.bmp", bmp_data)
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200
        assert resp.mimetype == "image/bmp"
        assert resp.data == bmp_data

    def test_pratinjau_gambar_webp(self, client):
        fid = _buat_media(1, "grafik.webp", DATA_WEBP)
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200
        assert resp.mimetype == "image/webp"
        assert resp.data == DATA_WEBP

    @pytest.mark.parametrize(
        ("nama", "isi"),
        [
            ("catatan.txt", b"Isi teks biasa."),
            ("dokumen.md", b"# Judul\nIsi markdown."),
            ("data.csv", b"a,b,c\n1,2,3"),
            ("konfigurasi.json", b'{"kunci": "nilai"}'),
        ],
    )
    def test_pratinjau_teks_berbagai_ekstensi_sebagai_json(self, client, nama, isi):
        fid = _buat_media(1, nama, isi)
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["kind"] == "text"
        assert data["name"] == nama
        assert data["size"] == len(isi)
        assert data["truncated"] is False
        assert data["text"] == isi.decode("utf-8")

    def test_pratinjau_teks_512kb_tidak_terpotong(self, client):
        isi_512kb = ("A" * 1023 + "\n").encode("utf-8") * 512
        assert len(isi_512kb) == 512 * 1024
        fid = _buat_media(1, "panjang_512kb.txt", isi_512kb)
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["kind"] == "text"
        assert data["size"] == 512 * 1024
        assert data["truncated"] is False
        assert len(data["text"]) == 512 * 1024

    def test_pratinjau_teks_melebihi_batas_terpotong(self, client):
        isi_besar = b"B" * (MAX_TEXT_BYTES + 250)
        fid = _buat_media(1, "sangat_besar.txt", isi_besar)
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["kind"] == "text"
        assert data["size"] == len(isi_besar)
        assert data["truncated"] is True
        assert len(data["text"]) == MAX_TEXT_BYTES

    def test_format_tidak_didukung_415_json(self, client):
        data_bin = b"\x00\x01\x02\x03\x04\x05"
        fid = _buat_media(1, "arsip.bin", data_bin)
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
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
    def test_deteksi_magic_bytes_bukan_ekstensi(self, client):
        # Berkas bernama .docx tetapi berisi data PNG valid
        fid_png = _buat_media(1, "laporan.docx", _sample_png())
        token_png = _grant(client, "doc.preview", fid_png)
        resp_png = client.get(
            f"/media-vault/preview/{fid_png}",
            headers={"X-Reauth-Grant": token_png},
        )
        assert resp_png.status_code == 200
        assert resp_png.mimetype == "image/png"

        # Berkas bernama .png tetapi berisi biner acak dengan byte NUL
        fid_bin = _buat_media(1, "foto_palsu.png", b"\x00\x02\x04\x06")
        token_bin = _grant(client, "doc.preview", fid_bin)
        resp_bin = client.get(
            f"/media-vault/preview/{fid_bin}",
            headers={"X-Reauth-Grant": token_bin},
        )
        assert resp_bin.status_code == 415
        assert resp_bin.get_json()["reason"] == "jenis"


# ── 4. Kontrol Akses, Status Kunci, dan Integritas ───────────────────────────


class TestPratinjauAksesDanIntegritas:
    def test_item_terkunci_dibuka_oleh_doc_preview(self, client):
        cid = _buat_koleksi(client, "Folder Kerja", kind="dokumen")
        fid = _buat_media(1, "rahasia.pdf", DATA_PDF)
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        # Tanpa grant -> 401
        assert client.get(f"/media-vault/preview/{fid}").status_code == 401

        # Dengan grant doc.preview untuk fid -> 200 OK
        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 200
        assert resp.data == DATA_PDF

    def test_item_view_tidak_cukup_untuk_preview(self, client):
        cid = _buat_koleksi(client, "Folder", kind="dokumen")
        fid = _buat_media(1, "rahasia.pdf", DATA_PDF)
        _pindah(client, cid, [fid])
        assert _ubah_state(client, cid, [fid], "locked").status_code == 200

        # Grant item.view aktif di sesi, tetapi endpoint preview menuntut doc.preview
        token_item_view = _grant(client, "item.view", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token_item_view},
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "scope"

    def test_album_folder_terkunci_butuh_album_unlock_dan_fallback_grant(self, client):
        cid = _buat_koleksi(client, "Folder Kunci", kind="dokumen", locked=True)
        fid = _buat_media(1, "dokumen.pdf", DATA_PDF)
        assert _pindah(client, cid, [fid],
                      _grant(client, "album.unlock", cid)).status_code == 200
        reauth.clear()

        token_preview = _grant(client, "doc.preview", fid)

        # Folder terkunci tanpa grant album.unlock -> 403 reason 'terkunci'
        resp_terkunci = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token_preview},
        )
        assert resp_terkunci.status_code == 403
        assert resp_terkunci.get_json()["reason"] == "terkunci"

        # Buka kunci folder (grant album.unlock aktif di sesi)
        _grant(client, "album.unlock", cid)

        # Permintaan dengan header token doc.preview berhasil karena grant_sah
        # melakukan fallback mencari grant album.unlock yang aktif di sesi
        resp_terbuka = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token_preview},
        )
        assert resp_terbuka.status_code == 200
        assert resp_terbuka.data == DATA_PDF

    def test_item_di_sampah_ditolak_404(self, client):
        fid = _buat_media(1, "dibuang.pdf", DATA_PDF)
        with get_db() as db:
            db.execute(
                "UPDATE vault_files SET deleted_at='2026-11-11 12:00:00' WHERE id=?",
                (fid,),
            )
            db.commit()

        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 404

    def test_pengguna_lain_ditolak_404(self, client, client2):
        fid_user1 = _buat_media(1, "milik_user1.pdf", DATA_PDF)
        token_user2 = _grant(client2, "doc.preview", fid_user1)
        resp = client2.get(
            f"/media-vault/preview/{fid_user1}",
            headers={"X-Reauth-Grant": token_user2},
        )
        assert resp.status_code == 404

    def test_hash_tidak_cocok_memicu_tamper_detected(self, client):
        fid = _buat_media(1, "asli.pdf", DATA_PDF)
        with get_db() as db:
            stored_name = db.execute(
                "SELECT stored_name FROM vault_files WHERE id=?", (fid,)
            ).fetchone()["stored_name"]

        # Rusak byte terakhir dari ciphertext berkas
        path = os.path.join(config.ENCRYPTED_FILES_DIR, stored_name)
        with open(path, "r+b") as handle:
            handle.seek(-1, os.SEEK_END)
            b = handle.read(1)
            handle.seek(-1, os.SEEK_END)
            handle.write(bytes([b[0] ^ 0xFF]))

        token = _grant(client, "doc.preview", fid)
        resp = client.get(
            f"/media-vault/preview/{fid}",
            headers={"X-Reauth-Grant": token},
        )
        assert resp.status_code == 403

        with get_db() as db:
            aksi = [
                b["action"]
                for b in db.execute(
                    "SELECT action FROM blockchain_log WHERE user_id=?", (1,)
                )
            ]
        assert "TAMPER_DETECTED" in aksi
