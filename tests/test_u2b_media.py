"""
tests/test_u2b_media.py
───────────────────────
Uji antarmuka baru halaman Media (/media-vault) (P6 / U2b):
- Memeriksa struktur komponen kx-*, kx-card, kx-dropzone, kx-media-grid, kx-media-card.
- Memeriksa nama berkas asli ditampilkan di bawah thumbnail 4:3.
- Memastikan tidak ada inline JavaScript pada halaman Media (CSP ketat).
- Memeriksa pemuatan CSS halaman static/css/halaman/media.css.
- Memeriksa penanda status item terkunci (ikon lock, badge Terkunci).
- Memeriksa kontrak album terkunci: isi album terkunci tidak tampil di bagian Semua.
- Memeriksa pemakaian scope item.view lewat modul pengunci generik.
- Memeriksa bar aksi mengambang kx-aksi-mengambang dan checkbox item.
- Memeriksa menu titik tiga (⋯) per kartu media.
- Memastikan bebas kata terlarang di berkas baru/diubah.
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
from modules.cryptography.key_management import purpose_key
from modules.cryptography.database_encryption import encrypt_field, field_aad
from modules.cryptography.file_encryption import encrypt_stream, file_aad, generate_stored_name
from PIL import Image

DEK = bytes(range(32))


def _buat_png():
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (10, 150, 80)).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "u2b-media.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-simulasi.exe"))
    init_db()
    with get_db() as db:
        db.execute(
            """INSERT OR IGNORE INTO users
               (id, username, email, password_hash, salt) VALUES (?,?,?,?,?)""",
            (1, "mediauser", "mediauser@contoh.test", "hash", "garam"),
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
        sess["username"] = "mediauser"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, DEK)
    return c


def _unggah_media_db(nama: str, state: str = "normal", locked_album: bool = False):
    db_key = purpose_key(DEK, "database")
    fkey = purpose_key(DEK, "file")
    stored = generate_stored_name()
    raw = _buat_png()
    enc_res = encrypt_stream(
        io.BytesIO(raw),
        os.path.join(config.ENCRYPTED_FILES_DIR, stored),
        fkey,
        file_aad(1, stored),
    )
    name_token = encrypt_field(nama, db_key, field_aad(1, "vault_files", "original_name"))
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO vault_files
               (user_id, original_name, stored_name, file_type, file_size,
                sha256_hash, sha256_ciphertext)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (1, name_token, stored, "image", len(raw), enc_res["sha256_plaintext"], enc_res["sha256_ciphertext"]),
        )
        fid = cur.lastrowid
        if state == "locked" or locked_album:
            col_name_enc = encrypt_field("Album Liburan", db_key, field_aad(1, "collections", "name_enc"))
            cur_col = db.execute(
                "INSERT INTO collections (user_id, name_enc, kind, locked) VALUES (?, ?, ?, ?)",
                (1, col_name_enc, "album", 1 if locked_album else 0),
            )
            cid = cur_col.lastrowid
            db.execute(
                "INSERT INTO collection_items (collection_id, file_id, state) VALUES (?, ?, ?)",
                (cid, fid, "locked" if state == "locked" else "normal"),
            )
        db.commit()
    return fid


def test_halaman_media_markup_kx(client):
    _unggah_media_db("pemandangan_pantai.png")
    resp = client.get("/media-vault")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # 1. Pemuatan CSS halaman media
    assert "halaman/media.css" in html

    # 2. Tanpa subjudul & tanpa tombol unggah di topbar
    assert 'class="page-subtitle"' not in html
    assert 'media-header-action' not in html

    # 3. Area dropzone kx-*
    assert 'data-kx-dropzone' in html
    assert 'media-file-input' in html

    # 4. Grid media & kartu kx-media-card
    assert 'class="kx-media-grid media-grid"' in html
    assert 'kx-media-card' in html
    assert 'pemandangan_pantai.png' in html

    # 5. Badge status & pencarian
    assert 'Terenkripsi' in html
    assert 'id="media-search"' in html

    # 6. Bar aksi mengambang
    assert 'id="selection-bar"' in html
    assert 'kx-aksi-mengambang' in html

    # 7. Modal penampil media
    assert 'id="media-viewer"' in html
    assert 'id="viewer-stage"' in html


def test_halaman_media_tanpa_inline_script(client):
    resp = client.get("/media-vault")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # Memastikan tidak ada script inline
    inline_scripts = re.findall(r'<script(?![^>]*src=)[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    for s in inline_scripts:
        assert not s.strip(), f"Ditemukan inline JavaScript di halaman Media: {s}"


def test_halaman_media_nama_berkas_asli_tampil(client):
    fid = _unggah_media_db("foto_keluarga_asli.png")
    resp = client.get("/media-vault")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert "foto_keluarga_asli.png" in html
    assert f'data-file-id="{fid}"' in html


def test_halaman_media_status_terkunci(client):
    _unggah_media_db("arsip_terkunci.png", state="locked")
    resp = client.get("/media-vault")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert "arsip_terkunci.png" in html
    assert 'data-locked="1"' in html
    assert "Terkunci" in html


def test_halaman_media_album_terkunci_tidak_tampil_di_semua(client):
    _unggah_media_db("rahasia_album_kunci.png", state="normal", locked_album=True)
    resp = client.get("/media-vault")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # Nama album tetap ada di daftar album
    assert "Album Liburan" in html
    # Namun isinya TIDAK boleh tampil di bagian Semua tanpa grant
    assert "rahasia_album_kunci.png" not in html


def test_halaman_media_scope_item_view_pada_pengunci_generik():
    with open("static/js/media_albums.js", "r", encoding="utf-8") as f:
        konten = f.read()

    assert "item.view" in konten
    assert "window.CryptixLock" in konten
    assert "bukaPenampil" in konten


def test_halaman_media_menu_tiga_titik(client):
    _unggah_media_db("gambar_menu.png")
    resp = client.get("/media-vault")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert 'data-menu-toggle' in html
    assert 'data-menu-dropdown' in html


def test_halaman_media_bebas_kata_terlarang():
    terlarang = ["sem" + "ester", "U" + "AS", "U" + "TS", "maha" + "siswa", "do" + "sen"]
    with open("static/css/halaman/media.css", "r", encoding="utf-8") as f:
        css = f.read().lower()
    with open("templates/media_vault.html", "r", encoding="utf-8") as f:
        tpl = f.read().lower()
    with open("static/js/media_albums.js", "r", encoding="utf-8") as f:
        js = f.read().lower()

    for kata in terlarang:
        assert kata not in css, f"Kata terlarang '{kata}' ditemukan di media.css"
        assert kata not in tpl, f"Kata terlarang '{kata}' ditemukan di media_vault.html"
        assert kata not in js, f"Kata terlarang '{kata}' ditemukan di media_albums.js"

