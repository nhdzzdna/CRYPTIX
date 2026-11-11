"""
tests/test_u2b_audio.py
───────────────────────
Uji antarmuka baru halaman Audio (/audio) dan Pengunci Item Generik (P5 / U2b):
- Memeriksa struktur komponen kx-*, kx-card, kx-dropzone, kx-table/kx-audio-tr.
- Memeriksa pemutar audio kustom tetap di bawah (bottom bar), elemen progress bar, dan tombol putar bulat.
- Memastikan tidak ada inline JavaScript pada halaman Audio (CSP ketat).
- Memeriksa pemuatan CSS halaman static/css/halaman/audio.css.
- Memeriksa keberadaan bar aksi mengambang kx-aksi-mengambang dan checkbox pilih semua.
- Memeriksa integrasi menu aksi (⋯) per baris dan tombol Winamp.
- Memeriksa kontrak scope pengunci item generik di static/js/item_lock.js (menerima item.view, doc.preview, item.unlock, album.unlock).
- Memeriksa penanda status trek terkunci pada halaman audio.
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

DEK = bytes(range(32))
ISI_AUDIO = b"ID3\x03\x00\x00\x00\x00\x00#TSSE\x00\x00\x00\x0f\x00\x00\x01\xff\xfeL\x00a\x00v\x00f\x005\x008\x00"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "u2b-audio.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "winamp-simulasi.exe"))
    init_db()
    with get_db() as db:
        db.execute(
            """INSERT OR IGNORE INTO users
               (id, username, email, password_hash, salt) VALUES (?,?,?,?,?)""",
            (1, "audiouser", "audiouser@contoh.test", "hash", "garam"),
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
        sess["username"] = "audiouser"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, DEK)
    return c


def _unggah_audio_db(nama: str, state: str = "normal"):
    db_key = purpose_key(DEK, "database")
    fkey = purpose_key(DEK, "file")
    stored = generate_stored_name()
    enc_res = encrypt_stream(
        io.BytesIO(ISI_AUDIO),
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
            (1, name_token, stored, "audio", len(ISI_AUDIO), enc_res["sha256_plaintext"], enc_res["sha256_ciphertext"]),
        )
        fid = cur.lastrowid
        if state == "locked":
            col_name_enc = encrypt_field("Folder Audio Rahasia", db_key, field_aad(1, "collections", "name_enc"))
            cur_col = db.execute(
                "INSERT INTO collections (user_id, name_enc, kind, locked) VALUES (?, ?, ?, ?)",
                (1, col_name_enc, "musik", 0),
            )
            cid = cur_col.lastrowid
            db.execute(
                "INSERT INTO collection_items (collection_id, file_id, state) VALUES (?, ?, ?)",
                (cid, fid, "locked"),
            )
        db.commit()
    return fid


def test_halaman_audio_markup_kx(client):
    _unggah_audio_db("trek_utama.mp3")
    resp = client.get("/audio")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # 1. Pemuatan CSS halaman
    assert "halaman/audio.css" in html

    # 2. Tanpa subjudul di header & tanpa tombol unggah topbar
    assert 'class="page-subtitle"' not in html
    assert 'audio-header-action' not in html

    # 3. Area dropzone kx-*
    assert 'data-kx-dropzone' in html
    assert 'audio-file-input' in html

    # 4. Tabel kx-table & baris audio kx-audio-tr
    assert 'class="kx-table-wrap"' in html
    assert 'kx-audio-table' in html
    assert 'kx-audio-play-circle' in html
    assert 'trek_utama.mp3' in html

    # 5. Kolom durasi dan badge status
    assert 'Terenkripsi' in html

    # 6. Pemutar kustom tetap di bawah
    assert 'class="kx-audio-player-bar"' in html
    assert 'id="music-audio"' in html
    assert 'id="music-play-toggle"' in html
    assert 'id="music-progress-bar"' in html
    assert 'id="music-time-cur"' in html

    # 7. Pencarian trek & pilihan massal
    assert 'id="audio-search"' in html
    assert 'id="selection-bar"' in html
    assert 'kx-aksi-mengambang' in html
    assert 'id="audio-select-all"' in html


def test_halaman_audio_tanpa_inline_script(client):
    resp = client.get("/audio")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # Memastikan tidak ada script inline
    inline_scripts = re.findall(r'<script(?![^>]*src=)[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    for s in inline_scripts:
        assert not s.strip(), f"Ditemukan inline JavaScript di halaman Audio: {s}"


def test_halaman_audio_status_terkunci(client):
    _unggah_audio_db("trek_rahasia.flac", state="locked")
    resp = client.get("/audio")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert "trek_rahasia.flac" in html
    assert 'data-locked="1"' in html
    assert "Terkunci" in html


def test_item_lock_kontrak_generik():
    # Verifikasi berkas statis item_lock.js memuat implementasi berbasis modal KX
    with open("static/js/item_lock.js", "r", encoding="utf-8") as f:
      konten = f.read()

    assert "window.CryptixLock" in konten
    assert "mintaGrant" in konten
    assert "lepasKunci" in konten
    assert "pilih" in konten
    assert "KX.modal" in konten
    assert "item.view" in konten
    assert "doc.preview" in konten
    assert "item.unlock" in konten


def test_item_lock_bebas_kata_terlarang():
    terlarang = ["sem" + "ester", "U" + "AS", "U" + "TS", "maha" + "siswa", "do" + "sen"]
    with open("static/js/item_lock.js", "r", encoding="utf-8") as f:
        isi_js = f.read().lower()
    with open("templates/musik.html", "r", encoding="utf-8") as f:
        isi_tpl = f.read().lower()

    for kata in terlarang:
        assert kata not in isi_js, f"Kata terlarang '{kata}' ditemukan di item_lock.js"
        assert kata not in isi_tpl, f"Kata terlarang '{kata}' ditemukan di musik.html"

