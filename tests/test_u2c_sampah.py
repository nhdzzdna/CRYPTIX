"""
tests/test_u2c_sampah.py
────────────────────────
Uji antarmuka baru halaman Sampah (P7 / U2c):
- Memeriksa struktur komponen kx-*, kx-card, kx-infobox, kx-trash-chip, kx-aksi-mengambang.
- Memeriksa ketiadaan JavaScript inline (CSP ketat).
- Memeriksa filter jenis (chip) dan penanda sisa hari kadaluwarsa.
- Memeriksa tombol hapus permanen terintegrasi dengan KX.konfirmasiHapus dan bebas window.confirm.
- Memeriksa integritas alur grant trash.purge dan event cryptix:reauth-grant.
- Memastikan tidak ada kata terlarang menurut AGENTS.md.
- Pengujian lintas halaman: /documents, /audio, /media-vault, dan /sampah mengembalikan 200 dan memuat kelas kx-.
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
from modules.strings import MSG
from modules import trash

DEK = bytes(range(32))


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "u2c-sampah.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc_files"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego_files"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp_files"))
    init_db()
    with get_db() as db:
        db.execute(
            """INSERT OR IGNORE INTO users
               (id, username, email, password_hash, salt) VALUES (?,?,?,?,?)""",
            (1, "trashuser", "trashuser@contoh.test", "hash", "garam"),
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
        sess["username"] = "trashuser"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, DEK)
    return c


def _tambah_item_sampah(nama: str = "arsip-lama.pdf"):
    db_key = purpose_key(DEK, "database")
    fkey = purpose_key(DEK, "file")
    stored = generate_stored_name()
    enc_res = encrypt_stream(
        io.BytesIO(b"konten rahasia arsip"),
        os.path.join(config.ENCRYPTED_FILES_DIR, stored),
        fkey,
        file_aad(1, stored),
    )
    name_token = encrypt_field(nama, db_key, field_aad(1, "vault_files", "original_name"))
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO vault_files
               (user_id, original_name, stored_name, file_type, file_size,
                sha256_hash, sha256_ciphertext, deleted_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (1, name_token, stored, "document", 20, enc_res["sha256_plaintext"], enc_res["sha256_ciphertext"]),
        )
        fid = cur.lastrowid
        db.commit()
    return fid


def test_halaman_sampah_markup_kx(client):
    _tambah_item_sampah("dokumen_terbuang.pdf")
    resp = client.get("/sampah")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # 1. CSS khusus dimuat
    assert "halaman/sampah.css" in html

    # 2. Komponen kx-* (infobox, kartu, tabel, badge, chip)
    assert 'class="kx-infobox"' in html
    assert 'class="kx-trash-header"' in html
    assert 'class="kx-trash-chip' in html
    assert 'class="kx-table trash-table"' in html
    assert 'id="trash-floating-actions"' in html
    assert 'data-kx-jumlah' in html

    # 3. Tanpa subjudul di header
    assert 'class="page-subtitle"' not in html

    # 4. Filter jenis tersedia
    assert 'data-trash-filter="all"' in html
    assert 'data-trash-filter="file"' in html
    assert 'data-trash-filter="note"' in html
    assert 'data-trash-filter="cred"' in html
    assert 'data-trash-filter="stego"' in html

    # 5. Penanda sisa hari dan nama terdekripsi
    assert "dokumen_terbuang.pdf" in html
    assert "hari" in html
    assert "kx-trash-item-days" in html


def test_halaman_sampah_tanpa_inline_script(client):
    resp = client.get("/sampah")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # Script inline tidak diperbolehkan
    inline_scripts = re.findall(r'<script(?![^>]*src=)[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    for s in inline_scripts:
        assert not s.strip(), f"Ditemukan inline script: {s}"

    # Handler inline tidak diperbolehkan
    assert not re.search(r'\son[a-z]+\s*=', html, re.IGNORECASE)


def test_sampah_js_bebas_window_confirm():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    jalur_js = os.path.join(root, "static", "js", "sampah.js")
    with open(jalur_js, "r", encoding="utf-8") as f:
        teks = f.read()

    assert "window.confirm" not in teks, "sampah.js tidak boleh memakai window.confirm"
    assert "window.alert" not in teks, "sampah.js tidak boleh memakai window.alert"
    assert "KX.konfirmasiHapus" in teks, "sampah.js harus memakai KX.konfirmasiHapus"
    assert "cryptix:reauth-grant" in teks, "sampah.js harus mendengarkan cryptix:reauth-grant"
    assert "trash.purge" in teks, "sampah.js harus meminta scope trash.purge"


def test_sampah_bebas_kata_terlarang():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    kata_terlarang = ["mahasiswa", "dosen", "UAS", "UTS"]
    for jalur in ("templates/sampah.html", "static/js/sampah.js", "static/css/halaman/sampah.css"):
        lengkap = os.path.join(root, jalur)
        with open(lengkap, "r", encoding="utf-8") as f:
            konten = f.read()
        for kata in kata_terlarang:
            assert kata.lower() not in konten.lower(), f"Kata terlarang '{kata}' ditemukan di {jalur}"


def test_lintas_halaman_koleksi_kx(client):
    # Menguji konsistensi respons 200 dan adopsi kx-* di seluruh halaman koleksi & sampah
    rute_koleksi = ["/documents", "/audio", "/media-vault", "/sampah"]
    for rute in rute_koleksi:
        res = client.get(rute)
        assert res.status_code == 200, f"Rute {rute} gagal diakses"
        html = res.get_data(as_text=True)
        assert "kx-" in html, f"Rute {rute} tidak memuat kelas kx-"
        assert "class=\"page-subtitle\"" not in html, f"Rute {rute} masih memiliki page-subtitle"
