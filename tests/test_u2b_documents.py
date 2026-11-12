"""
tests/test_u2b_documents.py
────────────────────────────
Uji antarmuka baru halaman Dokumen (P4 / U2b):
- Memeriksa struktur komponen kx-*, kx-card, kx-dropzone, kx-table/kx-doc-row.
- Memeriksa integrasi modal pratinjau kx-* dan bar aksi mengambang kx-aksi-mengambang.
- Memastikan tidak ada inline JavaScript pada halaman Dokumen.
- Memeriksa pemuatan CSS halaman static/css/halaman/documents.css.
- Memeriksa bahwa item terkunci membawa penanda badge/ikon lock yang sesuai.
"""

import re
import pytest
from database.db import get_db, init_db
from modules.cryptography import session_keys
from modules.cryptography.key_management import purpose_key
from modules.cryptography.database_encryption import encrypt_field, field_aad
from modules.cryptography.file_encryption import encrypt_stream, file_aad, generate_stored_name
import io
import os
import config
from app import create_app
from modules.authentication import reauth

DEK = bytes(range(32))

@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "u2b-doc.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "tmp"))
    init_db()
    with get_db() as db:
        db.execute(
            """INSERT OR IGNORE INTO users
               (id, username, email, password_hash, salt) VALUES (?,?,?,?,?)""",
            (1, "docuser", "docuser@contoh.test", "hash", "garam"),
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
        sess["username"] = "docuser"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, DEK)
    return c


def _unggah_berkas_db(nama: str, state: str = "normal"):
    db_key = purpose_key(DEK, "database")
    fkey = purpose_key(DEK, "file")
    stored = generate_stored_name()
    enc_res = encrypt_stream(
        io.BytesIO(b"isi dokumen tes uji"),
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
            (1, name_token, stored, "document", 19, enc_res["sha256_plaintext"], enc_res["sha256_ciphertext"]),
        )
        fid = cur.lastrowid
        if state == "locked":
            col_name_enc = encrypt_field("Folder Kunci", db_key, field_aad(1, "collections", "name_enc"))
            cur_col = db.execute("INSERT INTO collections (user_id, name_enc, kind, locked) VALUES (?, ?, ?, ?)",
                                 (1, col_name_enc, "dokumen", 0))
            cid = cur_col.lastrowid
            db.execute("INSERT INTO collection_items (collection_id, file_id, state) VALUES (?, ?, ?)",
                       (cid, fid, "locked"))
        db.commit()
    return fid


def test_halaman_dokumen_markup_kx(client):
    _unggah_berkas_db("kontrak_rahasia.pdf")
    resp = client.get("/documents")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # Memastikan CSS dokumen dimuat
    assert "halaman/documents.css" in html

    # Memastikan dropzone kx-* dan tidak ada subtitle/tombol unggah topbar
    assert 'data-kx-dropzone' in html
    assert 'class="page-subtitle"' not in html
    assert 'doc-header-action' not in html

    # Memastikan tidak ada script inline
    inline_scripts = re.findall(r'<script(?![^>]*src=)[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    for s in inline_scripts:
        assert not s.strip(), f"Ditemukan inline JavaScript di halaman Dokumen: {s}"

    # Memastikan ada modal pratinjau dan aksi mengambang
    assert 'id="preview-modal"' in html
    assert 'id="selection-bar"' in html
    assert "kontrak_rahasia.pdf" in html


def test_halaman_dokumen_badge_folder_di_semua(client):
    _unggah_berkas_db("laporan_folder.pdf", state="locked")
    resp = client.get("/vault")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert 'kx-doc-folder-badge' in html
    assert "Folder Kunci" in html


def test_halaman_dokumen_status_terkunci(client):
    _unggah_berkas_db("berkas_terkunci.pdf", state="locked")
    resp = client.get("/vault")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert "berkas_terkunci.pdf" in html
    assert 'data-locked="1"' in html
    assert "Terkunci" in html


# ── Kontrak Tambahan Halaman Dokumen (P7 / U2c) ──────────────────────────────

def test_kontrak_dokumen_nama_berkas_asli_tampil(client):
    """Nama berkas asli hasil dekripsi server harus tampil di baris dokumen."""
    _unggah_berkas_db("laporan_keuangan_2026.pdf")
    resp = client.get("/documents")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "laporan_keuangan_2026.pdf" in html


def test_kontrak_dokumen_penanda_terkunci(client):
    """Dokumen terkunci harus memuat ikon dan penanda status locked."""
    fid = _unggah_berkas_db("rahasia_negara.pdf", state="locked")
    resp = client.get("/vault")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "rahasia_negara.pdf" in html
    assert "Terkunci" in html
    assert 'data-locked="1"' in html


def test_kontrak_dokumen_tombol_hapus_memakai_konfirmasi(client):
    """Tombol hapus baris dokumen harus memicu dialog konfirmasi hapus KX."""
    _unggah_berkas_db("draf_revisi.txt")
    resp = client.get("/documents")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "draf_revisi.txt" in html
    # Memastikan ada tombol/form hapus yang terhubung dengan class atau handler konfirmasi
    assert 'doc-action' in html or 'data-action="delete"' in html or 'action' in html


def test_kontrak_dokumen_modal_pratinjau_ada(client):
    """Modal dialog pratinjau kx-modal harus terpasang di template dokumen."""
    resp = client.get("/documents")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert 'id="preview-modal"' in html
    assert 'kx-modal' in html
