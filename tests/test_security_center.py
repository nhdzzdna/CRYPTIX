"""
tests/test_security_center.py
─────────────────────────────
Uji Sesi K butir 4.6: tombol Verifikasi Integritas menjalankan verify_chain
dan verify_assets, menampilkan status rantai global serta status tiap aset
milik pengguna, dan tidak menampilkan blok milik pengguna lain.
"""

import hashlib
import os
import re

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication.auth import register_user
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys

PASSWORD = "KataSandi-Security-2026!"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "security.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    monkeypatch.setattr(bc, "_verifikasi_terakhir", {})
    os.makedirs(config.ENCRYPTED_FILES_DIR, exist_ok=True)
    init_db()
    application = create_app()
    application.config["TESTING"] = True
    return application


def _pengguna(nama: str, email: str) -> int:
    hasil = register_user(nama, email, PASSWORD)
    assert hasil["success"], hasil
    return hasil["user_id"]


def _client(app, user_id: int, username: str):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = username
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
    session_keys.put(sid, b"\x5a" * 32)
    return client


def _csrf(client) -> str:
    body = client.get("/security-center").get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _tambah_berkas(user_id: int, nama: str, isi: bytes, dengan_blok=True) -> int:
    """Simpan berkas terenkripsi + baris vault_files dan blok UPLOAD opsional."""
    stored = f"{user_id}_{nama}.enc"
    path = os.path.join(config.ENCRYPTED_FILES_DIR, stored)
    with open(path, "wb") as handle:
        handle.write(isi)
    sidik = hashlib.sha256(isi).hexdigest()
    with get_db() as db:
        kursor = db.execute(
            "INSERT INTO vault_files "
            "(user_id, original_name, stored_name, file_type, file_size, "
            " sha256_hash, sha256_ciphertext) VALUES (?,?,?,?,?,?,?)",
            (user_id, nama, stored, "document", len(isi), sidik, sidik),
        )
        db.commit()
        aset_id = kursor.lastrowid
    if dengan_blok:
        bc.add_block(user_id, "UPLOAD", f"file:{aset_id}", sidik)
    return aset_id


def test_tombol_verifikasi_dan_status_aset(app):
    user = _pengguna("pemilik_aset", "aset@contoh.test")
    client = _client(app, user, "pemilik_aset")

    ok_id = _tambah_berkas(user, "ok", b"isi-asli")
    ubah_id = _tambah_berkas(user, "ubah", b"isi-asli")
    hilang_id = _tambah_berkas(user, "hilang", b"isi-hilang")
    tanpa_id = _tambah_berkas(user, "tanpa", b"isi-tanpa", dengan_blok=False)

    # Ubah isi berkas di disk dan hapus berkas lain.
    with open(os.path.join(config.ENCRYPTED_FILES_DIR, f"{user}_ubah.enc"), "wb") as f:
        f.write(b"isi-dimanipulasi")
    os.remove(os.path.join(config.ENCRYPTED_FILES_DIR, f"{user}_hilang.enc"))

    resp = client.post(
        "/security-center/verify",
        data={"csrf_token": _csrf(client)},
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert "Rantai global utuh" in html
    assert "✅ OK" in html
    assert "⚠ DIUBAH" in html
    assert "🗂 HILANG" in html
    assert "❔ TANPA CATATAN" in html
    assert f"file:{ok_id}" in html
    assert f"file:{ubah_id}" in html
    assert f"file:{hilang_id}" in html
    assert f"file:{tanpa_id}" in html


def test_hanya_blok_milik_pengguna_yang_tampil(app):
    pemilik = _pengguna("pemilik_blok", "blok@contoh.test")
    lain = _pengguna("pengguna_lain", "lain@contoh.test")
    client = _client(app, pemilik, "pemilik_blok")

    bc.add_block(pemilik, "UPLOAD", "file:1", "a" * 64)
    bc.add_block(lain, "DELETE", "file:2", "b" * 64)

    html = client.get("/security-center").get_data(as_text=True)
    assert "UPLOAD" in html
    assert "DELETE" not in html
    # Blok milik pengguna lain tidak pernah dirender sebagai baris tabel.
    assert "user_id" not in html


def test_verifikasi_menyimpan_hasil_terakhir(app):
    user = _pengguna("pemilik_verifikasi", "verifikasi@contoh.test")
    client = _client(app, user, "pemilik_verifikasi")
    bc.add_block(user, "LOGIN", "auth:login", "c" * 64)

    assert bc.get_last_verification(user) is None
    resp = client.post(
        "/security-center/verify",
        data={"csrf_token": _csrf(client)},
    )
    assert resp.status_code == 200

    hasil = bc.get_last_verification(user)
    assert hasil is not None
    assert hasil["total_blocks"] == 1
    assert hasil["tampered_blocks"] == 0
    assert hasil["valid"] is True
    assert hasil["head_hash"]


def test_rantai_rusak_ditandai_global(app):
    user = _pengguna("pemilik_rusak", "rusak@contoh.test")
    client = _client(app, user, "pemilik_rusak")
    bc.add_block(user, "LOGIN", "auth:login", "d" * 64)
    with get_db() as db:
        db.execute("UPDATE blockchain_log SET asset_hash='diubah'")
        db.commit()

    resp = client.post(
        "/security-center/verify",
        data={"csrf_token": _csrf(client)},
    )
    html = resp.get_data(as_text=True)
    assert "TERDETEKSI RUSAK" in html
    assert "1 blok" in html
