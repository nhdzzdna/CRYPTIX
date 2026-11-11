"""
tests/test_n1_awal.py
─────────────────────
Uji N1: kunci pemulihan tidak hilang/berpindah otomatis, penolakan
pendaftaran wajah di bawah ambang atau dengan banyak wajah, dan username
tersamar pada daftar Account Vault.
"""

import os
import re
from pathlib import Path

import numpy as np
import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import face_recognition as face_mod
from modules.authentication import usb_authentication as usb_mod
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys
from modules.strings import MSG
from modules.username_masking import samarkan_username

ROOT = Path(__file__).resolve().parent.parent
KATA_SANDI = "Rahasia-N1-2026!"
USERNAME = "pemulih_n1"
EMAIL = "pemulih@contoh.test"
MASTER = bytes([0x5a]) * 32


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "n1.db"))
    monkeypatch.setattr(config, "STORAGE_ROOT", str(tmp_path / "storage"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(tmp_path / "dongle"))
    monkeypatch.setattr(usb_mod, "_get_removable_drives", lambda: [])
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    init_db()
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def client_akun(app):
    with get_db() as db:
        db.execute(
            "INSERT INTO users (id, username, email, password_hash, salt) "
            "VALUES (1, ?, ?, 'hash-tidak-dipakai', 'garam')",
            (USERNAME, EMAIL),
        )
        db.commit()
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = USERNAME
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, MASTER)
    return c


def _csrf(client, halaman="/register") -> str:
    page = client.get(halaman)
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    if cocok is None:
        cocok = re.search(r'name="csrf_token" value="([^"]+)"', body)
    assert cocok, "token CSRF tidak ditemukan"
    return cocok.group(1)


def _csrf_form(client, halaman="/account-vault") -> str:
    body = client.get(halaman).get_data(as_text=True)
    cocok = re.search(r'name="csrf_token" value="([^"]+)"', body)
    assert cocok, "token CSRF form tidak ditemukan"
    return cocok.group(1)


def _isi_register(client):
    return client.post("/register", data={
        "username": USERNAME,
        "email": EMAIL,
        "password": KATA_SANDI,
        "confirm_password": KATA_SANDI,
        "dongle": config.DEV_DONGLE_DIR,
        "csrf_token": _csrf(client, "/register"),
    })


class TestKunciPemulihan:
    def test_halaman_tanpa_pengalihan_otomatis_dan_kontrol_lengkap(
        self, app, client
    ):
        resp = _isi_register(client)
        body = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert resp.headers["Cache-Control"].startswith("no-store")
        assert 'id="recovery-key"' in body
        assert "Kunci ini membuka akun bila password atau dongle hilang" in body
        assert 'id="btn-copy-recovery"' in body
        assert 'id="btn-download-recovery"' in body
        assert 'id="confirm_saved"' in body
        assert re.search(
            r'id="btn-recovery-continue"[^>]*\bdisabled\b', body
        )
        assert "js/recovery.js" in body

        # tidak ada meta refresh dan kotak kunci bukan elemen .alert yang
        # dihapus otomatis oleh script.js setelah lima detik
        assert not re.search(r"http-equiv=[\"']?refresh", body, re.IGNORECASE)
        tag = re.search(r'<[^>]*id="recovery-key"[^>]*>', body)
        assert tag and "alert" not in tag.group(0).lower()

        skrip = (ROOT / "static" / "js" / "recovery.js").read_text(
            encoding="utf-8"
        )
        assert "window.location" not in skrip
        assert "location.href" not in skrip
        assert "setTimeout" not in skrip

        cookie = client.get_cookie("session")
        assert cookie is not None
        assert "recovery-key" not in cookie.value


class TestPendaftaranWajah:
    def test_deteksi_di_bawah_80_persen_ditolak(self, monkeypatch):
        monkeypatch.setattr(face_mod, "_decode_frame", lambda item: item)

        def _wajah(frame):
            nomor = int(str(frame).split("-")[1])
            if nomor >= 23:
                return []
            return [np.full((200, 200), nomor, dtype=np.uint8)]

        monkeypatch.setattr(face_mod, "_deteksi_semua_wajah", _wajah)
        monkeypatch.setattr(face_mod, "_mata_terbuka", lambda roi: True)
        hasil = face_mod.daftarkan_wajah(
            1, [f"frame-{i}" for i in range(30)], b"x" * 32
        )
        assert hasil["success"] is False
        assert hasil["error"] == MSG.FACE_LOW_DETECTION_RATE

    def test_lebih_dari_satu_wajah_ditolak(self, monkeypatch):
        monkeypatch.setattr(face_mod, "_decode_frame", lambda item: item)

        def _wajah(frame):
            nomor = int(str(frame).split("-")[1])
            roi = np.full((200, 200), nomor, dtype=np.uint8)
            # Sepuluh dari tiga puluh frame memuat wajah sekunder (33%),
            # melewati ambang 30% sehingga pendaftaran harus ditolak.
            return [roi, roi] if nomor < 10 else [roi]

        monkeypatch.setattr(face_mod, "_deteksi_semua_wajah", _wajah)
        monkeypatch.setattr(face_mod, "_mata_terbuka", lambda roi: True)
        hasil = face_mod.daftarkan_wajah(
            1, [f"frame-{i}" for i in range(30)], b"x" * 32
        )
        assert hasil["success"] is False
        assert hasil["error"] == MSG.FACE_MULTIPLE_FACES

    def test_skrip_wajah_dan_kontrol_penyiapan_ada(self):
        teks = (ROOT / "static" / "js" / "face.js").read_text(encoding="utf-8")
        assert teks.count("function kirimPendaftaran(") == 1
        assert "window.CryptixFace = { daftar: daftar, tangkap: tangkap }" in teks
        setup = (ROOT / "templates" / "setup.html").read_text(encoding="utf-8")
        assert 'id="setup-face-live"' in setup
        assert 'id="setup-face-progress"' in setup
        assert "MSG.SETUP_FACE_PRIVACY" in setup
        assert "sekitar 30 gambar" in MSG.SETUP_FACE_PRIVACY


class TestUsernameTersamar:
    def test_aturan_penyamar(self):
        assert samarkan_username("alice@contoh.test") == "al***@contoh.test"
        assert samarkan_username("bob") == "bo***"
        assert samarkan_username("") == "***"
        assert samarkan_username("a") == "***"
        assert samarkan_username("a@contoh.test") == "***@contoh.test"

    def test_daftar_menampilkan_username_tersamar_tanpa_bentuk_lengkap(
        self, client_akun
    ):
        lengkap = "rahasia.pengguna@contoh.test"
        token = _csrf_form(client_akun)
        resp = client_akun.post("/account-vault/add", data={
            "csrf_token": token,
            "site_name": "Situs N1",
            "username": lengkap,
            "password": "Kata-Sandi-N1!",
            "url": "https://n1.test",
            "notes": "catatan",
        })
        assert resp.status_code == 302

        body = client_akun.get("/account-vault").get_data(as_text=True)
        assert "Situs N1" in body
        assert "ra***@contoh.test" in body
        assert lengkap not in body
        assert "rahasia.pengguna" not in body
        assert "Kata-Sandi-N1!" not in body
