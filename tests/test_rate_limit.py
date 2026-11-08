"""
tests/test_rate_limit.py
────────────────────────
Uji butir 2.7: pembatas laju endpoint sensitif dan kunci akun sementara
setelah lima kegagalan masuk beruntun.
"""

import re

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import auth
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import create_account
from modules.blockchain import blockchain as bc
from modules.strings import MSG

KATA_SANDI = "Rahasia-Batas-2026!"
USERNAME = "pengguna_batas"
EMAIL = "batas@contoh.test"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "batas.db"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(tmp_path / "dongle"))
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    monkeypatch.setattr(usb_mod, "_get_removable_drives", lambda: [])
    init_db()
    token = usb_mod.register_usb_token(str(tmp_path / "dongle"))
    assert token is not None
    hasil = create_account(USERNAME, EMAIL, KATA_SANDI, token)
    assert hasil["success"], hasil
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _csrf(client, halaman="/login") -> str:
    body = client.get(halaman).get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _login(client, csrf, username=USERNAME, password=KATA_SANDI):
    return client.post(
        "/login",
        json={"username": username, "password": password},
        headers={"X-CSRFToken": csrf},
    )


def _baris() -> dict:
    with get_db() as db:
        baris = db.execute(
            "SELECT * FROM users WHERE username=?", (USERNAME,)
        ).fetchone()
    return dict(baris)


class TestKunciAkun:
    def test_lima_gagal_mengunci_akun(self, app, client):
        csrf = _csrf(client)
        for _ in range(5):
            resp = _login(client, csrf, password="kata-sandi-salah-99")
            assert resp.status_code == 401
            assert resp.get_json()["error"] == MSG.LOGIN_STAGE1_FAILED

        baris = _baris()
        assert baris["failed_attempts"] == 5
        assert baris["locked_until"] is not None

        # kata sandi benar tetap ditolak selama kunci aktif
        terkunci = _login(client, csrf)
        assert terkunci.status_code == 401
        assert terkunci.get_json()["error"] == MSG.LOGIN_STAGE1_FAILED

        with get_db() as db:
            jumlah = db.execute(
                "SELECT COUNT(*) FROM blockchain_log WHERE action='LOGIN_FAIL'"
            ).fetchone()[0]
        assert jumlah >= 1

    def test_masuk_berhasil_mereset_hitungan(self, app, client):
        csrf = _csrf(client)
        for _ in range(4):
            assert _login(
                client, csrf, password="kata-sandi-salah-99"
            ).status_code == 401

        sukses = _login(client, csrf)
        assert sukses.status_code == 200
        baris = _baris()
        assert baris["failed_attempts"] == 0
        assert baris["locked_until"] is None

    def test_eskalasi_durasi_kunci(self):
        assert auth.durasi_kunci(4) is None
        assert auth.durasi_kunci(5) == 60
        assert auth.durasi_kunci(10) == 5 * 60
        assert auth.durasi_kunci(15) == 15 * 60
        assert auth.durasi_kunci(20) == 30 * 60
        assert auth.durasi_kunci(99) == 30 * 60


class TestPembatasLaju:
    def test_login_dibatasi_setelah_lima_belas_percobaan(self, app, client):
        csrf = _csrf(client)
        status = [
            _login(client, csrf, username="tidak_ada", password="salah-123456")
            .status_code
            for _ in range(16)
        ]
        assert status[:15] == [401] * 15
        assert status[15] == 429

    def test_verifikasi_wajah_dibatasi(self, app, client):
        csrf = _csrf(client)
        status = [
            client.post(
                "/api/verify_face",
                json={"frames": ["a"] * 5},
                headers={"X-CSRFToken": csrf},
            ).status_code
            for _ in range(21)
        ]
        assert status[:20] == [401] * 20
        assert status[20] == 429
