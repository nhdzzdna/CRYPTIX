"""
tests/test_account_recovery.py
──────────────────────────────
Uji butir 2.8: pemulihan akun dengan kunci pemulihan, pembungkusan ulang DEK
memakai kata sandi dan dongle baru, serta penerbitan kunci pemulihan baru.
"""

import re

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import create_account, verifikasi_tahap_satu
from modules.authentication.password_hash import verify_password
from modules.blockchain import blockchain as bc
from modules.cryptography.key_management import recover_dek
from modules.strings import MSG

KATA_SANDI = "Rahasia-Awal-2026!"
KATA_SANDI_BARU = "Rahasia-Baru-2026!"
USERNAME = "pengguna_pulih"
EMAIL = "pulih@contoh.test"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "pulih.db"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    dongle_lama = tmp_path / "dongle_lama"
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(dongle_lama))
    monkeypatch.setattr(usb_mod, "_get_removable_drives", lambda: [])
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    init_db()
    token = usb_mod.register_usb_token(str(dongle_lama))
    assert token is not None
    hasil = create_account(USERNAME, EMAIL, KATA_SANDI, token)
    assert hasil["success"], hasil
    application = create_app()
    application.config["TESTING"] = True
    application.config["TEST_RECOVERY_KEY"] = hasil["recovery_key"]
    application.config["TEST_TMP"] = str(tmp_path)
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _csrf(halaman_html: str) -> str:
    cocok = re.search(r'name="csrf_token" value="([^"]+)"', halaman_html)
    assert cocok, "token CSRF tidak ditemukan"
    return cocok.group(1)


def _kunci_dari(halaman_html: str) -> str:
    cocok = re.search(r'<code id="recovery-key"[^>]*>([^<]+)</code>', halaman_html)
    assert cocok, "kunci pemulihan tidak ditampilkan"
    return cocok.group(1).strip()


def _pending_dari(halaman_html: str) -> str:
    cocok = re.search(r'name="pending" value="([^"]+)"', halaman_html)
    assert cocok, "token pending tidak ditemukan"
    return cocok.group(1)


def _baris() -> dict:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE username=?", (USERNAME,)
        ).fetchone()
    return dict(row)


def test_halaman_pemulihan_dan_tautan_login(app, client):
    halaman = client.get("/account-recovery")
    assert halaman.status_code == 200
    assert "Kunci Pemulihan" in halaman.get_data(as_text=True)

    masuk = client.get("/login").get_data(as_text=True)
    assert 'href="/account-recovery"' in masuk
    assert "Pulihkan akun" in masuk


def test_pemulihan_sukses_mempertahankan_dek(app, client, tmp_path, monkeypatch):
    sebelum = _baris()
    kunci_lama = app.config["TEST_RECOVERY_KEY"]
    dek_lama = recover_dek(kunci_lama, sebelum)

    dongle_baru = tmp_path / "dongle_baru"
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(dongle_baru))

    halaman = client.get("/account-recovery").get_data(as_text=True)
    csrf = _csrf(halaman)
    resp = client.post(
        "/account-recovery",
        data={
            "csrf_token": csrf,
            "username": USERNAME,
            "recovery_key": kunci_lama,
            "password": KATA_SANDI_BARU,
            "confirm_password": KATA_SANDI_BARU,
            "dongle": str(dongle_baru),
        },
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)[:500]
    html = resp.get_data(as_text=True)
    assert resp.headers["Cache-Control"].startswith("no-store")
    kunci_baru = _kunci_dari(html)
    pending = _pending_dari(html)
    assert kunci_baru != kunci_lama

    sesudah = _baris()
    assert sesudah["wrapped_dek"] != sebelum["wrapped_dek"]
    assert sesudah["recovery_wrapped_dek"] != sebelum["recovery_wrapped_dek"]
    assert sesudah["usb_token_id"] != sebelum["usb_token_id"]
    assert sesudah["failed_attempts"] == 0
    assert sesudah["locked_until"] is None
    assert verify_password(KATA_SANDI_BARU, sesudah["password_hash"], sesudah["salt"])

    # DEK tidak berubah: berkas dan template biometrik tetap dapat dibuka.
    assert recover_dek(kunci_baru, sesudah) == dek_lama

    hasil = verifikasi_tahap_satu(USERNAME, KATA_SANDI_BARU)
    assert hasil["success"], hasil
    assert hasil["dek"] == dek_lama

    konfirmasi = client.post(
        "/account-recovery/confirm",
        data={
            "csrf_token": _csrf(html),
            "pending": pending,
            "confirm_saved": "1",
        },
    )
    assert konfirmasi.status_code == 302
    assert konfirmasi.headers["Location"].rstrip("/") in ("", "/login")

    ulang = client.post(
        "/account-recovery/confirm",
        data={
            "csrf_token": _csrf(client.get("/login").get_data(as_text=True)),
            "pending": pending,
            "confirm_saved": "1",
        },
    )
    assert ulang.status_code == 302
    assert ulang.headers["Location"].rstrip("/") in ("", "/login")


def test_kunci_pemulihan_salah_ditolak(app, client):
    sebelum = _baris()
    html = client.get("/account-recovery").get_data(as_text=True)
    resp = client.post(
        "/account-recovery",
        data={
            "csrf_token": _csrf(html),
            "username": USERNAME,
            "recovery_key": "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-GGGGG",
            "password": KATA_SANDI_BARU,
            "confirm_password": KATA_SANDI_BARU,
            "dongle": str(app.config["TEST_TMP"]),
        },
    )
    assert resp.status_code == 200
    assert MSG.ACCOUNT_RECOVERY_FAILED in resp.get_data(as_text=True)
    assert _baris() == sebelum


def test_nama_pengguna_tidak_dikenal_gagal_umum(app, client):
    html = client.get("/account-recovery").get_data(as_text=True)
    resp = client.post(
        "/account-recovery",
        data={
            "csrf_token": _csrf(html),
            "username": "tidak_ada_akun",
            "recovery_key": "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-GGGGG",
            "password": KATA_SANDI_BARU,
            "confirm_password": KATA_SANDI_BARU,
            "dongle": str(app.config["TEST_TMP"]),
        },
    )
    assert resp.status_code == 200
    assert MSG.ACCOUNT_RECOVERY_FAILED in resp.get_data(as_text=True)


def test_pemulihan_dibatasi_lajunya(app, client):
    html = client.get("/account-recovery").get_data(as_text=True)
    csrf = _csrf(html)
    status = []
    for _ in range(11):
        status.append(
            client.post(
                "/account-recovery",
                data={
                    "csrf_token": csrf,
                    "username": "tidak_ada_akun",
                    "recovery_key": "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-GGGGG",
                    "password": KATA_SANDI_BARU,
                    "confirm_password": KATA_SANDI_BARU,
                    "dongle": str(app.config["TEST_TMP"]),
                },
            ).status_code
        )
    assert status[:10] == [200] * 10
    assert status[10] == 429
