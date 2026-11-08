"""
tests/test_password_change.py
─────────────────────────────
Uji butir 2.9: ganti kata sandi di pengaturan wajib grant autentikasi ulang
dan membungkus ulang DEK sehingga data lama tetap dapat dibuka.
"""

import re

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import biometrics
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import create_account
from modules.authentication.password_hash import verify_password
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys
from modules.cryptography.key_management import recover_dek, unlock_dek
from modules.strings import MSG

KATA_SANDI = "Rahasia-Awal-2026!"
KATA_SANDI_BARU = "Rahasia-Baru-2026!"
USERNAME = "pengguna_ganti"
EMAIL = "ganti@contoh.test"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "ganti.db"))
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
    token = usb_mod.register_usb_token(str(tmp_path / "dongle"))
    assert token is not None
    hasil = create_account(USERNAME, EMAIL, KATA_SANDI, token)
    assert hasil["success"], hasil
    application = create_app()
    application.config["TESTING"] = True
    application.config["TEST_RECOVERY_KEY"] = hasil["recovery_key"]
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _token_meta(halaman: str) -> str:
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', halaman)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _masuk(client) -> str:
    """Login dua tahap memakai metode uji agar DEK tersimpan di server."""
    token = _token_meta(client.get("/login").get_data(as_text=True))
    biometrics.tambah_metode(
        "uji", "Metode Uji",
        terdaftar=lambda user_id: True,
        verifikasi=lambda user_id, bukti: bukti == {"kunci": "sah"},
    )
    try:
        resp1 = client.post(
            "/login",
            json={"username": USERNAME, "password": KATA_SANDI},
            headers={"X-CSRFToken": token},
        )
        assert resp1.status_code == 200, resp1.get_data(as_text=True)
        resp2 = client.post(
            "/login/biometric",
            json={"pending": resp1.get_json()["pending"],
                  "bukti": {"uji": {"kunci": "sah"}}},
            headers={"X-CSRFToken": token},
        )
        assert resp2.status_code == 200, resp2.get_data(as_text=True)
    finally:
        biometrics.hapus_metode("uji")
    with client.session_transaction() as sess:
        return sess["session_id"]


def _grant(client, password=KATA_SANDI, scope="settings.change") -> str:
    csrf = _token_meta(client.get("/settings").get_data(as_text=True))
    resp = client.post(
        "/api/reauth",
        json={"method": "password", "scope": scope, "password": password},
        headers={"X-CSRFToken": csrf},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["grant"]


def _baris() -> dict:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE username=?", (USERNAME,)
        ).fetchone()
    return dict(row)


def _ganti(client, grant, csrf, password=KATA_SANDI_BARU, current=KATA_SANDI):
    return client.post(
        "/settings/change-password",
        data={
            "csrf_token": csrf,
            "reauth_grant": grant or "",
            "current_password": current,
            "new_password": password,
            "confirm_password": password,
        },
    )


def test_tombol_ganti_kata_sandi_meminta_reauth(app, client):
    _masuk(client)
    html = client.get("/settings").get_data(as_text=True)
    assert 'data-reauth="settings.change"' in html
    assert 'minlength="12"' in html


def test_tanpa_grant_ditolak(app, client):
    _masuk(client)
    sebelum = _baris()
    csrf = _token_meta(client.get("/settings").get_data(as_text=True))
    resp = _ganti(client, None, csrf)
    assert resp.status_code == 401
    assert resp.get_json()["reason"] == "missing"
    assert _baris() == sebelum


def test_grant_scope_lain_ditolak(app, client):
    _masuk(client)
    sebelum = _baris()
    grant = _grant(client, scope="file.download")
    csrf = _token_meta(client.get("/settings").get_data(as_text=True))
    resp = _ganti(client, grant, csrf)
    assert resp.status_code == 403
    assert resp.get_json()["reason"] == "scope"
    assert _baris() == sebelum


def test_ganti_kata_sandi_membungkus_ulang_dek(app, client):
    sid = _masuk(client)
    dek = session_keys.get(sid)
    assert dek is not None
    sebelum = _baris()
    kunci_pemulihan = app.config["TEST_RECOVERY_KEY"]

    csrf = _token_meta(client.get("/settings").get_data(as_text=True))
    grant = _grant(client)
    resp = _ganti(client, grant, csrf)
    assert resp.status_code == 302
    assert resp.headers["Location"].rstrip("/") in ("", "/login")

    sesudah = _baris()
    assert sesudah["wrapped_dek"] != sebelum["wrapped_dek"]
    assert sesudah["kek_salt"] != sebelum["kek_salt"]
    assert sesudah["recovery_wrapped_dek"] == sebelum["recovery_wrapped_dek"]
    assert verify_password(
        KATA_SANDI_BARU, sesudah["password_hash"], sesudah["salt"]
    )

    sah, rahasia = usb_mod.verify_usb_token(
        sesudah["usb_verifier"], sesudah["usb_volume_serial"],
        sesudah["usb_token_id"],
    )
    assert sah and rahasia is not None
    assert unlock_dek(KATA_SANDI_BARU, rahasia, sesudah) == dek

    # Kunci pemulihan lama tetap membuka DEK yang sama: data dan template
    # biometrik tidak perlu dienkripsi ulang.
    assert recover_dek(kunci_pemulihan, sesudah) == dek

    assert session_keys.get(sid) is None
    assert client.get("/settings").status_code == 302


def test_kata_sandi_baru_sama_ditolak(app, client):
    _masuk(client)
    sebelum = _baris()
    csrf = _token_meta(client.get("/settings").get_data(as_text=True))
    grant = _grant(client)
    resp = _ganti(
        client, grant, csrf,
        password=KATA_SANDI, current=KATA_SANDI,
    )
    assert resp.status_code == 302
    assert _baris() == sebelum


def test_kata_sandi_lemah_ditolak(app, client):
    _masuk(client)
    sebelum = _baris()
    csrf = _token_meta(client.get("/settings").get_data(as_text=True))
    grant = _grant(client)
    resp = _ganti(client, grant, csrf, password="pendek", current=KATA_SANDI)
    assert resp.status_code == 302
    assert _baris() == sebelum
