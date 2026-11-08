"""
tests/test_reauth_webauthn.py
──────────────────────────────
Uji langkah 0 Sesi G: metode WebAuthn pada autentikasi ulang (step-up).
Tantangan diterbitkan lewat endpoint khusus, sekali pakai, dan grant baru
terbit hanya setelah respons autentikator palsu terverifikasi.
"""

import re

import pytest
from webauthn.helpers import base64url_to_bytes

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth, webauthn
from modules.authentication.auth import register_user
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys
from modules.strings import MSG
from tests.test_webauthn import _Autentikator

KATA_SANDI = "KataSandi-Reauth-2026!"
USERNAME = "pemilik_reauth"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "reauth_wa.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    init_db()
    application = create_app()
    application.config["TESTING"] = True
    reauth.clear()
    yield application
    reauth.clear()


@pytest.fixture()
def pengguna(app):
    hasil = register_user(USERNAME, "pemilik@contoh.test", KATA_SANDI)
    assert hasil["success"], hasil
    return hasil["user_id"]


def _client(app, user_id: int):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = USERNAME
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
    session_keys.put(sid, b"\x11" * 32)
    return c


def _csrf(client, halaman: str = "/settings") -> str:
    body = client.get(halaman).get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _daftarkan(user_id: int) -> _Autentikator:
    aut = _Autentikator()
    tantangan = webauthn.tantangan_baru(webauthn.kunci_daftar(user_id))
    hasil = webauthn.daftarkan_kredensial(
        user_id, aut.respons_daftar(tantangan), "uji"
    )
    assert hasil["success"] is True, hasil
    return aut


def _opsi(client, csrf: str):
    return client.post(
        "/api/reauth/webauthn/options", json={},
        headers={"X-CSRFToken": csrf},
    )


def _reauth(client, csrf: str, bukti):
    return client.post(
        "/api/reauth",
        json={
            "method": "webauthn",
            "scope": "settings.change",
            "resource_id": None,
            "response": bukti,
        },
        headers={"X-CSRFToken": csrf},
    )


def _blok_reauth() -> list[dict]:
    with get_db() as db:
        return [
            dict(baris) for baris in db.execute(
                "SELECT * FROM blockchain_log WHERE action = 'REAUTH'"
            )
        ]


class TestReauthWebAuthn:
    def test_opsi_tanpa_sesi_ditolak(self, app):
        client = app.test_client()
        csrf = _csrf(client, "/login")
        resp = _opsi(client, csrf)
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.SESSION_EXPIRED

    def test_opsi_tanpa_kredensial_ditolak(self, app, pengguna):
        client = _client(app, pengguna)
        resp = _opsi(client, _csrf(client))
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.REAUTH_WEBAUTHN_NONE

    def test_webauthn_menerbitkan_grant(self, app, pengguna):
        client = _client(app, pengguna)
        aut = _daftarkan(pengguna)
        csrf = _csrf(client)

        resp = _opsi(client, csrf)
        assert resp.status_code == 200
        opsi = resp.get_json()["options"]
        assert opsi["userVerification"] == "required"
        assert opsi["allowCredentials"][0]["id"]

        tantangan = base64url_to_bytes(opsi["challenge"])
        hasil = _reauth(client, csrf, aut.respons_masuk(tantangan, sign_count=2))
        assert hasil.status_code == 200, hasil.get_data(as_text=True)
        data = hasil.get_json()
        assert data["success"] is True
        assert data["scope"] == "settings.change"
        assert len(_blok_reauth()) == 1

    def test_tantangan_sekali_pakai_setelah_sukses(self, app, pengguna):
        client = _client(app, pengguna)
        aut = _daftarkan(pengguna)
        csrf = _csrf(client)

        opsi = _opsi(client, csrf).get_json()["options"]
        tantangan = base64url_to_bytes(opsi["challenge"])
        bukti = aut.respons_masuk(tantangan, sign_count=1)
        assert _reauth(client, csrf, bukti).status_code == 200

        ulang = _reauth(client, csrf, bukti)
        assert ulang.status_code == 401
        assert ulang.get_json()["error"] == MSG.REAUTH_WEBAUTHN_FAILED

    def test_tantangan_salah_ditolak(self, app, pengguna):
        client = _client(app, pengguna)
        aut = _daftarkan(pengguna)
        csrf = _csrf(client)
        _opsi(client, csrf)

        bukti = aut.respons_masuk(b"\x00" * 32, sign_count=1)
        resp = _reauth(client, csrf, bukti)
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.REAUTH_WEBAUTHN_FAILED
        assert _blok_reauth() == []

    def test_tanpa_opsi_sebelumnya_ditolak(self, app, pengguna):
        client = _client(app, pengguna)
        aut = _daftarkan(pengguna)
        csrf = _csrf(client)

        resp = _reauth(client, csrf, aut.respons_masuk(b"\x01" * 32, sign_count=1))
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.REAUTH_WEBAUTHN_FAILED
