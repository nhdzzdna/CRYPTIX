"""
Uji tambahan GL: pembatas laju recovery/biometrik dan reveal per pengguna,
galat JSON untuk API, serta penanganan RuntimeError detektor wajah.
"""

import re

import pytest

import config
from app import create_app
from database.db import init_db
from modules.authentication import face_recognition as face_mod
from modules.authentication.auth import register_user
from modules.cryptography import pending_keys, session_keys
from modules.strings import MSG


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "gl.db"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    init_db()
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    body = client.get("/login").get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _masuk_sebagai(client, user_id: int, username: str) -> None:
    sid = session_keys.create_session_id()
    session_keys.put(sid, b"\x01" * 32)
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = username
        sess["session_id"] = sid


class TestLimiterTambahan:
    def test_account_recovery_confirm_dibatasi(self, client):
        csrf = _csrf(client)
        for _ in range(10):
            resp = client.post(
                "/account-recovery/confirm",
                data={"csrf_token": csrf},
                headers={"Accept": "application/json"},
            )
            assert resp.status_code == 302

        resp = client.post(
            "/account-recovery/confirm",
            data={"csrf_token": csrf},
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 429
        badan = resp.get_json()
        assert badan["success"] is False
        assert badan["error"] == MSG.RATE_LIMITED
        assert badan["reason"] == "rate_limit"

    def test_login_biometric_dibatasi(self, client):
        csrf = _csrf(client)
        for _ in range(20):
            resp = client.post(
                "/login/biometric",
                json={"pending": "tidak-ada"},
                headers={"X-CSRFToken": csrf, "Accept": "application/json"},
            )
            assert resp.status_code == 400

        resp = client.post(
            "/login/biometric",
            json={"pending": "tidak-ada"},
            headers={"X-CSRFToken": csrf, "Accept": "application/json"},
        )
        assert resp.status_code == 429
        assert resp.get_json()["reason"] == "rate_limit"


class TestRevealLimitPerPengguna:
    def test_reveal_dibatasi_per_pengguna(self, app, client):
        csrf = _csrf(client)
        _masuk_sebagai(client, 1, "pengguna_satu")

        for i in range(20):
            resp = client.post(
                f"/account-vault/reveal/{i + 1}",
                headers={"X-CSRFToken": csrf, "Accept": "application/json"},
            )
            assert resp.status_code == 401, resp.get_data(as_text=True)

        kena = client.post(
            "/account-vault/reveal/999",
            headers={"X-CSRFToken": csrf, "Accept": "application/json"},
        )
        assert kena.status_code == 429
        assert kena.get_json()["reason"] == "rate_limit"

        lain = app.test_client()
        csrf_lain = _csrf(lain)
        _masuk_sebagai(lain, 2, "pengguna_dua")
        tetap = lain.post(
            "/account-vault/reveal/1",
            headers={"X-CSRFToken": csrf_lain, "Accept": "application/json"},
        )
        assert tetap.status_code == 401


class TestGalatJson:
    def test_api_tidak_ada_json(self, client):
        resp = client.get("/api/tidak-ada")
        assert resp.status_code == 404
        badan = resp.get_json()
        assert badan["success"] is False
        assert badan["error"] == MSG.ERROR_NOT_FOUND
        assert badan["reason"] == "not_found"

    def test_api_metode_salah_json(self, client):
        csrf = _csrf(client)
        resp = client.post(
            "/api/dongle/status", headers={"X-CSRFToken": csrf}
        )
        assert resp.status_code == 405
        badan = resp.get_json()
        assert badan["success"] is False
        assert badan["error"] == MSG.ERROR_METHOD_NOT_ALLOWED
        assert badan["reason"] == "method_not_allowed"

    def test_halaman_tidak_ada_tetap_html(self, client):
        resp = client.get("/halaman-tidak-ada", headers={"Accept": "text/html"})
        assert resp.status_code == 404
        assert "text/html" in resp.content_type
        assert resp.get_json(silent=True) is None


class TestRuntimeErrorWajah:
    def test_register_face_runtime_error_json(self, app, client, monkeypatch):
        hasil = register_user(
            "pengguna_satu",
            "pengguna_satu@contoh.test",
            "Rahasia-Uji-2026!",
        )
        user_id = hasil["user_id"]
        csrf = _csrf(client)
        _masuk_sebagai(client, user_id, "pengguna_satu")

        def _meledak(*_args, **_kwargs):
            raise RuntimeError("cascade Haar tidak tersedia")

        monkeypatch.setattr(face_mod, "daftarkan_wajah", _meledak)

        grant_resp = client.post(
            "/api/reauth",
            json={
                "method": "password",
                "scope": "biometric.manage",
                "password": "Rahasia-Uji-2026!",
            },
            headers={"X-CSRFToken": csrf},
        )
        assert grant_resp.status_code == 200, grant_resp.get_data(as_text=True)
        grant = grant_resp.get_json()["grant"]

        resp = client.post(
            "/api/register_face",
            json={"frames": ["a"] * 30, "duration_ms": 3000},
            headers={
                "X-CSRFToken": csrf,
                "X-Reauth-Grant": grant,
            },
        )
        assert resp.status_code == 500
        badan = resp.get_json()
        assert badan["success"] is False
        assert badan["error"] == MSG.FACE_DETECTOR_UNAVAILABLE
        teks = resp.get_data(as_text=True)
        assert "Traceback" not in teks
        assert "RuntimeError" not in teks

    def test_verify_face_runtime_error_json(self, client, monkeypatch):
        csrf = _csrf(client)
        token = pending_keys.letakkan(1, b"\x02" * 32)
        with client.session_transaction() as sess:
            sess["login_stage"] = 1
            sess["login_pending"] = token

        def _meledak(*_args, **_kwargs):
            raise RuntimeError("cascade Haar tidak tersedia")

        monkeypatch.setattr(face_mod, "verifikasi_wajah", _meledak)
        resp = client.post(
            "/api/verify_face",
            json={"pending": token, "frames": ["a"] * 5},
            headers={"X-CSRFToken": csrf},
        )
        assert resp.status_code == 500
        badan = resp.get_json()
        assert badan["success"] is False
        assert badan["error"] == MSG.FACE_DETECTOR_UNAVAILABLE
        teks = resp.get_data(as_text=True)
        assert "Traceback" not in teks
        assert "RuntimeError" not in teks

    def test_verify_face_runtime_error_json(self, client, monkeypatch):
        csrf = _csrf(client)
        token = pending_keys.letakkan(1, b"\x02" * 32)
        with client.session_transaction() as sess:
            sess["login_stage"] = 1
            sess["login_pending"] = token

        def _meledak(*_args, **_kwargs):
            raise RuntimeError("cascade Haar tidak tersedia")

        monkeypatch.setattr(face_mod, "verifikasi_wajah", _meledak)
        resp = client.post(
            "/api/verify_face",
            json={"pending": token, "frames": ["a"] * 5},
            headers={"X-CSRFToken": csrf},
        )
        assert resp.status_code == 500
        badan = resp.get_json()
        assert badan["success"] is False
        assert badan["error"] == MSG.FACE_DETECTOR_UNAVAILABLE
        teks = resp.get_data(as_text=True)
        assert "Traceback" not in teks
        assert "RuntimeError" not in teks
