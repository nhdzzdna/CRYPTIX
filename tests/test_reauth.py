"""
tests/test_reauth.py
────────────────────
Uji autentikasi ulang (step-up): penerbitan grant lewat kata sandi, pencatatan
blok REAUTH, penolakan grant kedaluwarsa, milik sesi lain, sekali pakai,
scope/resource salah, serta grant media.stream yang dapat dipakai berulang.
"""

import logging
import re

import pytest
from flask import jsonify

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth
from modules.authentication.password_hash import hash_password
from modules.cryptography import session_keys
from modules.strings import MSG

DEK = bytes(range(32))
PASSWORD = "KataSandi-Uji-2026!"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "reauth.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    init_db()

    pw_hash, salt = hash_password(PASSWORD)
    with get_db() as db:
        db.execute(
            """INSERT INTO users (id, username, email, password_hash, salt)
               VALUES (?,?,?,?,?)""",
            (1, "penguji", "penguji@contoh.test", pw_hash, salt),
        )
        db.commit()

    application = create_app()
    application.config["TESTING"] = True

    def file_view(resource_id: int):
        return jsonify({"ok": True, "resource_id": resource_id})

    def stream_view(resource_id: int):
        return jsonify({"ok": True, "resource_id": resource_id})

    application.add_url_rule(
        "/uji/file/<int:resource_id>", "uji_file",
        reauth.require_grant("file.download")(file_view),
        methods=["GET", "POST"],
    )
    application.add_url_rule(
        "/uji/stream/<int:resource_id>", "uji_stream",
        reauth.require_grant("media.stream")(stream_view),
    )

    reauth.clear()
    yield application
    reauth.clear()


def _client(app):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "penguji"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
    session_keys.put(sid, DEK)
    return c


@pytest.fixture()
def client(app):
    return _client(app)


@pytest.fixture()
def client_lain(app):
    return _client(app)


def _csrf(client) -> str:
    halaman = client.get("/media-vault")
    assert halaman.status_code == 200
    cocok = re.search(
        r'<meta name="csrf-token" content="([^"]+)"',
        halaman.get_data(as_text=True),
    )
    assert cocok
    return cocok.group(1)


def _minta_grant(client, scope="file.download", resource_id=7,
                 password=PASSWORD, method="password"):
    return client.post(
        "/api/reauth",
        json={
            "method": method,
            "scope": scope,
            "resource_id": resource_id,
            "password": password,
        },
        headers={"X-CSRFToken": _csrf(client)},
    )


def _blok_reauth():
    with get_db() as db:
        return [
            dict(baris) for baris in db.execute(
                "SELECT * FROM blockchain_log WHERE action = 'REAUTH' "
                "ORDER BY block_index"
            )
        ]


class TestPenerbitanGrant:
    def test_password_benar_menerbitkan_grant_dan_mencatat_blok(self, client):
        resp = _minta_grant(client)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["grant"]
        assert data["scope"] == "file.download"
        assert data["resource_id"] == "7"
        assert data["expires_in"] == 120
        assert data["reusable"] is False

        blok = _blok_reauth()
        assert len(blok) == 1
        assert blok[0]["asset_ref"] == "reauth:file.download"
        assert data["grant"] not in blok[0]["asset_hash"]
        assert data["grant"] not in blok[0]["asset_ref"]

        lanjut = client.get(
            "/uji/file/7", headers={"X-Reauth-Grant": data["grant"]}
        )
        assert lanjut.status_code == 200
        assert lanjut.get_json()["resource_id"] == 7

    def test_password_salah_ditolak_tanpa_blok(self, client):
        resp = _minta_grant(client, password="kata-sandi-salah")
        assert resp.status_code == 401
        assert resp.get_json()["success"] is False
        assert resp.get_json()["error"] == MSG.REAUTH_FAILED
        assert _blok_reauth() == []

    def test_password_kosong_ditolak(self, client):
        resp = _minta_grant(client, password="")
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.REAUTH_PASSWORD_REQUIRED

    def test_password_tidak_masuk_sesi_cookie_log_atau_blockchain(
        self, client, caplog
    ):
        caplog.set_level(logging.DEBUG)
        resp = _minta_grant(client)
        assert resp.status_code == 200
        data = resp.get_json()

        with client.session_transaction() as sess:
            assert PASSWORD not in str(dict(sess))
        assert PASSWORD not in (resp.headers.get("Set-Cookie") or "")
        assert PASSWORD not in caplog.text

        for baris in _blok_reauth():
            assert PASSWORD not in str(baris)

        # Token grant juga tidak disimpan di cookie sesi.
        with client.session_transaction() as sess:
            assert data["grant"] not in str(dict(sess))

    def test_scope_tidak_dikenal_ditolak(self, client):
        resp = _minta_grant(client, scope="rahasia.salah")
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.REAUTH_SCOPE_UNKNOWN

    def test_metode_tidak_dikenal_ditolak(self, client):
        resp = _minta_grant(client, method="sms")
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.REAUTH_METHOD_UNSUPPORTED

    def test_webauthn_tanpa_respons_ditolak(self, client):
        resp = _minta_grant(client, method="webauthn")
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.REAUTH_WEBAUTHN_FAILED

    def test_registri_metode_dapat_ditambah(self):
        nama = "uji_registri"

        def metode(user_id, payload):
            return True, None

        reauth.register_method(nama)(metode)
        try:
            assert reauth.verify_method(nama, 1, {}) == (True, None)
            assert nama in reauth.available_methods()
        finally:
            reauth._METHOD_REGISTRY.pop(nama, None)

    def test_scope_dekorator_tidak_dikenal_ditolak(self):
        with pytest.raises(ValueError):
            reauth.require_grant("tidak.ada")


class TestValidasiGrant:
    def test_grant_kedaluwarsa_ditolak(self, client, monkeypatch):
        with client.session_transaction() as sess:
            sid = sess["session_id"]
        grant = reauth.issue_grant(sid, "file.download", 7)
        kedaluwarsa_pada = reauth._grants[grant["token"]]["expires_at"] + 1
        monkeypatch.setattr(reauth, "_now", lambda: kedaluwarsa_pada)

        resp = client.get(
            "/uji/file/7", headers={"X-Reauth-Grant": grant["token"]}
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "expired"

    def test_grant_milik_sesi_lain_ditolak(self, client, client_lain):
        data = _minta_grant(client).get_json()
        resp = client_lain.get(
            "/uji/file/7", headers={"X-Reauth-Grant": data["grant"]}
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "session"

    def test_grant_sekali_pakai_tidak_bisa_dipakai_ulang(self, client):
        data = _minta_grant(client).get_json()
        pertama = client.get(
            "/uji/file/7", headers={"X-Reauth-Grant": data["grant"]}
        )
        assert pertama.status_code == 200

        kedua = client.get(
            "/uji/file/7", headers={"X-Reauth-Grant": data["grant"]}
        )
        assert kedua.status_code == 401
        assert kedua.get_json()["reason"] == "invalid"

    def test_scope_salah_ditolak(self, client):
        data = _minta_grant(client, scope="file.download").get_json()
        resp = client.get(
            "/uji/stream/7", headers={"X-Reauth-Grant": data["grant"]}
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "scope"

    def test_resource_salah_ditolak(self, client):
        data = _minta_grant(
            client, scope="file.download", resource_id=7
        ).get_json()
        resp = client.get(
            "/uji/file/8", headers={"X-Reauth-Grant": data["grant"]}
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "resource"

        benar = client.get(
            "/uji/file/7", headers={"X-Reauth-Grant": data["grant"]}
        )
        assert benar.status_code == 200

    def test_tanpa_grant_ditolak(self, client):
        resp = client.get("/uji/file/7")
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"

    def test_media_stream_dapat_dipakai_berulang_15_menit(
        self, client, monkeypatch
    ):
        data = _minta_grant(
            client, scope="media.stream", resource_id=9
        ).get_json()
        assert data["reusable"] is True
        assert data["expires_in"] == 900

        for _ in range(3):
            resp = client.get(
                "/uji/stream/9", headers={"X-Reauth-Grant": data["grant"]}
            )
            assert resp.status_code == 200

        salah_resource = client.get(
            "/uji/stream/10", headers={"X-Reauth-Grant": data["grant"]}
        )
        assert salah_resource.status_code == 403
        assert salah_resource.get_json()["reason"] == "resource"

        kedaluwarsa_pada = (
            reauth._grants[data["grant"]]["expires_at"] + 1
        )
        monkeypatch.setattr(reauth, "_now", lambda: kedaluwarsa_pada)
        kedaluwarsa = client.get(
            "/uji/stream/9", headers={"X-Reauth-Grant": data["grant"]}
        )
        assert kedaluwarsa.status_code == 401
        assert kedaluwarsa.get_json()["reason"] == "expired"

    def test_grant_bisa_dikirim_lewat_field_form(self, client):
        token = _csrf(client)
        data = _minta_grant(client).get_json()
        resp = client.post(
            "/uji/file/7",
            data={"csrf_token": token, "reauth_grant": data["grant"]},
        )
        assert resp.status_code == 200


class TestAntarmuka:
    def test_modal_dan_js_reauth_dimuat_di_halaman(self, client):
        body = client.get("/media-vault").get_data(as_text=True)
        assert 'id="reauth-modal"' in body
        assert "js/reauth.js" in body
        assert 'id="reauth-password"' in body
        assert 'autocomplete="current-password"' in body
