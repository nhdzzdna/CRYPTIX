"""
tests/test_session_keys.py
──────────────────────────
Butir 3.1 (penyimpanan kunci sisi server), 3.2 (cookie dan batas waktu),
dan 3.4 (meta csrf-token, apiFetch, handler CSRFError).
"""

import json
import os
import re
import time
from pathlib import Path

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import biometrics
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import create_account
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys
from modules.cryptography.key_management import unlock_dek
from modules.strings import MSG

USERNAME = "penguji_sesi"
KATA_SANDI = "kata-sandi-sesi-123"
EMAIL = "sesi@contoh.test"
DEK_UJI = b"\x11" * 32


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "sesi.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    # Turunkan biaya PBKDF2 khusus pengujian; login dan ekspektasi sama-sama
    # memakai config sehingga DEK yang dibandingkan tetap konsisten.
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(tmp_path / "dongle"))
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


def _masuk(client) -> str:
    """Login dua tahap lalu kembalikan session id; memastikan DEK tersimpan."""
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


def _token_meta(halaman) -> str:
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', halaman)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


class TestPenyimpananKunci:
    def test_put_lalu_get_mengembalikan_dek_yang_sama(self):
        sid = session_keys.create_session_id()
        session_keys.put(sid, DEK_UJI)
        assert session_keys.get(sid) == DEK_UJI

    def test_get_id_tidak_dikenal_mengembalikan_none(self):
        assert session_keys.get("tidak-ada") is None
        assert session_keys.get("") is None

    def test_session_id_acak_dan_panjang(self):
        a, b = session_keys.create_session_id(), session_keys.create_session_id()
        assert a != b
        assert len(a) >= 32

    def test_drop_menimpa_bytearray_entri(self):
        sid = session_keys.create_session_id()
        session_keys.put(sid, b"\xAB" * 32)
        isi_lama = session_keys._store[sid]["dek"]
        session_keys.drop(sid)
        assert session_keys.get(sid) is None
        assert isi_lama == bytearray(32)

    def test_timeout_diam_membuang_dek(self, monkeypatch):
        monkeypatch.setattr(config, "SESSION_IDLE_MINUTES", 0)
        sid = session_keys.create_session_id()
        session_keys.put(sid, DEK_UJI)
        time.sleep(0.05)
        assert session_keys.get(sid) is None
        assert sid not in session_keys._store

    def test_timeout_mutlak_membuang_dek(self, monkeypatch):
        monkeypatch.setattr(config, "SESSION_ABSOLUTE_MINUTES", 0)
        sid = session_keys.create_session_id()
        session_keys.put(sid, DEK_UJI)
        time.sleep(0.05)
        assert session_keys.get(sid) is None
        assert sid not in session_keys._store

    def test_clear_mengosongkan_seluruh_entri(self):
        sid = session_keys.create_session_id()
        session_keys.put(sid, DEK_UJI)
        session_keys.clear()
        assert session_keys.get(sid) is None
        assert session_keys._store == {}

    def test_fungsi_serialisasi_hex_sudah_dihapus(self):
        from modules.cryptography import key_management
        assert not hasattr(key_management, "master_key_to_hex")
        assert not hasattr(key_management, "master_key_from_hex")

    def test_sumber_aplikasi_tanpa_kunci_hex_di_session(self):
        for direktori in ("routes", "modules", "templates", "static"):
            for path in Path(direktori).rglob("*"):
                if path.suffix not in {".py", ".html", ".js", ".css"}:
                    continue
                isi = path.read_text(encoding="utf-8", errors="ignore")
                assert "master_key_hex" not in isi, path
                assert "master_key_to_hex" not in isi, path


class TestKonfigurasiCookie:
    def test_setelan_cookie_diterapkan_ke_aplikasi(self, app):
        assert app.config["SESSION_COOKIE_HTTPONLY"] is True
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
        assert app.config["SESSION_COOKIE_SECURE"] == config.SESSION_COOKIE_SECURE

    def test_batas_mutlak_menjadi_umur_cookie(self, app):
        from datetime import timedelta
        assert app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(
            minutes=config.SESSION_ABSOLUTE_MINUTES
        )
        assert config.SESSION_IDLE_MINUTES > 0
        assert config.SESSION_ABSOLUTE_MINUTES >= config.SESSION_IDLE_MINUTES

    def test_cookie_aktual_berflag_keamanan(self, client):
        _masuk(client)
        kue = client.get_cookie("session")
        assert kue is not None
        assert kue.http_only is True
        assert kue.same_site == "Lax"
        assert kue.secure == config.SESSION_COOKIE_SECURE
        assert kue.expires is not None


class TestAlurLogin:
    def test_dek_disimpan_di_server_bukan_di_cookie(self, app, client):
        sid = _masuk(client)
        kue = client.get_cookie("session")
        isi = app.session_interface.get_signing_serializer(app).loads(kue.value)

        assert set(isi) <= {"user_id", "username", "session_id", "_permanent",
                            "_csrf_token", "_flashes"}
        assert isi["session_id"] == sid
        assert isi["_permanent"] is True

        with get_db() as db:
            baris = db.execute(
                "SELECT * FROM users WHERE username=?", (USERNAME,)
            ).fetchone()
        # DEK dibuka dari key bundle dengan password + rahasia dongle,
        # bukan diturunkan dari password seperti alur lama.
        with open(os.path.join(config.DEV_DONGLE_DIR, config.USB_TOKEN_FILENAME),
                  encoding="utf-8") as handle:
            rahasia = bytes.fromhex(json.load(handle)["secret"])
        dek = unlock_dek(KATA_SANDI, rahasia, dict(baris))
        assert session_keys.get(sid) == dek
        assert dek.hex() not in str(isi)
        assert KATA_SANDI not in str(isi)

    def test_cookie_hanya_memuat_id_pengguna_dan_username(self, app, client):
        _masuk(client)
        kue = client.get_cookie("session")
        isi = app.session_interface.get_signing_serializer(app).loads(kue.value)
        assert isi["user_id"] is not None
        assert isi["username"] == USERNAME
        assert "session_id" in isi

    def test_logout_get_ditolak(self, client):
        _masuk(client)
        assert client.get("/logout").status_code == 405

    def test_logout_tanpa_csrf_ditolak(self, client):
        _masuk(client)
        assert client.post("/logout").status_code == 400

    def test_logout_post_membuang_dek_dan_sesi(self, client):
        sid = _masuk(client)
        halaman = client.get("/dashboard")
        token = _token_meta(halaman.get_data(as_text=True))
        resp = client.post("/logout", data={"csrf_token": token})
        assert resp.status_code == 302
        assert session_keys.get(sid) is None
        with client.session_transaction() as sess:
            assert "user_id" not in sess

    def test_timeout_diam_mengarahkan_ke_login(self, client, monkeypatch):
        sid = _masuk(client)
        monkeypatch.setattr(config, "SESSION_IDLE_MINUTES", 0)
        time.sleep(0.05)
        resp = client.get("/dashboard")
        assert resp.status_code == 302
        assert resp.headers["Location"] in ("/", "/login")
        assert session_keys.get(sid) is None
        isi = client.get("/login").get_data(as_text=True)
        assert MSG.SESSION_EXPIRED in isi


class TestCSRF:
    def test_meta_csrf_pada_halaman_auth(self, client):
        for halaman in ("/login", "/register"):
            body = client.get(halaman).get_data(as_text=True)
            assert '<meta name="csrf-token"' in body
            assert "js/api.js" in body

    def test_meta_csrf_pada_halaman_utama(self, client):
        _masuk(client)
        body = client.get("/dashboard").get_data(as_text=True)
        assert '<meta name="csrf-token"' in body
        assert "js/api.js" in body

    def test_semua_template_memakai_api_fetch(self):
        for path in Path("templates").glob("*.html"):
            isi = path.read_text(encoding="utf-8")
            assert "fetch(" not in isi.replace("apiFetch(", ""), path

    def test_dua_layout_memuat_api_js_dan_meta(self):
        for path in (Path("templates/base.html"),
                     Path("templates/auth_base.html")):
            isi = path.read_text(encoding="utf-8")
            assert '<meta name="csrf-token"' in isi, path
            assert "js/api.js" in isi, path

    def test_api_js_menyediakan_api_fetch_berekspor_global(self):
        isi = Path("static/js/api.js").read_text(encoding="utf-8")
        assert "function apiFetch" in isi
        assert "X-CSRFToken" in isi

    def test_csrf_gagal_pada_api_dibalas_json(self, client):
        resp = client.post("/api/verify_face",
                           json={"username": USERNAME, "frame": ""})
        assert resp.status_code == 400
        assert resp.is_json
        data = resp.get_json()
        assert data["success"] is False
        assert data["error"]

    def test_header_xcsrftoken_diterima_server(self, client):
        token = _token_meta(
            client.get("/login").get_data(as_text=True)
        )
        resp = client.post(
            "/api/verify_face",
            json={"username": USERNAME, "frame": "abc"},
            headers={"X-CSRFToken": token},
        )
        assert resp.status_code == 401
        assert resp.get_json()["success"] is False

    def test_csrf_gagal_pada_form_html_dibalas_halaman(self, client):
        _masuk(client)
        resp = client.post("/secure-notes/add",
                           data={"title": "x", "content": "y"})
        assert resp.status_code == 400
        assert "text/html" in resp.content_type
