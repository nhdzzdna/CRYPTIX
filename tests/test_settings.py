"""
tests/test_settings.py
──────────────────────
Uji butir 4.8: halaman Settings mengelola dongle, kredensial WebAuthn,
wajah, kunci pemulihan, dan batas sesi. Setiap tindakan sensitif wajib
grant autentikasi ulang dengan scope yang tepat.
"""

import json
import os
import re

from flask_wtf import csrf
import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth
from modules.authentication import webauthn
from modules.authentication import face_recognition as face_mod
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import create_account, register_user
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys
from modules.cryptography.key_management import (
    recover_dek, unlock_dek,
)
from modules.strings import MSG
from tests.test_webauthn import _Autentikator

KATA_SANDI = "Rahasia-Settings-2026!"
USERNAME = "pengguna_settings"
EMAIL = "settings@contoh.test"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "settings.db"))
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

    with get_db() as db:
        baris = db.execute(
            "SELECT * FROM users WHERE username=?", (USERNAME,)
        ).fetchone()
    dek = unlock_dek(KATA_SANDI, token["secret"], dict(baris))

    application = create_app()
    application.config["TESTING"] = True
    application.config["TEST_RECOVERY_KEY"] = hasil["recovery_key"]
    application.config["TEST_DEK"] = dek
    reauth.clear()
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _token_meta(halaman: str) -> str:
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', halaman)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _baris(username: str = USERNAME) -> dict:
    with get_db() as db:
        baris = db.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
    return dict(baris)


def _masuk(client, app, sid_timeout=None) -> str:
    baris = _baris()
    sid = session_keys.create_session_id()
    with client.session_transaction() as sess:
        sess["user_id"] = baris["id"]
        sess["username"] = baris["username"]
        sess["session_id"] = sid
    session_keys.put(sid, app.config["TEST_DEK"], sid_timeout)
    return sid


def _grant(client, scope: str = "settings.change") -> str:
    csrf = _token_meta(client.get("/settings").get_data(as_text=True))
    resp = client.post(
        "/api/reauth",
        json={"method": "password", "scope": scope, "password": KATA_SANDI},
        headers={"X-CSRFToken": csrf},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["grant"]


def _csrf(client) -> str:
    return _token_meta(client.get("/settings").get_data(as_text=True))


def _seed_credential(user_id: int, nama: str = "uji") -> str:
    aut = _Autentikator()
    tantangan = webauthn.tantangan_baru(webauthn.kunci_daftar(user_id))
    hasil = webauthn.daftarkan_kredensial(
        user_id, aut.respons_daftar(tantangan), nama
    )
    assert hasil["success"], hasil
    return hasil["credential_id"]


class TestHalamanSettings:
    def test_menampilkan_seluruh_bagian_dan_csrf(self, app, client):
        _masuk(client, app)
        body = client.get("/settings").get_data(as_text=True)

        for judul in (
            "Ganti Password",
            "USB Token / Dongle",
            "Kunci Pemulihan",
            "Batas Diam Sesi",
            "Face Recognition",
            "WebAuthn",
        ):
            assert judul in body

        assert body.count('name="csrf_token"') >= 4
        assert 'data-reauth="settings.change"' in body
        assert 'data-reauth="biometric.manage"' in body
        assert "recovery_key_baru" not in body

    def test_menampilkan_pilihan_dongle_dari_daftar_drive(
        self, app, client, monkeypatch
    ):
        _masuk(client, app)
        monkeypatch.setattr(usb_mod, "daftar_drive", lambda: [
            {"mountpoint": "D:\\dongle-a", "volume_serial": "AAAA1111"},
            {"mountpoint": "D:\\dongle-b", "volume_serial": "BBBB2222"},
        ])

        body = client.get("/settings").get_data(as_text=True)
        assert 'name="mountpoint"' in body
        assert "D:\\dongle-a" in body
        assert "D:\\dongle-b" in body
        assert "Pilih dongle tujuan" in body
        assert MSG.USB_REREGISTER_HINT in body

    def test_kredensial_webauthn_ditampilkan_dengan_nama(self, app, client):
        _masuk(client, app)
        _seed_credential(_baris()["id"], "Laptop kantor")

        body = client.get("/settings").get_data(as_text=True)
        assert "Laptop kantor" in body
        assert "Hapus" in body

    def test_lima_tab_dan_panel_tersedia(self, app, client):
        _masuk(client, app)
        body = client.get("/settings").get_data(as_text=True)

        for tab_id in ("tab-profil", "tab-keamanan", "tab-biometrik", "tab-sesi", "tab-akun"):
            assert f'id="{tab_id}"' in body

        for pane_id in ("pane-profil", "pane-keamanan", "pane-biometrik", "pane-sesi", "pane-akun"):
            assert f'id="{pane_id}"' in body

        assert 'data-tab-target="profil"' in body
        assert 'data-tab-target="keamanan"' in body
        assert 'data-tab-target="biometrik"' in body
        assert 'data-tab-target="sesi"' in body
        assert 'data-tab-target="akun"' in body
        assert 'data-goto-tab="biometrik"' in body

    def test_avatar_dan_informasi_profil(self, app, client):
        _masuk(client, app)
        body = client.get("/settings").get_data(as_text=True)

        assert 'class="kx-settings-avatar"' in body
        assert USERNAME[0].upper() in body
        assert USERNAME in body
        assert EMAIL in body
        assert "data-buka-modal=\"#modal-ubah-email\"" in body

    def test_struktur_modal_dan_target_username_bahaya(self, app, client):
        _masuk(client, app)
        body = client.get("/settings").get_data(as_text=True)

        assert 'id="modal-ubah-email"' in body
        assert 'id="modal-konfirmasi-recovery"' in body
        assert 'id="modal-reset-data"' in body
        assert 'id="modal-hapus-akun"' in body

        assert f'data-target-username="{USERNAME}"' in body
        assert 'data-submit-target="#btn-submit-reset"' in body
        assert 'data-submit-target="#btn-submit-delete"' in body
        assert 'id="btn-submit-reset"' in body
        assert 'id="btn-submit-delete"' in body
        assert 'data-reauth="account.danger"' in body

    def test_kunci_pemulihan_baru_memuat_tombol_salin_unduh_dan_centang(self, app, client):
        _masuk(client, app)
        grant = _grant(client, scope="settings.change")
        resp = client.post(
            "/settings/recovery-key",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": grant,
            },
        )
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)

        assert 'id="box-recovery-key-baru"' in body
        assert 'id="settings-recovery-val"' in body
        assert 'id="btn-download-settings-recovery"' in body
        assert 'id="check-saved-recovery"' in body
        assert 'data-kx-salin="' in body
        assert MSG.SETTINGS_RECOVERY_SAVED_CHECKBOX in body

    def test_tanpa_kata_terlarang_pada_halaman_dan_skrip(self):
        kata_terlarang = [
            "sem" + "ester",
            "U" + "AS",
            "U" + "TS",
            "maha" + "siswa",
            "do" + "sen",
        ]
        berkas_diperiksa = [
            "templates/settings.html",
            "static/css/halaman/settings.css",
            "static/js/settings.js",
        ]
        for jalur in berkas_diperiksa:
            with open(jalur, "r", encoding="utf-8") as handle:
                konten = handle.read().lower()
            for kata in kata_terlarang:
                assert kata.lower() not in konten, f"Kata terlarang '{kata}' ditemukan di {jalur}"


class TestDongle:
    def test_daftar_ulang_tanpa_grant_ditolak(self, app, client):
        _masuk(client, app)
        sebelum = _baris()
        resp = client.post(
            "/settings/register-usb",
            data={
                "csrf_token": _csrf(client),
                "current_password": KATA_SANDI,
            },
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"
        assert _baris() == sebelum

    def test_password_salah_tidak_mengubah_dongle(self, app, client):
        _masuk(client, app)
        sebelum = _baris()
        grant = _grant(client)
        resp = client.post(
            "/settings/register-usb",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": grant,
                "current_password": "Kata-Sandi-Salah-2026!",
            },
        )
        assert resp.status_code == 302
        assert _baris() == sebelum

    def test_daftar_ulang_membungkus_ulang_dek(self, app, client, monkeypatch):
        _masuk(client, app)
        dongle_lama = config.DEV_DONGLE_DIR
        dongle_baru = os.path.join(os.path.dirname(dongle_lama), "dongle_baru")
        os.makedirs(dongle_baru, exist_ok=True)
        monkeypatch.setattr(
            usb_mod, "_kandidat_drive",
            lambda: [dongle_lama, dongle_baru],
        )

        grant = _grant(client)
        resp = client.post(
            "/settings/register-usb",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": grant,
                "current_password": KATA_SANDI,
                "mountpoint": dongle_baru,
            },
        )
        assert resp.status_code == 302

        sesudah = _baris()
        with open(
            os.path.join(dongle_baru, config.USB_TOKEN_FILENAME),
            encoding="utf-8",
        ) as handle:
            rahasia_baru = bytes.fromhex(json.load(handle)["secret"])
        assert unlock_dek(KATA_SANDI, rahasia_baru, sesudah) == (
            app.config["TEST_DEK"]
        )
        # Kunci pemulihan lama tetap membuka DEK yang sama.
        assert recover_dek(
            app.config["TEST_RECOVERY_KEY"], sesudah
        ) == app.config["TEST_DEK"]

        with get_db() as db:
            blok = db.execute(
                "SELECT 1 FROM blockchain_log WHERE action='DONGLE_REGISTER'"
            ).fetchone()
        assert blok is not None


class TestKredensialWebAuthn:
    def test_hapus_tanpa_grant_ditolak(self, app, client):
        _masuk(client, app)
        user_id = _baris()["id"]
        credential_id = _seed_credential(user_id)
        _seed_credential(user_id, "kedua")

        resp = client.post(
            "/settings/webauthn/delete",
            data={
                "csrf_token": _csrf(client),
                "credential_id": credential_id,
            },
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"
        assert any(
            k["credential_id"] == credential_id
            for k in webauthn.kredensial_pengguna(user_id)
        )

    def test_hapus_memakai_grant_biometric_manage(self, app, client):
        _masuk(client, app)
        user_id = _baris()["id"]
        pertama = _seed_credential(user_id, "pertama")
        kedua = _seed_credential(user_id, "kedua")

        grant = _grant(client, scope="biometric.manage")
        resp = client.post(
            "/settings/webauthn/delete",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": grant,
                "credential_id": pertama,
            },
        )
        assert resp.status_code == 302

        tersisa = webauthn.kredensial_pengguna(user_id)
        assert [k["credential_id"] for k in tersisa] == [kedua]

    def test_scope_salah_ditolak(self, app, client):
        _masuk(client, app)
        user_id = _baris()["id"]
        credential_id = _seed_credential(user_id)
        _seed_credential(user_id, "kedua")

        grant = _grant(client, scope="settings.change")
        resp = client.post(
            "/settings/webauthn/delete",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": grant,
                "credential_id": credential_id,
            },
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "scope"

    def test_biometrik_terakhir_tidak_boleh_dihapus(self, app, client):
        _masuk(client, app)
        user_id = _baris()["id"]
        credential_id = _seed_credential(user_id)

        grant = _grant(client, scope="biometric.manage")
        resp = client.post(
            "/settings/webauthn/delete",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": grant,
                "credential_id": credential_id,
            },
            follow_redirects=True,
        )
        assert MSG.SETTINGS_BIOMETRIC_LAST in resp.get_data(as_text=True)
        assert len(webauthn.kredensial_pengguna(user_id)) == 1

    def test_kredensial_pengguna_lain_tidak_terhapus(self, app, client):
        _masuk(client, app)
        lain = register_user("pengguna_lain_settings", "lain@contoh.test", KATA_SANDI)
        assert lain["success"], lain
        credential_id = _seed_credential(lain["user_id"])

        grant = _grant(client, scope="biometric.manage")
        resp = client.post(
            "/settings/webauthn/delete",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": grant,
                "credential_id": credential_id,
            },
            follow_redirects=True,
        )
        assert MSG.SETTINGS_BIOMETRIC_NOT_FOUND in resp.get_data(as_text=True)
        assert len(webauthn.kredensial_pengguna(lain["user_id"])) == 1


class TestWajahDanKunciPemulihan:
    def test_daftar_ulang_wajah_tanpa_grant_ditolak(self, app, client):
        _masuk(client, app)
        resp = client.post(
            "/api/register_face",
            json={"frames": ["x"] * 30, "duration_ms": 3000},
            headers={"X-CSRFToken": _csrf(client)},
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"

    def test_daftar_ulang_wajah_memakai_grant(self, app, client, monkeypatch):
        _masuk(client, app)
        dipanggil = {}

        def _palsu(user_id, frames, dek):
            dipanggil["user_id"] = user_id
            dipanggil["frames"] = len(frames)
            return {"success": True, "sampel": len(frames)}

        monkeypatch.setattr(face_mod, "daftarkan_wajah", _palsu)
        grant = _grant(client, scope="biometric.manage")
        resp = client.post(
            "/api/register_face",
            json={"frames": ["x"] * 30, "duration_ms": 3000},
            headers={
                "X-CSRFToken": _csrf(client),
                "X-Reauth-Grant": grant,
            },
        )
        data = resp.get_json()
        assert data["success"] is True, data
        assert dipanggil == {"user_id": _baris()["id"], "frames": 30}

    def test_kunci_pemulihan_baru_mengganti_bungkus_lama(self, app, client):
        _masuk(client, app)
        kunci_lama = app.config["TEST_RECOVERY_KEY"]
        sebelum = _baris()

        grant = _grant(client, scope="settings.change")
        resp = client.post(
            "/settings/recovery-key",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": grant,
            },
        )
        assert resp.status_code == 200
        assert "no-store" in resp.headers["Cache-Control"]

        body = resp.get_data(as_text=True)
        pola = r"(?:[A-Z2-7]{8}-){6}[A-Z2-7]{4}"
        cocok = re.search(pola, body)
        assert cocok, "kunci pemulihan baru tidak tampil"
        kunci_baru = cocok.group(0)

        sesudah = _baris()
        assert sesudah["recovery_wrapped_dek"] != sebelum["recovery_wrapped_dek"]
        assert recover_dek(kunci_baru, sesudah) == app.config["TEST_DEK"]
        with pytest.raises(ValueError):
            recover_dek(kunci_lama, sesudah)

        kue = client.get_cookie("session")
        assert kunci_baru not in kue.value
        with client.session_transaction() as sess:
            assert kunci_baru not in str(dict(sess))

    def test_kunci_pemulihan_tanpa_grant_ditolak(self, app, client):
        _masuk(client, app)
        sebelum = _baris()
        resp = client.post(
            "/settings/recovery-key",
            data={"csrf_token": _csrf(client)},
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"
        assert _baris() == sebelum


class TestBatasSesi:
    def test_pilihan_tidak_valid_ditolak(self, app, client):
        _masuk(client, app)
        sebelum = _baris()
        grant = _grant(client)
        resp = client.post(
            "/settings/session-timeout",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": grant,
                "session_timeout_minutes": "7",
            },
        )
        assert resp.status_code == 302
        assert _baris() == sebelum

    def test_batas_sesi_disimpan_dan_diterapkan(self, app, client):
        sid = _masuk(client, app)
        grant = _grant(client)
        resp = client.post(
            "/settings/session-timeout",
            data={
                "csrf_token": _csrf(client),
                "reauth_grant": grant,
                "session_timeout_minutes": "30",
            },
        )
        assert resp.status_code == 302

        assert _baris()["session_timeout_minutes"] == 30
        assert session_keys._store[sid]["timeout_minutes"] == 30

        body = client.get("/settings").get_data(as_text=True)
        assert re.search(
            r'<option value="30"[^>]*selected', body
        )
