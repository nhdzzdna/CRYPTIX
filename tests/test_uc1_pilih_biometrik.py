"""
tests/test_uc1_pilih_biometrik.py
──────────────────────────────────
Uji UC1 butir pilihan biometrik: tahap 2 login memverifikasi satu metode
yang dipilih pengguna, menolak metode yang tidak terdaftar, dan meneruskan
detail kegagalan metode (mis. mata tertutup) ke peramban.
"""

import re

import pytest

import config
from app import create_app
from database.db import init_db
from modules.authentication import biometrics
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import create_account
from modules.blockchain import blockchain as bc
from modules.strings import MSG

KATA_SANDI = "Rahasia-Pilih-2026!"
USERNAME = "pengguna_pilih"
EMAIL = "pilih@contoh.test"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "pilih.db"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
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


@pytest.fixture()
def dua_metode():
    for nama in ("uji_a", "uji_b"):
        biometrics.tambah_metode(
            nama, nama.upper(),
            terdaftar=lambda user_id: True,
            verifikasi=lambda user_id, bukti: bukti == {"kunci": "sah"},
        )
    yield
    for nama in ("uji_a", "uji_b"):
        biometrics.hapus_metode(nama)


def _csrf(client) -> str:
    body = client.get("/login").get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _tahap1(client, csrf):
    resp = client.post(
        "/login",
        json={"username": USERNAME, "password": KATA_SANDI},
        headers={"X-CSRFToken": csrf},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()


def _tahap2(client, csrf, pending, bukti, metode=None):
    isian = {"pending": pending, "bukti": bukti}
    if metode is not None:
        isian["metode"] = metode
    return client.post(
        "/login/biometric",
        json=isian,
        headers={"X-CSRFToken": csrf},
    )


class TestPilihanSatuMetode:
    def test_metode_eksplisit_hanya_mengirim_bukti_terpilih(
        self, app, client, dua_metode
    ):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf)["pending"]
        resp = _tahap2(
            client, csrf, pending, {"uji_a": {"kunci": "sah"}}, metode="uji_a"
        )
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_metode_kedua_juga_dapat_dipilih(self, app, client, dua_metode):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf)["pending"]
        resp = _tahap2(
            client, csrf, pending, {"uji_b": {"kunci": "sah"}}, metode="uji_b"
        )
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_satu_kunci_bukti_tanpa_field_metode_tetap_lulus(
        self, app, client, dua_metode
    ):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf)["pending"]
        resp = _tahap2(client, csrf, pending, {"uji_a": {"kunci": "sah"}})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_bukti_metode_lain_tidak_dipakai(self, app, client, dua_metode):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf)["pending"]
        resp = _tahap2(
            client, csrf, pending, {"uji_b": {"kunci": "sah"}}, metode="uji_a"
        )
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.LOGIN_BIOMETRIC_FAILED

    def test_dua_bukti_tanpa_pilihan_ditolak(self, app, client, dua_metode):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf)["pending"]
        resp = _tahap2(
            client,
            csrf,
            pending,
            {"uji_a": {"kunci": "sah"}, "uji_b": {"kunci": "sah"}},
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.LOGIN_BIOMETRIC_CHOOSE


class TestPenolakanMetode:
    def test_metode_tidak_terdaftar_ditolak(self, app, client, dua_metode):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf)["pending"]
        resp = _tahap2(
            client, csrf, pending, {"lain": {"kunci": "sah"}}, metode="lain"
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["error"] == MSG.LOGIN_BIOMETRIC_METHOD_INVALID
        assert data["code"] == "metode_tidak_terdaftar"

        # Pending belum dibuang sehingga pengguna dapat memilih metode lain.
        resp = _tahap2(
            client, csrf, pending, {"uji_a": {"kunci": "sah"}}, metode="uji_a"
        )
        assert resp.status_code == 200

    def test_tanpa_tahap_satu_ditolak(self, app, client, dua_metode):
        csrf = _csrf(client)
        resp = _tahap2(
            client, csrf, "token-acak", {"uji_a": {"kunci": "sah"}},
            metode="uji_a",
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.LOGIN_STAGE_ORDER

    def test_tanpa_metode_terdaftar_ditolak(self, app, client):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf)["pending"]
        resp = _tahap2(client, csrf, pending, {})
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.LOGIN_BIOMETRIC_NONE


class TestDetailKegagalanMetode:
    def test_kode_mata_tertutup_diteruskan(self, app, client):
        biometrics.tambah_metode(
            "wajah_uji", "Wajah Uji",
            terdaftar=lambda user_id: True,
            verifikasi=lambda user_id, bukti: {
                "success": False,
                "error": MSG.FACE_EYES_CLOSED,
                "code": "mata_tertutup",
            },
        )
        try:
            csrf = _csrf(client)
            pending = _tahap1(client, csrf)["pending"]
            resp = _tahap2(
                client, csrf, pending, {"wajah_uji": ["frame"]},
                metode="wajah_uji",
            )
        finally:
            biometrics.hapus_metode("wajah_uji")

        assert resp.status_code == 401
        data = resp.get_json()
        assert data["error"] == MSG.FACE_EYES_CLOSED
        assert data["code"] == "mata_tertutup"

    def test_verifikasi_metode_mengembalikan_dict_galat(self, app):
        biometrics.tambah_metode(
            "gagal_uji", "Gagal Uji",
            terdaftar=lambda user_id: True,
            verifikasi=lambda user_id, bukti: {
                "success": False,
                "error": "Pesan khusus.",
                "code": "khusus",
            },
        )
        try:
            hasil = biometrics.verifikasi_metode_biometrik(
                1, "gagal_uji", {"gagal_uji": {}}
            )
        finally:
            biometrics.hapus_metode("gagal_uji")
        assert hasil == {
            "success": False,
            "error": "Pesan khusus.",
            "code": "khusus",
        }
