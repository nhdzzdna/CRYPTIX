"""
tests/test_two_stage_login.py
──────────────────────────────
Uji Fase 2 butir 2.4: login dua tahap (password + dongle lalu biometrik),
pesan generik tahap 1, urutan tahap, kebijakan biometrik, dan pembuktian
bahwa password tidak muncul di sesi, cookie, cache, maupun log.
"""

import json
import logging
import os
import re
import shutil

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import biometrics
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import create_account
from modules.blockchain import blockchain as bc
from modules.cryptography import pending_keys, session_keys
from modules.cryptography.key_management import unlock_dek
from modules.strings import MSG

KATA_SANDI = "Rahasia-Masuk-2026!"
USERNAME = "pengguna_masuk"
EMAIL = "masuk@contoh.test"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "masuk.db"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "BIOMETRIC_POLICY", "all_enrolled")
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
def metode_uji():
    """Metode biometrik buatan pengujian; dicabut setelah test."""
    biometrics.tambah_metode(
        "uji", "Metode Uji",
        terdaftar=lambda user_id: True,
        verifikasi=lambda user_id, bukti: bukti == {"kunci": "sah"},
    )
    yield
    biometrics.hapus_metode("uji")


@pytest.fixture()
def dua_metode():
    """Dua metode biometrik buatan pengujian untuk uji kebijakan."""
    for nama in ("uji_a", "uji_b"):
        biometrics.tambah_metode(
            nama, nama.upper(),
            terdaftar=lambda user_id: True,
            verifikasi=lambda user_id, bukti: bukti == {"kunci": "sah"},
        )
    yield
    for nama in ("uji_a", "uji_b"):
        biometrics.hapus_metode(nama)


def _csrf(client, halaman="/login") -> str:
    """Token CSRF sebuah halaman; sekali ambil untuk kedua tahap login."""
    body = client.get(halaman).get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _tahap1(client, csrf, username=USERNAME, password=KATA_SANDI):
    return client.post(
        "/login",
        json={"username": username, "password": password},
        headers={"X-CSRFToken": csrf},
    )


def _tahap2(client, csrf, pending, bukti):
    return client.post(
        "/login/biometric",
        json={"pending": pending, "bukti": bukti},
        headers={"X-CSRFToken": csrf},
    )


def _baris() -> dict:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE username=?", (USERNAME,)
        ).fetchone()
    assert row is not None
    return dict(row)


def _dek_diharapkan(tmp_path) -> bytes:
    """DEK akun uji dibuka langsung dengan rahasia dongle pada berkas token."""
    path = os.path.join(str(tmp_path / "dongle"), config.USB_TOKEN_FILENAME)
    with open(path, encoding="utf-8") as handle:
        rahasia = bytes.fromhex(json.load(handle)["secret"])
    return unlock_dek(KATA_SANDI, rahasia, _baris())


def _masuk_penuh(client, csrf, bukti=None):
    """Tahap 1 lalu tahap 2 dengan bukti uji yang sah; kembalikan respons tahap 2."""
    resp1 = _tahap1(client, csrf)
    assert resp1.status_code == 200, resp1.get_data(as_text=True)
    pending = resp1.get_json()["pending"]
    return _tahap2(client, csrf, pending, bukti or {"uji": {"kunci": "sah"}})


# ── Tahap 1: password + dongle ───────────────────────────────────────────────

class TestTahapSatu:
    def test_dek_ditahan_di_server_bukan_di_cookie(self, app, client,
                                                   metode_uji, tmp_path):
        csrf = _csrf(client)
        resp = _tahap1(client, csrf)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["pending"]
        assert data["metode"] == [{"nama": "uji", "label": "Metode Uji"}]
        assert data["kebijakan"] == config.BIOMETRIC_POLICY
        assert KATA_SANDI not in resp.get_data(as_text=True)

        with client.session_transaction() as sess:
            assert sess["login_stage"] == 1
            assert sess["login_pending"] == data["pending"]
            assert "user_id" not in sess

        entri = pending_keys.periksa(data["pending"])
        assert entri is not None
        user_id, dek = entri
        assert user_id == _baris()["id"]
        assert dek == _dek_diharapkan(tmp_path)
        assert pending_keys.TTL_DETIK == 180.0

    def test_satu_pesan_untuk_semua_kegagalan(self, app, client, tmp_path):
        csrf = _csrf(client)
        pesan = []

        resp = _tahap1(client, csrf, password="kata-sandi-salah-99")
        assert resp.status_code == 401
        pesan.append(resp.get_json()["error"])

        resp = _tahap1(client, csrf, username="pengguna_tidak_ada")
        assert resp.status_code == 401
        pesan.append(resp.get_json()["error"])

        # dongle tidak ada
        shutil.rmtree(str(tmp_path / "dongle"))
        usb_mod.lupakan_cache()
        resp = _tahap1(client, csrf)
        assert resp.status_code == 401
        pesan.append(resp.get_json()["error"])

        # dongle tidak cocok: token ditulis ulang, verifier akun tetap lama
        assert usb_mod.register_usb_token(str(tmp_path / "dongle")) is not None
        resp = _tahap1(client, csrf)
        assert resp.status_code == 401
        pesan.append(resp.get_json()["error"])

        assert pesan == [MSG.LOGIN_STAGE1_FAILED] * 4

    def test_tahap1_diulang_ditolak(self, app, client, metode_uji):
        csrf = _csrf(client)
        assert _tahap1(client, csrf).status_code == 200
        resp = _tahap1(client, csrf)
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.LOGIN_STAGE_ORDER

    def test_get_login_membatalkan_tahap_tertunda(self, app, client, metode_uji):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf).get_json()["pending"]
        client.get("/login")
        assert pending_keys.periksa(pending) is None
        resp = _tahap2(client, csrf, pending, {"uji": {"kunci": "sah"}})
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.LOGIN_STAGE_ORDER


# ── Tahap 2: biometrik dan urutan ────────────────────────────────────────────

class TestTahapDua:
    def test_tanpa_tahap1_ditolak(self, app, client):
        csrf = _csrf(client)
        resp = _tahap2(client, csrf, "token-acak", {})
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.LOGIN_STAGE_ORDER

    def test_pending_bukan_milik_sesi_ditolak(self, app, client, metode_uji):
        csrf = _csrf(client)
        _tahap1(client, csrf)
        resp = _tahap2(client, csrf, "token-acak", {"uji": {"kunci": "sah"}})
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.LOGIN_STAGE_ORDER

    def test_tanpa_csrf_ditolak(self, app, client, metode_uji):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf).get_json()["pending"]
        resp = client.post(
            "/login/biometric", json={"pending": pending, "bukti": {}}
        )
        assert resp.status_code == 400
        assert resp.is_json

    def test_biometrik_gagal_pending_masih_bisa_diulang(self, app, client,
                                                       metode_uji, tmp_path):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf).get_json()["pending"]

        gagal = _tahap2(client, csrf, pending, {"uji": {"kunci": "salah"}})
        assert gagal.status_code == 401
        assert gagal.get_json()["error"] == MSG.LOGIN_BIOMETRIC_FAILED
        assert pending_keys.periksa(pending) is not None
        with client.session_transaction() as sess:
            assert "user_id" not in sess

        sukses = _tahap2(client, csrf, pending, {"uji": {"kunci": "sah"}})
        assert sukses.status_code == 200

    def test_pending_kedaluwarsa_ditolak(self, app, client, metode_uji,
                                         monkeypatch):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf).get_json()["pending"]
        monkeypatch.setattr(pending_keys, "TTL_DETIK", 0.0)
        resp = _tahap2(client, csrf, pending, {"uji": {"kunci": "sah"}})
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.LOGIN_PENDING_EXPIRED
        with client.session_transaction() as sess:
            assert "login_stage" not in sess

    def test_tahap2_sukses_memindahkan_dek_ke_aktif(self, app, client,
                                                    metode_uji, tmp_path):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf).get_json()["pending"]
        resp = _tahap2(client, csrf, pending, {"uji": {"kunci": "sah"}})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["redirect"] == "/dashboard"

        assert pending_keys.periksa(pending) is None
        with client.session_transaction() as sess:
            sid = sess["session_id"]
            assert sess["user_id"] == _baris()["id"]
            assert sess["username"] == USERNAME
            assert "login_stage" not in sess
            assert "login_pending" not in sess
            assert KATA_SANDI not in str(dict(sess))
        assert session_keys.get(sid) == _dek_diharapkan(tmp_path)

        kue = client.get_cookie("session")
        isi = app.session_interface.get_signing_serializer(app).loads(kue.value)
        assert set(isi) <= {"user_id", "username", "session_id", "_permanent",
                            "_csrf_token", "_flashes"}
        assert KATA_SANDI not in kue.value
        assert client.get("/dashboard").status_code == 200

    def test_tahap2_setelah_sukses_ditolak(self, app, client, metode_uji):
        csrf = _csrf(client)
        assert _masuk_penuh(client, csrf).status_code == 200
        # sesi baru sudah memakai token CSRF segar setelah session.clear()
        csrf_baru = _csrf(client, "/dashboard")
        resp = _tahap2(client, csrf_baru, "sudah-habis",
                       {"uji": {"kunci": "sah"}})
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.LOGIN_STAGE_ORDER

    def test_login_lagi_setelah_masuk_ditolak(self, app, client, metode_uji):
        csrf = _csrf(client)
        assert _masuk_penuh(client, csrf).status_code == 200
        csrf_baru = _csrf(client, "/dashboard")
        resp = _tahap1(client, csrf_baru)
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.LOGIN_STAGE_ORDER


# ── Pilihan biometrik tahap 2 ────────────────────────────────────────────────

class TestPilihanBiometrik:
    def test_satu_metode_terpilih_lulus(self, app, client, dua_metode):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf).get_json()["pending"]
        resp = _tahap2(client, csrf, pending, {"uji_a": {"kunci": "sah"}})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_metode_lain_juga_bisa_dipilih(self, app, client, dua_metode):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf).get_json()["pending"]
        resp = _tahap2(client, csrf, pending, {"uji_b": {"kunci": "sah"}})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_dua_bukti_tanpa_pilihan_ditolak(self, app, client, dua_metode):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf).get_json()["pending"]
        resp = _tahap2(client, csrf, pending, {
            "uji_a": {"kunci": "sah"}, "uji_b": {"kunci": "sah"},
        })
        assert resp.status_code == 400
        assert resp.get_json()["error"] == MSG.LOGIN_BIOMETRIC_CHOOSE

    def test_metode_terpilih_tanpa_bukti_ditolak(self, app, client,
                                                 dua_metode):
        csrf = _csrf(client)
        pending = _tahap1(client, csrf).get_json()["pending"]
        resp = _tahap2(client, csrf, pending, {"uji_a": {"kunci": "salah"}})
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.LOGIN_BIOMETRIC_FAILED

    def test_tanpa_metode_terdaftar_ditolak_termasuk_mode_pengembangan(
        self, app, client, monkeypatch
    ):
        monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
        csrf = _csrf(client)
        resp1 = _tahap1(client, csrf)
        assert resp1.status_code == 200
        assert resp1.get_json()["metode"] == []
        pending = resp1.get_json()["pending"]
        resp2 = _tahap2(client, csrf, pending, {})
        assert resp2.status_code == 401
        assert resp2.get_json()["error"] == MSG.LOGIN_BIOMETRIC_NONE


# ── Registry metode biometrik ────────────────────────────────────────────────

class TestRegistryMetode:
    def test_metode_biometrik_terdaftar_hanya_untuk_pemiliknya(self, app):
        biometrics.tambah_metode(
            "milik_42", "Milik 42",
            terdaftar=lambda user_id: user_id == 42,
            verifikasi=lambda user_id, bukti: True,
        )
        try:
            assert biometrics.metode_biometrik_terdaftar(42) == ["milik_42"]
            assert biometrics.metode_biometrik_terdaftar(7) == []
        finally:
            biometrics.hapus_metode("milik_42")

    def test_metode_untuk_pengguna_membawa_label(self, app):
        biometrics.tambah_metode(
            "berlabel", "Metode Berlabel",
            terdaftar=lambda user_id: True,
            verifikasi=lambda user_id, bukti: True,
        )
        try:
            assert biometrics.metode_untuk_pengguna(1) == [
                {"nama": "berlabel", "label": "Metode Berlabel"}
            ]
        finally:
            biometrics.hapus_metode("berlabel")

    def test_bukti_hilang_atau_verifikasi_gagal_jadi_false(self, app):
        biometrics.tambah_metode(
            "pecah", "Metode Pecah",
            terdaftar=lambda user_id: True,
            verifikasi=lambda user_id, bukti: 1 / 0,
        )
        try:
            hasil = biometrics.verifikasi_tahap_biometrik(1, {})
            assert hasil == {"pecah": False}
            hasil = biometrics.verifikasi_tahap_biometrik(1, {"pecah": {}})
            assert hasil == {"pecah": False}
        finally:
            biometrics.hapus_metode("pecah")

    def test_kebijakan_kosong_selalu_gagal(self):
        assert biometrics.kebijakan_dipenuhi({}) is False
        assert biometrics.kebijakan_dipenuhi({"a": True}) is True
        assert biometrics.kebijakan_dipenuhi({"a": False}) is False

    def test_tambah_metode_tidak_valid_ditolak(self):
        with pytest.raises(ValueError):
            biometrics.tambah_metode("", "Tanpa Nama", lambda u: True, lambda u, b: True)
        with pytest.raises(ValueError):
            biometrics.tambah_metode("x", "X", "bukan-fungsi", lambda u, b: True)


# ── Status dongle ────────────────────────────────────────────────────────────

class TestStatusDongle:
    def test_status_dongle_tanpa_username(self, app, client, tmp_path):
        resp = client.get("/api/dongle/status")
        assert resp.status_code == 200
        assert resp.get_json() == {"detected": True}
        assert USERNAME not in resp.get_data(as_text=True)

        shutil.rmtree(str(tmp_path / "dongle"))
        resp = client.get("/api/dongle/status")
        assert resp.get_json() == {"detected": False}


# ── Password tidak bocor ─────────────────────────────────────────────────────

class _TangkapLog(logging.Handler):
    """Menangkap record logger "cryptix" selama pengujian berlangsung."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


class TestKebocoranPassword:
    def test_password_tidak_muncul_di_sesi_cookie_cache_atau_log(
        self, app, client, metode_uji, tmp_path
    ):
        tangkap = _TangkapLog()
        akar = logging.getLogger("cryptix")
        akar.addHandler(tangkap)
        try:
            csrf = _csrf(client)
            pending = _tahap1(client, csrf).get_json()["pending"]
            dek = pending_keys.periksa(pending)[1]
            resp = _tahap2(client, csrf, pending, {"uji": {"kunci": "sah"}})
            assert resp.status_code == 200
        finally:
            akar.removeHandler(tangkap)

        # Sesi dan cookie
        with client.session_transaction() as sess:
            isi_sesi = str(dict(sess))
            assert KATA_SANDI not in isi_sesi
            assert dek.hex() not in isi_sesi
        kue = client.get_cookie("session").value
        assert KATA_SANDI not in kue
        assert dek.hex() not in kue

        # Cache sisi server: DEK tertahan dan DEK aktif
        assert KATA_SANDI not in str(pending_keys._store)
        assert KATA_SANDI not in str(session_keys._store)
        assert dek.hex() not in str(session_keys._store)

        # Log
        isi_log = " | ".join(r.getMessage() for r in tangkap.records)
        assert KATA_SANDI not in isi_log
        for handler in akar.handlers:
            path = getattr(handler, "baseFilename", None)
            if path and os.path.isfile(path):
                with open(path, encoding="utf-8", errors="ignore") as handle:
                    assert KATA_SANDI not in handle.read()

    def test_password_tidak_muncul_pada_respon_tahap1(self, app, client,
                                                      metode_uji, tmp_path):
        csrf = _csrf(client)
        resp = _tahap1(client, csrf)
        body = resp.get_data(as_text=True)
        assert KATA_SANDI not in body
        assert _dek_diharapkan(tmp_path).hex() not in body
