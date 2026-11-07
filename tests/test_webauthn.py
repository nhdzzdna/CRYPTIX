"""
tests/test_webauthn.py
──────────────────────
Uji butir 2.5: WebAuthn (py_webauthn) — pendaftaran kredensial platform,
tantangan sisi server yang sekali pakai, tahap 2 login, dan pembaruan
sign_count.

Respons autentikator disusun sendiri dengan kunci P-256: clientDataJSON,
authenticatorData, dan attestationObject "none" memakai struktur yang sama
dengan autentikator platform sungguhan.
"""

import base64
import hashlib
import json
import os
import re
import struct
import time

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import base64url_to_bytes

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import biometrics, webauthn
from modules.authentication import face_recognition as face_mod
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import register_user
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys
from modules.strings import MSG

KATA_SANDI = "Rahasia-Uji-2026!"
USERNAME = "pengguna_uji"
EMAIL = "uji@contoh.test"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "webauthn.db"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    monkeypatch.setattr(face_mod, "_FACE_DATA_DIR", str(tmp_path / "faces"))
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(tmp_path / "dongle"))
    monkeypatch.setattr(usb_mod, "_get_removable_drives", lambda: [])
    os.makedirs(str(tmp_path / "faces"), exist_ok=True)
    init_db()
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _client_data(tipe: str, tantangan: bytes, origin: str) -> bytes:
    return json.dumps(
        {
            "type": tipe,
            "challenge": _b64url(tantangan),
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _auth_data(flags: int, sign_count: int, rp_id: str, terlampir: bytes = b"") -> bytes:
    hash_rp = hashlib.sha256(rp_id.encode("utf-8")).digest()
    return hash_rp + bytes([flags]) + struct.pack(">I", sign_count) + terlampir


class _Autentikator:
    """Autentikator platform palsu: kunci P-256 dan penyusun respons."""

    def __init__(self):
        self.kunci = ec.generate_private_key(ec.SECP256R1())
        self.id = os.urandom(32)

    def _terlampir(self) -> bytes:
        angka = self.kunci.public_key().public_numbers()
        cose = cbor2.dumps({
            1: 2,                       # kty: EC2
            3: -7,                      # alg: ES256
            -1: 1,                      # crv: P-256
            -2: angka.x.to_bytes(32, "big"),
            -3: angka.y.to_bytes(32, "big"),
        })
        aaguid = b"\x4a\x7d\x5a\x1c" + b"\x00" * 12     # AAGUID bukan nol
        return aaguid + struct.pack(">H", len(self.id)) + self.id + cose

    def respons_daftar(self, tantangan: bytes) -> dict:
        klien = _client_data("webauthn.create", tantangan, config.RP_ORIGIN)
        # 0x45 = UP | UV | AT (data kredensial terlampir)
        auth = _auth_data(0x45, 0, config.RP_ID, self._terlampir())
        objek = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {
            "id": _b64url(self.id),
            "rawId": _b64url(self.id),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": _b64url(klien),
                "attestationObject": _b64url(objek),
                "transports": ["internal"],
            },
        }

    def respons_masuk(self, tantangan: bytes, sign_count: int = 1) -> dict:
        klien = _client_data("webauthn.get", tantangan, config.RP_ORIGIN)
        auth = _auth_data(0x05, sign_count, config.RP_ID)
        dasar = auth + hashlib.sha256(klien).digest()
        tanda = self.kunci.sign(dasar, ec.ECDSA(hashes.SHA256()))
        return {
            "id": _b64url(self.id),
            "rawId": _b64url(self.id),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": _b64url(klien),
                "authenticatorData": _b64url(auth),
                "signature": _b64url(tanda),
                "userHandle": None,
            },
        }


def _token_meta(client, halaman: str = "/login") -> str:
    body = client.get(halaman).get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _token_form(client, halaman: str) -> str:
    body = client.get(halaman).get_data(as_text=True)
    cocok = re.search(r'name="csrf_token" value="([^"]+)"', body)
    assert cocok, "token CSRF tidak ditemukan"
    return cocok.group(1)


def _menuju_login(lokasi: str) -> bool:
    return lokasi in ("/", "/login")


def _daftarkan_pengguna(client) -> None:
    """Pendaftaran + konfirmasi kunci pemulihan → sesi penyiapan."""
    token = _token_form(client, "/register")
    resp = client.post("/register", data={
        "username": USERNAME,
        "email": EMAIL,
        "password": KATA_SANDI,
        "confirm_password": KATA_SANDI,
        "csrf_token": token,
    })
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    pending = re.search(r'name="pending" value="([^"]+)"', body).group(1)
    konfirm = client.post("/register/recovery", data={
        "pending": pending,
        "confirm_saved": "1",
        "csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', body).group(1),
    })
    assert konfirm.status_code == 302, konfirm.get_data(as_text=True)[:400]
    assert konfirm.headers["Location"].endswith("/setup")


def _pengguna_baru(nama: str) -> int:
    """Akun kedua tanpa wizard; kembalikan user_id."""
    hasil = register_user(nama, f"{nama}@contoh.test", KATA_SANDI)
    assert hasil["success"], hasil
    return hasil["user_id"]


def _satu_pengguna() -> dict:
    with get_db() as db:
        baris = db.execute("SELECT * FROM users").fetchone()
    return dict(baris)


def _satu_kredensial() -> dict | None:
    with get_db() as db:
        baris = db.execute(
            "SELECT * FROM webauthn_credentials ORDER BY credential_id"
        ).fetchone()
    return dict(baris) if baris else None


def _sesi_masuk(client, user_id: int, username: str) -> None:
    with client.session_transaction() as sess:
        sess.pop("setup_user_id", None)
        sess["user_id"] = user_id
        sess["username"] = username
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, b"\x5a" * 32)


def _opsi_daftar(client, csrf: str) -> bytes:
    resp = client.post(
        "/api/webauthn/register/options", json={},
        headers={"X-CSRFToken": csrf},
    )
    data = resp.get_json()
    assert data["success"] is True, data
    return base64url_to_bytes(data["options"]["challenge"])


# ── Opsi dan tantangan ───────────────────────────────────────────────────────

class TestOpsiDanTantangan:
    def test_opsi_pendaftaran_platform_dan_verifikasi_wajib(self, app):
        opsi = webauthn.buat_opsi_pendaftaran(1, USERNAME)
        seleksi = opsi["authenticatorSelection"]
        assert seleksi["authenticatorAttachment"] == "platform"
        assert seleksi["userVerification"] == "required"
        assert opsi["rp"]["id"] == config.RP_ID
        assert opsi["rp"]["name"] == "CRYPTIX"
        assert isinstance(opsi["challenge"], str) and opsi["challenge"]
        assert opsi["user"]["name"] == USERNAME

    def test_opsi_login_membolehkan_kredensial_sendiri(self, app):
        user_id = _pengguna_baru("pengguna_opsi")
        aut = _Autentikator()
        tantangan = webauthn.tantangan_baru(webauthn.kunci_daftar(user_id))
        hasil = webauthn.daftarkan_kredensial(
            user_id, aut.respons_daftar(tantangan), "uji"
        )
        assert hasil["success"] is True, hasil

        opsi = webauthn.buat_opsi_login(user_id)
        izin = opsi["allowCredentials"]
        assert len(izin) == 1
        assert izin[0]["id"] == hasil["credential_id"]
        assert opsi["userVerification"] == "required"
        assert opsi["rpId"] == config.RP_ID

    def test_tantangan_sekali_pakai(self, app):
        kunci = "uji:1"
        tantangan = webauthn.tantangan_baru(kunci)
        assert webauthn.periksa_tantangan(kunci) == tantangan
        webauthn.hapus_tantangan(kunci)
        assert webauthn.periksa_tantangan(kunci) is None

    def test_tantangan_kedaluwarsa_dibuang(self, app):
        kunci = "uji:2"
        webauthn.tantangan_baru(kunci)
        basi = time.time() - webauthn.TTL_TANTANGAN - 1
        webauthn._tantangan[kunci] = (b"tua", basi)
        assert webauthn.periksa_tantangan(kunci) is None
        assert kunci not in webauthn._tantangan

    def test_tantangan_baru_menggantikan_yang_lama(self, app):
        kunci = "uji:3"
        pertama = webauthn.tantangan_baru(kunci)
        kedua = webauthn.tantangan_baru(kunci)
        assert pertama != kedua
        assert webauthn.periksa_tantangan(kunci) == kedua

    def test_kosongkan_tantangan(self, app):
        webauthn.tantangan_baru("uji:4")
        webauthn.kosongkan_tantangan()
        assert webauthn.periksa_tantangan("uji:4") is None


# ── Pendaftaran lewat API ────────────────────────────────────────────────────

class TestPendaftaranAPI:
    def test_pendaftaran_tanpa_sesi_ditolak(self, app, client):
        csrf = _token_meta(client)
        resp = client.post(
            "/api/webauthn/register/options", json={},
            headers={"X-CSRFToken": csrf},
        )
        assert resp.status_code == 401
        assert resp.get_json()["success"] is False

    def test_pendaftaran_lengkap_lalu_gerbang_terbuka(self, app, client):
        _daftarkan_pengguna(client)
        csrf = _token_meta(client, "/setup")
        aut = _Autentikator()

        tantangan = _opsi_daftar(client, csrf)
        resp = client.post(
            "/api/webauthn/register/complete",
            json={"nama": "sidik uji", "response": aut.respons_daftar(tantangan)},
            headers={"X-CSRFToken": csrf},
        )
        data = resp.get_json()
        assert data["success"] is True, data
        assert data["setup_done"] is True

        baris = _satu_kredensial()
        assert baris["user_id"] == _satu_pengguna()["id"]
        assert baris["sign_count"] == 0
        assert baris["nama"] == "sidik uji"
        assert len(bytes.fromhex(baris["public_key"])) >= 70

        with client.session_transaction() as sess:
            assert "setup_user_id" not in sess
        # gerbang penyiapan terbuka: halaman lain kini mengarah ke masuk
        assert _menuju_login(client.get("/dashboard").headers["Location"])

    def test_kredensial_sama_ditolak(self, app, client):
        _daftarkan_pengguna(client)
        csrf = _token_meta(client, "/setup")
        aut = _Autentikator()

        tantangan = _opsi_daftar(client, csrf)
        resp = client.post(
            "/api/webauthn/register/complete",
            json={"response": aut.respons_daftar(tantangan)},
            headers={"X-CSRFToken": csrf},
        )
        assert resp.get_json()["success"] is True

        # pendaftaran ulang dari sesi masuk (halaman Settings)
        _sesi_masuk(client, _satu_pengguna()["id"], USERNAME)
        csrf = _token_meta(client, "/settings")
        tantangan = _opsi_daftar(client, csrf)
        resp = client.post(
            "/api/webauthn/register/complete",
            json={"response": aut.respons_daftar(tantangan)},
            headers={"X-CSRFToken": csrf},
        )
        data = resp.get_json()
        assert data["success"] is False
        assert data["error"] == MSG.WEBAUTHN_DUPLICATE

    def test_respons_tantangan_salah_ditolak(self, app, client):
        _daftarkan_pengguna(client)
        csrf = _token_meta(client, "/setup")
        aut = _Autentikator()
        _opsi_daftar(client, csrf)

        # tantangan yang tidak pernah diterbitkan server untuk pendaftaran ini
        respons = aut.respons_daftar(b"\x77" * 32)
        resp = client.post(
            "/api/webauthn/register/complete",
            json={"response": respons},
            headers={"X-CSRFToken": csrf},
        )
        data = resp.get_json()
        assert data["success"] is False
        assert data["error"] == MSG.WEBAUTHN_REGISTER_FAILED
        assert _satu_kredensial() is None

    def test_tantangan_pendaftaran_tanpa_opsi_ditolak(self, app, client):
        _daftarkan_pengguna(client)
        csrf = _token_meta(client, "/setup")
        aut = _Autentikator()
        tantangan = webauthn.tantangan_baru("daftar:acak")
        resp = client.post(
            "/api/webauthn/register/complete",
            json={"response": aut.respons_daftar(tantangan)},
            headers={"X-CSRFToken": csrf},
        )
        data = resp.get_json()
        assert data["success"] is False
        assert data["error"] == MSG.WEBAUTHN_CHALLENGE_EXPIRED
        assert _satu_kredensial() is None


# ── Tahap 2 login ────────────────────────────────────────────────────────────

class TestLoginDuaTahap:
    def _siapkan_kredensial(self, client) -> _Autentikator:
        _daftarkan_pengguna(client)
        csrf = _token_meta(client, "/setup")
        aut = _Autentikator()
        tantangan = _opsi_daftar(client, csrf)
        resp = client.post(
            "/api/webauthn/register/complete",
            json={"response": aut.respons_daftar(tantangan)},
            headers={"X-CSRFToken": csrf},
        )
        assert resp.get_json()["success"] is True
        return aut

    def test_login_penuh_dengan_webauthn(self, app, client):
        aut = self._siapkan_kredensial(client)

        # ── tahap 1 ───────────────────────────────────────────────────────
        csrf = _token_meta(client, "/login")
        resp = client.post(
            "/login",
            json={"username": USERNAME, "password": KATA_SANDI},
            headers={"X-CSRFToken": csrf},
        )
        tahap1 = resp.get_json()
        assert tahap1["success"] is True, tahap1
        assert [m["nama"] for m in tahap1["metode"]] == ["webauthn"]
        assert tahap1["webauthn_options"]["userVerification"] == "required"

        # ── tahap 2 ───────────────────────────────────────────────────────
        tantangan = base64url_to_bytes(tahap1["webauthn_options"]["challenge"])
        bukti = aut.respons_masuk(tantangan, sign_count=3)
        resp = client.post(
            "/login/biometric",
            json={"pending": tahap1["pending"], "bukti": {"webauthn": bukti}},
            headers={"X-CSRFToken": csrf},
        )
        tahap2 = resp.get_json()
        assert tahap2["success"] is True, tahap2

        with client.session_transaction() as sess:
            assert sess["user_id"] == _satu_pengguna()["id"]
            assert sess.get("login_stage") is None

        # sign_count diperbarui dan tantangan masuk sekali pakai
        assert _satu_kredensial()["sign_count"] == 3
        assert webauthn.periksa_tantangan(
            webauthn.kunci_masuk(_satu_pengguna()["id"])
        ) is None

    def test_login_dengan_tantangan_salah_gagal(self, app, client):
        self._siapkan_kredensial(client)

        csrf = _token_meta(client, "/login")
        resp = client.post(
            "/login",
            json={"username": USERNAME, "password": KATA_SANDI},
            headers={"X-CSRFToken": csrf},
        )
        tahap1 = resp.get_json()
        assert tahap1["success"] is True, tahap1

        # tantangan yang bukan milik permintaan ini
        bukti = _Autentikator().respons_masuk(b"\x00" * 32, sign_count=1)
        resp = client.post(
            "/login/biometric",
            json={"pending": tahap1["pending"], "bukti": {"webauthn": bukti}},
            headers={"X-CSRFToken": csrf},
        )
        data = resp.get_json()
        assert data["success"] is False
        assert data["error"] == MSG.LOGIN_BIOMETRIC_FAILED
        with client.session_transaction() as sess:
            assert "user_id" not in sess

    def test_login_tanpa_kredensial_tanpa_opsi_webauthn(self, app, client):
        _daftarkan_pengguna(client)
        # akun tanpa biometrik sama sekali: wizard dilewati agar permintaan
        # login dapat dijawab (tanpa opsi WebAuthn)
        with client.session_transaction() as sess:
            sess.pop("setup_user_id", None)
        csrf = _token_meta(client, "/login")
        resp = client.post(
            "/login",
            json={"username": USERNAME, "password": KATA_SANDI},
            headers={"X-CSRFToken": csrf},
        )
        data = resp.get_json()
        assert data["success"] is True, data
        assert data["metode"] == []
        assert "webauthn_options" not in data

    def test_verifikasi_kredensial_pengguna_lain_ditolak(self, app, client):
        pemilik = _pengguna_baru("pemilik_kredensial")
        lain = _pengguna_baru("pengguna_lain")
        aut = _Autentikator()
        tantangan = webauthn.tantangan_baru(webauthn.kunci_daftar(pemilik))
        assert webauthn.daftarkan_kredensial(
            pemilik, aut.respons_daftar(tantangan)
        )["success"] is True

        kunci = webauthn.kunci_masuk(lain)
        webauthn.tantangan_baru(kunci)
        hasil = webauthn.verifikasi_webauthn(
            lain, aut.respons_masuk(b"\x01" * 32), kunci
        )
        assert hasil["success"] is False
        assert hasil["error"] == MSG.WEBAUTHN_NO_CREDENTIAL
        # tantangan pengguna lain tidak terbuang oleh kegagalan ini
        assert webauthn.periksa_tantangan(kunci) is not None

    def test_verifikasi_tanpa_tantangan_aktif_ditolak(self, app, client):
        user_id = _pengguna_baru("tanpa_tantangan")
        aut = _Autentikator()
        tantangan = webauthn.tantangan_baru(webauthn.kunci_daftar(user_id))
        webauthn.daftarkan_kredensial(user_id, aut.respons_daftar(tantangan))
        hasil = webauthn.verifikasi_webauthn(
            user_id, aut.respons_masuk(b"\x02" * 32),
            webauthn.kunci_masuk(user_id),
        )
        assert hasil["success"] is False
        assert hasil["error"] == MSG.WEBAUTHN_CHALLENGE_EXPIRED


# ── Registry metode dan halaman Settings ─────────────────────────────────────

class TestRegistryDanSettings:
    def test_metode_webauthn_terdaftar_setelah_kredensial_ada(self, app):
        user_id = _pengguna_baru("pengguna_metode")
        assert "webauthn" not in biometrics.metode_biometrik_terdaftar(user_id)
        aut = _Autentikator()
        tantangan = webauthn.tantangan_baru(webauthn.kunci_daftar(user_id))
        assert webauthn.daftarkan_kredensial(
            user_id, aut.respons_daftar(tantangan)
        )["success"] is True
        assert biometrics.metode_biometrik_terdaftar(user_id) == ["webauthn"]
        daftar = biometrics.metode_untuk_pengguna(user_id)
        assert daftar[0]["nama"] == "webauthn"
        assert daftar[0]["label"]

    def test_settings_menampilkan_status_webauthn(self, app, client):
        _daftarkan_pengguna(client)
        baris = _satu_pengguna()
        _sesi_masuk(client, baris["id"], baris["username"])

        body = client.get("/settings").get_data(as_text=True)
        assert "<h4>WebAuthn</h4>" in body
        bagian = body.split("<h4>WebAuthn</h4>", 1)[1]
        assert "Belum didaftarkan" in bagian

        aut = _Autentikator()
        csrf = _token_meta(client, "/settings")
        tantangan = _opsi_daftar(client, csrf)
        resp = client.post(
            "/api/webauthn/register/complete",
            json={"response": aut.respons_daftar(tantangan)},
            headers={"X-CSRFToken": csrf},
        )
        data = resp.get_json()
        assert data["success"] is True, data
        assert data["setup_done"] is False

        body = client.get("/settings").get_data(as_text=True)
        bagian = body.split("<h4>WebAuthn</h4>", 1)[1]
        assert "badge-success" in bagian
        assert "Belum didaftarkan" not in bagian
