"""
tests/test_registration_flow.py
───────────────────────────────
Uji Fase 2 butir 2.1–2.3: kebijakan akun, pendaftaran berdongle, penulisan
token ke dongle, kunci pemulihan tampil sekali, dan wizard penyiapan keamanan.
"""

import hashlib
import hmac
import json
import os
import re
import shutil

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import face_recognition as face_mod
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import (
    register_user, validate_email, validate_password,
    validate_registration, validate_username,
)
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys
from modules.cryptography.key_management import unlock_dek
from modules.strings import MSG

KATA_SANDI = "Rahasia-Uji-2026!"
USERNAME = "pengguna_uji"
EMAIL = "uji@contoh.test"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "registrasi.db"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(tmp_path / "dongle"))
    monkeypatch.setattr(usb_mod, "_get_removable_drives", lambda: [])
    init_db()
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _token_csrf_dari(halaman_html: str) -> str:
    cocok = re.search(r'name="csrf_token" value="([^"]+)"', halaman_html)
    if cocok is None:
        # halaman tanpa form (mis. wizard tanpa unggahan) memakai meta
        cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', halaman_html)
    assert cocok, "token CSRF tidak ditemukan"
    return cocok.group(1)


def _menuju_login(lokasi: str) -> bool:
    """url_for('auth.login') memilih rule '/' sehingga kedua bentuk diterima."""
    return lokasi in ("/", "/login")


def _token_csrf(client, halaman: str) -> str:
    page = client.get(halaman)
    assert page.status_code == 200, page.get_data(as_text=True)[:400]
    return _token_csrf_dari(page.get_data(as_text=True))


def _isi_register(client, **tambahan):
    data = {
        "username": USERNAME,
        "email": EMAIL,
        "password": KATA_SANDI,
        "confirm_password": KATA_SANDI,
        "csrf_token": _token_csrf(client, "/register"),
    }
    data.update(tambahan)
    return client.post("/register", data=data)


def _kunci_dari(halaman_html: str) -> str:
    cocok = re.search(r'<code id="recovery-key"[^>]*>([^<]+)</code>', halaman_html)
    assert cocok, "kunci pemulihan tidak ditampilkan"
    return cocok.group(1).strip()


def _pending_dari(halaman_html: str) -> str:
    cocok = re.search(r'name="pending" value="([^"]+)"', halaman_html)
    assert cocok, "token pending tidak ditemukan"
    return cocok.group(1)


def _satu_pengguna() -> dict | None:
    with get_db() as db:
        row = db.execute("SELECT * FROM users").fetchone()
    return dict(row) if row else None


def _daftarkan_dan_konfirmasi(client) -> str:
    """Pendaftaran sukses lalu konfirmasi kunci pemulihan; kembalikan pending."""
    resp = _isi_register(client)
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    pending = _pending_dari(body)
    konfirm = client.post("/register/recovery", data={
        "pending": pending,
        "confirm_saved": "1",
        "csrf_token": _token_csrf_dari(body),
    })
    assert konfirm.status_code == 302, konfirm.get_data(as_text=True)[:400]
    assert konfirm.headers["Location"].endswith("/setup")
    return pending


def _sesi_masuk(client, user_id: int = 1, username: str = "pengujian") -> str:
    """Pasang sesi login buatan; kembalikan session id yang dipakai."""
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = username
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, b"\x5a" * 32)
    return sid


# ── 2.1 Kebijakan akun ────────────────────────────────────────────────────────

class TestKebijakanAkun:
    def test_username_valid_dan_invalid(self):
        assert validate_username("pengguna_uji") is None
        assert validate_username("ab") == MSG.REGISTER_USERNAME_INVALID
        assert validate_username("spasi di sini") == MSG.REGISTER_USERNAME_INVALID
        assert validate_username("karakter-asing✓") == MSG.REGISTER_USERNAME_INVALID

    def test_surel_valid_dan_invalid(self):
        assert validate_email("uji@contoh.test") is None
        assert validate_email("tanpa-at") == MSG.REGISTER_EMAIL_INVALID
        assert validate_email("dua@at@contoh.test") == MSG.REGISTER_EMAIL_INVALID
        assert validate_email("x@contoh") == MSG.REGISTER_EMAIL_INVALID

    def test_kata_sandi_terlalu_pendek(self):
        assert validate_password("Ab3!short", USERNAME) == MSG.REGISTER_PASSWORD_TOO_SHORT

    def test_kata_sandi_memuat_username(self):
        assert validate_password("pengguna_uji-2026!", USERNAME) == \
            MSG.REGISTER_PASSWORD_USERNAME

    def test_kata_sandi_umum(self):
        assert validate_password("password1234", USERNAME) == MSG.REGISTER_PASSWORD_COMMON

    def test_kata_sandi_kurang_jenis_karakter(self):
        # hanya huruf kecil + huruf besar (2 dari 4)
        assert validate_password("HanyaaHuruufSaja", USERNAME) == \
            MSG.REGISTER_PASSWORD_COMPLEX

    def test_kata_sandi_memenuhi_kebijakan(self):
        assert validate_password(KATA_SANDI, USERNAME) is None

    def test_konfirmasi_tidak_cocok(self):
        assert validate_registration(USERNAME, EMAIL, KATA_SANDI, "lain") == \
            MSG.REGISTER_PASSWORD_MISMATCH

    def test_isian_kosong(self):
        assert validate_registration("", EMAIL, KATA_SANDI, KATA_SANDI) == \
            MSG.REGISTER_FIELDS_REQUIRED

    def test_galat_registrasi_tanpa_kebocoran_exception(self, client):
        resp = _isi_register(client, email="bukan-email")
        body = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert MSG.REGISTER_EMAIL_INVALID in body
        assert "Traceback" not in body and "sqlite3" not in body
        assert _satu_pengguna() is None


# ── 2.2 Dongle USB ────────────────────────────────────────────────────────────

class TestDongleUSB:
    def test_daftar_drive_muat_folder_mode_pengembangan(self, app, tmp_path):
        drives = usb_mod.daftar_drive()
        tujuan = os.path.normpath(str(tmp_path / "dongle"))
        assert any(os.path.normpath(d["mountpoint"]) == tujuan for d in drives)

    def test_token_ditulis_dan_verifier_cocok(self, app, tmp_path):
        token = usb_mod.register_usb_token(str(tmp_path / "dongle"))
        assert token is not None
        path = os.path.join(str(tmp_path / "dongle"), config.USB_TOKEN_FILENAME)
        with open(path, "r", encoding="utf-8") as handle:
            isi = json.load(handle)
        assert isi["version"] == usb_mod.TOKEN_VERSION
        assert isi["token_id"] == token["token_id"]
        rahasia = bytes.fromhex(isi["secret"])
        assert len(rahasia) == 32
        ver = hmac.new(rahasia, b"cryptix-usb-verifier", hashlib.sha256).hexdigest()
        assert ver == token["verifier"]

        ok, kembali = usb_mod.verify_usb_token(
            token["verifier"], token["volume_serial"], token["token_id"]
        )
        assert ok is True and kembali == rahasia

    def test_verifier_salah_ditolak(self, app, tmp_path):
        token = usb_mod.register_usb_token(str(tmp_path / "dongle"))
        assert usb_mod.verify_usb_token(
            "00" * 32, token["volume_serial"], token["token_id"]
        ) == (False, None)
        assert usb_mod.verify_usb_token(
            token["verifier"], token["volume_serial"], "id-salah"
        ) == (False, None)

    def test_gerbang_startup_mode_setup_awal(self, app):
        assert usb_mod.gerbang_startup() is None

    def test_gerbang_startup_pengguna_tanpa_dongle(self, app):
        register_user(USERNAME, EMAIL, KATA_SANDI)
        assert usb_mod.gerbang_startup() == MSG.USB_STARTUP_UNREGISTERED

    def test_gerbang_startup_dongle_terpasang(self, app, client, tmp_path):
        _isi_register(client)
        assert usb_mod.gerbang_startup() is None

    def test_gerbang_startup_dongle_tidak_terpasang(self, app, client, tmp_path):
        _isi_register(client)
        shutil.rmtree(str(tmp_path / "dongle"))
        usb_mod.lupakan_cache()
        assert usb_mod.gerbang_startup() == MSG.USB_STARTUP_BLOCKED

    def test_sesi_masuk_tanpa_dongle_dibuang(self, app, client, tmp_path):
        _isi_register(client)
        baris = _satu_pengguna()
        shutil.rmtree(str(tmp_path / "dongle"))
        usb_mod.lupakan_cache()
        sid = _sesi_masuk(client, user_id=baris["id"], username=baris["username"])
        resp = client.get("/crypto-tools")
        assert resp.status_code == 302
        assert _menuju_login(resp.headers["Location"])
        assert session_keys.get(sid) is None
        with client.session_transaction() as sess:
            assert "user_id" not in sess


# ── 2.3a Form registrasi dengan daftar dongle ────────────────────────────────

class TestFormRegistrasiDongle:
    def test_form_menampilkan_daftar_dongle(self, app, client, tmp_path):
        body = client.get("/register").get_data(as_text=True)
        assert 'name="dongle"' in body
        assert str(tmp_path / "dongle") in body

    def test_endpoint_daftar_drive(self, app, client, tmp_path):
        resp = client.get("/api/usb_drives")
        data = resp.get_json()
        tujuan = os.path.normpath(str(tmp_path / "dongle"))
        assert any(
            os.path.normpath(d["mountpoint"]) == tujuan for d in data["drives"]
        )

    def test_tanpa_dongle_pendaftaran_ditolak(self, app, client, monkeypatch):
        monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", False)
        monkeypatch.setattr(usb_mod, "_get_removable_drives", lambda: [])
        resp = _isi_register(client)
        body = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert MSG.REGISTER_USB_REQUIRED in body
        assert _satu_pengguna() is None

    def test_dongle_palsu_ditolak(self, app, client):
        resp = _isi_register(client, dongle="/tidak/ada/dongle")
        body = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert MSG.REGISTER_USB_INVALID in body
        assert _satu_pengguna() is None


# ── 2.3b Penulisan token + kunci pemulihan sekali ────────────────────────────

class TestPendaftaranLengkap:
    def test_akun_dibuat_dengan_bundle_dan_dongle(self, app, client, tmp_path):
        resp = _isi_register(client)
        body = resp.get_data(as_text=True)
        assert resp.status_code == 200

        baris = _satu_pengguna()
        assert baris["username"] == USERNAME
        assert baris["kek_salt"] and baris["wrapped_dek"]
        assert baris["recovery_wrapped_dek"]
        assert baris["usb_token_id"] and baris["usb_verifier"]

        path = os.path.join(str(tmp_path / "dongle"), config.USB_TOKEN_FILENAME)
        with open(path, "r", encoding="utf-8") as handle:
            isi = json.load(handle)
        assert isi["token_id"] == baris["usb_token_id"]
        rahasia = bytes.fromhex(isi["secret"])
        ver = hmac.new(rahasia, b"cryptix-usb-verifier", hashlib.sha256).hexdigest()
        assert ver == baris["usb_verifier"]

        dek = unlock_dek(KATA_SANDI, rahasia, baris)
        assert len(dek) == 32
        with pytest.raises(ValueError):
            unlock_dek(KATA_SANDI, b"\x00" * 32, baris)

        # halaman kunci pemulihan tampil sebagai respons pendaftaran
        kunci = _kunci_dari(body)
        assert re.fullmatch(r"(?:[A-Z2-7]{8}-){1,7}[A-Z2-7]{1,8}", kunci)
        assert resp.headers.get("Cache-Control", "").startswith("no-store")

    def test_kunci_pulih_tidak_masuk_cookie_atau_flash(self, app, client):
        resp = _isi_register(client)
        kunci = _kunci_dari(resp.get_data(as_text=True))
        cookie = client.get_cookie("session")
        isi_cookie = cookie.value if cookie else ""
        assert kunci not in isi_cookie
        with client.session_transaction() as sess:
            assert kunci not in str(sess.get("_flashes", []))
            assert kunci not in str(dict(sess))

    def test_konfirmasi_wajib_dicentang(self, app, client):
        resp = _isi_register(client)
        body = resp.get_data(as_text=True)
        kunci, pending = _kunci_dari(body), _pending_dari(body)
        ulang = client.post("/register/recovery", data={
            "pending": pending,
            "csrf_token": _token_csrf_dari(body),
        })
        isi = ulang.get_data(as_text=True)
        assert ulang.status_code == 200
        assert MSG.RECOVERY_CHECK_REQUIRED in isi
        assert _kunci_dari(isi) == kunci  # kunci masih tampil

    def test_konfirmasi_lanjut_ke_setup_dan_sekali_pakai(self, app, client):
        resp = _isi_register(client)
        body = resp.get_data(as_text=True)
        kunci = _kunci_dari(body)
        pending = _pending_dari(body)
        token = _token_csrf_dari(body)

        konfirm = client.post("/register/recovery", data={
            "pending": pending, "confirm_saved": "1", "csrf_token": token,
        })
        assert konfirm.status_code == 302
        assert konfirm.headers["Location"].endswith("/setup")
        with client.session_transaction() as sess:
            assert "setup_user_id" in sess

        # percobaan kedua: gerbang penyiapan mengambil alih, kunci tidak tampil lagi
        ulang = client.post("/register/recovery", data={
            "pending": pending, "confirm_saved": "1", "csrf_token": token,
        }, follow_redirects=True)
        assert ulang.status_code == 200
        assert kunci not in ulang.get_data(as_text=True)

    def test_pending_kedaluwarsa_ditolak(self, app, client):
        token = _token_csrf(client, "/register")
        resp = client.post("/register/recovery", data={
            "pending": "token-acak-yang-tidak-ada",
            "confirm_saved": "1",
            "csrf_token": token,
        })
        assert resp.status_code == 302
        assert _menuju_login(resp.headers["Location"])
        with client.session_transaction() as sess:
            assert MSG.RECOVERY_ONLY_ONCE in str(sess.get("_flashes", []))


# ── 2.3c Wizard penyiapan keamanan ───────────────────────────────────────────

class TestPenyiapanKeamanan:
    def test_hanya_halaman_setup_yang_bisa_diakses(self, app, client):
        _daftarkan_dan_konfirmasi(client)
        for halaman in ("/dashboard", "/settings", "/register", "/login",
                        "/crypto-tools"):
            resp = client.get(halaman)
            assert resp.status_code == 302, halaman
            assert resp.headers["Location"].endswith("/setup"), halaman
        assert client.get("/setup").status_code == 200

    def test_setup_tanpa_sesi_mengarahkan_ke_login(self, app, client):
        resp = client.get("/setup")
        assert resp.status_code == 302
        assert _menuju_login(resp.headers["Location"])

    def test_unggah_sidik_jari_sudah_dihapus(self, app, client):
        _daftarkan_dan_konfirmasi(client)
        body = client.get("/setup").get_data(as_text=True)
        assert 'name="fingerprint_image"' not in body
        assert "daftarWebAuthn" in body
        # unggah citra sidik jari tidak lagi menjadi bagian wizard
        aturan = next(r for r in app.url_map.iter_rules() if r.rule == "/setup")
        assert "POST" not in aturan.methods
        assert client.get("/dashboard").headers["Location"].endswith("/setup")

    def test_wajah_menyelesaikan_penyiapan(self, app, client, monkeypatch):
        _daftarkan_dan_konfirmasi(client)
        token = _token_csrf(client, "/setup")

        def _daftar_palsu(uid, frames, dek):
            with get_db() as db:
                db.execute(
                    "INSERT INTO biometric_templates "
                    "(user_id, metode, template, sampel) VALUES (?, 'wajah', ?, ?)",
                    (uid, b"FG1-palsu", len(frames)),
                )
                db.commit()
            return {"success": True, "sampel": len(frames)}

        monkeypatch.setattr(face_mod, "daftarkan_wajah", _daftar_palsu)
        resp = client.post(
            "/api/register_face",
            json={"frames": ["data:image/jpeg;base64,AAAA"] * 30,
                  "duration_ms": 3100},
            headers={"X-CSRFToken": token},
        )
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["success"] is True
        assert data["setup_done"] is True
        with client.session_transaction() as sess:
            assert "setup_user_id" not in sess
        assert _menuju_login(client.get("/dashboard").headers["Location"])

    def test_api_wajah_tanpa_sesi_ditolak(self, app, client):
        token = _token_csrf(client, "/register")
        resp = client.post(
            "/api/register_face", json={"frames": []},
            headers={"X-CSRFToken": token},
        )
        assert resp.status_code == 401
        assert resp.get_json()["success"] is False


# ── Tombol Logout pada sidebar ────────────────────────────────────────────────

class TestTombolLogout:
    def test_sidebar_memakai_form_post_bercsrf(self, app, client):
        _sesi_masuk(client)
        body = client.get("/crypto-tools").get_data(as_text=True)
        assert re.search(r'<form method="POST" action="/logout"[^>]*>', body)
        assert 'name="csrf_token"' in body

    def test_logout_post_berfungsi(self, app, client):
        sid = _sesi_masuk(client)
        token = _token_csrf(client, "/crypto-tools")
        resp = client.post("/logout", data={"csrf_token": token})
        assert resp.status_code == 302
        assert _menuju_login(resp.headers["Location"])
        assert session_keys.get(sid) is None
        with client.session_transaction() as sess:
            assert "user_id" not in sess

    def test_logout_get_ditolak(self, app, client):
        _sesi_masuk(client)
        assert client.get("/logout").status_code == 405


# ── Fungsi lama yang dihapus ──────────────────────────────────────────────────

def test_get_stego_key_dan_super_enc_subkey_dihapus():
    import modules.cryptography.key_management as key_management
    assert not hasattr(key_management, "get_stego_key")
    assert not hasattr(key_management, "get_super_enc_subkey")
