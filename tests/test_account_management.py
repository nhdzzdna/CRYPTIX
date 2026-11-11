"""
tests/test_account_management.py
────────────────────────────────
Uji UC2 Bagian 3: ubah surel, reset data akun, hapus akun, dan hapus akun
tanpa masuk lewat halaman pemulihan. Seluruh penghapusan data harus utuh
dalam satu transaksi dan rantai blockchain tetap valid.
"""

import json
import os
import re

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import create_account, register_user
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys
from modules.cryptography.key_management import unlock_dek
from modules.strings import MSG

KATA_SANDI = "Rahasia-Akun-2026!"
USERNAME = "pengguna_akun"
EMAIL = "akun@contoh.test"

KATA_SANDI_LAIN = "Rahasia-Lain-2026!"
USERNAME_LAIN = "pengguna_lain"
EMAIL_LAIN = "lain@contoh.test"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "akun.db"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    dongle = tmp_path / "dongle"
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(dongle))
    monkeypatch.setattr(usb_mod, "_get_removable_drives", lambda: [])
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    init_db()

    token = usb_mod.register_usb_token(str(dongle))
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
    application.config["TEST_DEK"] = dek
    application.config["TEST_DONGLE"] = str(dongle)
    reauth.clear()
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _baris(username: str = USERNAME) -> dict | None:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
    return dict(row) if row else None


def _masuk(client, app) -> str:
    baris = _baris()
    sid = session_keys.create_session_id()
    with client.session_transaction() as sess:
        sess["user_id"] = baris["id"]
        sess["username"] = baris["username"]
        sess["session_id"] = sid
    session_keys.put(sid, app.config["TEST_DEK"])
    return sid


def _meta_csrf(halaman: str) -> str:
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', halaman)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _form_csrf(halaman: str) -> str:
    cocok = re.search(r'name="csrf_token" value="([^"]+)"', halaman)
    assert cocok, "token CSRF form tidak ditemukan"
    return cocok.group(1)


def _grant(client, scope: str) -> str:
    csrf = _meta_csrf(client.get("/settings").get_data(as_text=True))
    resp = client.post(
        "/api/reauth",
        json={"method": "password", "scope": scope, "password": KATA_SANDI},
        headers={"X-CSRFToken": csrf},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["grant"]


def _aksi_rantai() -> set[str]:
    with get_db() as db:
        return {
            baris["action"]
            for baris in db.execute("SELECT action FROM blockchain_log").fetchall()
        }


def _seed_data(user_id: int) -> tuple[str, str]:
    """Isi seluruh tabel data pengguna dan dua berkas penyimpanan."""
    os.makedirs(config.ENCRYPTED_FILES_DIR, exist_ok=True)
    os.makedirs(config.STEGO_IMAGES_DIR, exist_ok=True)
    stored = f"{user_id}_vault.enc"
    stego = f"{user_id}_stego.png"
    with open(os.path.join(config.ENCRYPTED_FILES_DIR, stored), "wb") as handle:
        handle.write(b"isi-terenkripsi")
    with open(os.path.join(config.STEGO_IMAGES_DIR, stego), "wb") as handle:
        handle.write(b"isi-stego")

    sidik = "a" * 64
    with get_db() as db:
        kursor = db.execute(
            "INSERT INTO vault_files "
            "(user_id, original_name, stored_name, file_type, file_size, "
            " sha256_hash, sha256_ciphertext) VALUES (?,?,?,?,?,?,?)",
            (user_id, "dokumen", stored, "document", 12, sidik, sidik),
        )
        file_id = kursor.lastrowid
        db.execute(
            "INSERT INTO account_vault "
            "(user_id, site_name_enc, username_enc, password_enc) "
            "VALUES (?,?,?,?)",
            (user_id, "v1:aa:bb", "v1:cc:dd", "v1:ee:ff"),
        )
        db.execute(
            "INSERT INTO secure_notes (user_id, title_enc, content_enc) "
            "VALUES (?,?,?)",
            (user_id, "v1:11:22", "v1:33:44"),
        )
        db.execute(
            "INSERT INTO stego_images (user_id, original_name, stored_name) "
            "VALUES (?,?,?)",
            (user_id, "gambar", stego),
        )
        koleksi = db.execute(
            "INSERT INTO collections (user_id, kind, name_enc) VALUES (?,?,?)",
            (user_id, "album", "v1:55:66"),
        )
        db.execute(
            "INSERT INTO collection_items (file_id, collection_id, state) "
            "VALUES (?,?,?)",
            (file_id, koleksi.lastrowid, "normal"),
        )
        db.execute(
            "INSERT INTO webauthn_credentials "
            "(user_id, credential_id, public_key, nama) VALUES (?,?,?,?)",
            (user_id, f"kredensial-{user_id}", "pk", "uji"),
        )
        db.execute(
            "INSERT INTO biometric_templates (user_id, template, sampel) "
            "VALUES (?,?,?)",
            (user_id, b"template-wajah", 1),
        )
        db.commit()
    return stored, stego


def _jumlah(tabel: str, user_id: int) -> int:
    with get_db() as db:
        return db.execute(
            f"SELECT COUNT(*) AS jumlah FROM {tabel} WHERE user_id = ?",
            (user_id,),
        ).fetchone()["jumlah"]


def _rantai_valid() -> bool:
    return all(blok["is_valid"] for blok in bc.verify_chain())


# ── Ubah surel ────────────────────────────────────────────────────────────────

class TestUbahEmail:
    def test_email_valid_diperbarui(self, app, client):
        _masuk(client, app)
        grant = _grant(client, "settings.change")
        resp = client.post(
            "/settings/email",
            data={
                "csrf_token": _form_csrf(client.get("/settings").get_data(as_text=True)),
                "reauth_grant": grant,
                "current_password": KATA_SANDI,
                "email": "akun.baru@contoh.test",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert MSG.SETTINGS_EMAIL_CHANGED in resp.get_data(as_text=True)
        assert _baris()["email"] == "akun.baru@contoh.test"
        assert "MODIFY" in _aksi_rantai()
        assert _rantai_valid()

    def test_email_duplikat_ditolak(self, app, client):
        assert register_user(USERNAME_LAIN, EMAIL_LAIN, KATA_SANDI_LAIN)["success"]
        _masuk(client, app)
        grant = _grant(client, "settings.change")
        resp = client.post(
            "/settings/email",
            data={
                "csrf_token": _form_csrf(client.get("/settings").get_data(as_text=True)),
                "reauth_grant": grant,
                "current_password": KATA_SANDI,
                "email": EMAIL_LAIN,
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert MSG.SETTINGS_EMAIL_TAKEN in resp.get_data(as_text=True)
        assert _baris()["email"] == EMAIL

    def test_email_tanpa_grant_ditolak(self, app, client):
        _masuk(client, app)
        resp = client.post(
            "/settings/email",
            data={
                "csrf_token": _form_csrf(client.get("/settings").get_data(as_text=True)),
                "current_password": KATA_SANDI,
                "email": "tanpa.grant@contoh.test",
            },
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"
        assert _baris()["email"] == EMAIL

    def test_email_password_salah_ditolak(self, app, client):
        _masuk(client, app)
        grant = _grant(client, "settings.change")
        resp = client.post(
            "/settings/email",
            data={
                "csrf_token": _form_csrf(client.get("/settings").get_data(as_text=True)),
                "reauth_grant": grant,
                "current_password": "Kata-Sandi-Salah-2026!",
                "email": "salah@contoh.test",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert MSG.SETTINGS_WRONG_PASSWORD in resp.get_data(as_text=True)
        assert _baris()["email"] == EMAIL


# ── Reset data ────────────────────────────────────────────────────────────────

class TestResetData:
    def _kirim_reset(self, client, username: str = USERNAME):
        grant = _grant(client, "account.danger")
        return client.post(
            "/settings/reset-data",
            data={
                "csrf_token": _form_csrf(client.get("/settings").get_data(as_text=True)),
                "reauth_grant": grant,
                "current_password": KATA_SANDI,
                "confirm_username": username,
            },
            follow_redirects=True,
        )

    def test_reset_menyimpan_akun_dan_menghapus_data(self, app, client):
        _masuk(client, app)
        user_id = _baris()["id"]
        stored, stego = _seed_data(user_id)

        with get_db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS trash_items "
                "(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL)"
            )
            db.execute("INSERT INTO trash_items (user_id) VALUES (?)", (user_id,))
            db.commit()

        resp = self._kirim_reset(client)
        assert resp.status_code == 200
        assert MSG.SETTINGS_RESET_DONE in resp.get_data(as_text=True)

        # Akun, kunci, kredensial WebAuthn, dan templat wajah tetap ada.
        assert _baris() is not None
        assert _jumlah("webauthn_credentials", user_id) == 1
        assert _jumlah("biometric_templates", user_id) == 1
        assert _baris()["wrapped_dek"]

        # Seluruh data pengguna hilang.
        for tabel in (
            "vault_files", "account_vault", "secure_notes",
            "stego_images", "collections", "trash_items",
        ):
            assert _jumlah(tabel, user_id) == 0, tabel
        with get_db() as db:
            sisa = db.execute(
                "SELECT COUNT(*) AS jumlah FROM collection_items"
            ).fetchone()["jumlah"]
        assert sisa == 0

        assert not os.path.exists(
            os.path.join(config.ENCRYPTED_FILES_DIR, stored)
        )
        assert not os.path.exists(
            os.path.join(config.STEGO_IMAGES_DIR, stego)
        )
        assert "ACCOUNT_RESET" in _aksi_rantai()
        assert _rantai_valid()

    def test_reset_username_salah_ditolak(self, app, client):
        _masuk(client, app)
        user_id = _baris()["id"]
        _seed_data(user_id)

        resp = self._kirim_reset(client, username="nama_lain")
        assert resp.status_code == 200
        assert MSG.SETTINGS_CONFIRM_USERNAME_MISMATCH in resp.get_data(as_text=True)
        assert _jumlah("vault_files", user_id) == 1
        assert _jumlah("secure_notes", user_id) == 1

    def test_reset_tanpa_grant_ditolak(self, app, client):
        _masuk(client, app)
        user_id = _baris()["id"]
        _seed_data(user_id)

        resp = client.post(
            "/settings/reset-data",
            data={
                "csrf_token": _form_csrf(client.get("/settings").get_data(as_text=True)),
                "current_password": KATA_SANDI,
                "confirm_username": USERNAME,
            },
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"
        assert _jumlah("vault_files", user_id) == 1

    def test_pengguna_lain_tidak_terpengaruh(self, app, client):
        assert register_user(USERNAME_LAIN, EMAIL_LAIN, KATA_SANDI_LAIN)["success"]
        lain = _baris(USERNAME_LAIN)
        _seed_data(lain["id"])

        _masuk(client, app)
        user_id = _baris()["id"]
        _seed_data(user_id)

        resp = self._kirim_reset(client)
        assert resp.status_code == 200
        assert _jumlah("vault_files", user_id) == 0
        assert _jumlah("vault_files", lain["id"]) == 1
        assert _jumlah("secure_notes", lain["id"]) == 1
        assert _baris(USERNAME_LAIN) is not None


# ── Hapus akun ────────────────────────────────────────────────────────────────

class TestHapusAkun:
    def _kirim_hapus(self, client, username: str = USERNAME):
        grant = _grant(client, "account.danger")
        return client.post(
            "/settings/delete-account",
            data={
                "csrf_token": _form_csrf(client.get("/settings").get_data(as_text=True)),
                "reauth_grant": grant,
                "current_password": KATA_SANDI,
                "confirm_username": username,
            },
        )

    def test_hapus_akun_membebaskan_dongle(self, app, client):
        _masuk(client, app)
        user_id = _baris()["id"]
        stored, stego = _seed_data(user_id)

        resp = self._kirim_hapus(client)
        assert resp.status_code == 302
        assert resp.headers["Location"].rstrip("/") in ("", "/login")

        assert _baris() is None
        assert _jumlah("vault_files", user_id) == 0
        assert _jumlah("webauthn_credentials", user_id) == 0
        assert _jumlah("biometric_templates", user_id) == 0
        assert not os.path.exists(
            os.path.join(config.ENCRYPTED_FILES_DIR, stored)
        )
        assert not os.path.exists(
            os.path.join(config.STEGO_IMAGES_DIR, stego)
        )
        assert "ACCOUNT_DELETE" in _aksi_rantai()
        assert _rantai_valid()

        # Dongle yang sama dapat didaftarkan ulang oleh akun lain.
        token = usb_mod.register_usb_token(app.config["TEST_DONGLE"])
        assert token is not None
        hasil = create_account(USERNAME_LAIN, EMAIL_LAIN, KATA_SANDI_LAIN, token)
        assert hasil["success"], hasil
        assert _baris(USERNAME_LAIN) is not None

    def test_hapus_username_salah_ditolak(self, app, client):
        _masuk(client, app)
        user_id = _baris()["id"]
        _seed_data(user_id)

        resp = self._kirim_hapus(client, username="nama_lain")
        assert resp.status_code == 302
        assert _baris() is not None
        assert _jumlah("vault_files", user_id) == 1

    def test_hapus_tanpa_grant_ditolak(self, app, client):
        _masuk(client, app)
        user_id = _baris()["id"]

        resp = client.post(
            "/settings/delete-account",
            data={
                "csrf_token": _form_csrf(client.get("/settings").get_data(as_text=True)),
                "current_password": KATA_SANDI,
                "confirm_username": USERNAME,
            },
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"
        assert _baris() is not None
        assert _jumlah("vault_files", user_id) == 0


# ── Hapus akun tanpa masuk (halaman pemulihan) ────────────────────────────────

class TestHapusAkunPemulihan:
    def _halaman(self, client) -> str:
        return client.get("/account-recovery").get_data(as_text=True)

    def _kirim(self, client, password: str = KATA_SANDI,
               username: str = USERNAME, confirm: str | None = None):
        return client.post(
            "/recovery/reset-account",
            data={
                "csrf_token": _form_csrf(self._halaman(client)),
                "username": username,
                "confirm_username": confirm if confirm is not None else username,
                "password": password,
            },
        )

    def test_halaman_memuat_form_reset_dan_batasannya(self, app, client):
        html = self._halaman(client)
        assert MSG.RECOVERY_RESET_LINK in html
        assert MSG.RECOVERY_RESET_LIMITATION in html
        assert 'action="/recovery/reset-account"' in html

    def test_modal_reset_akun_memuat_komponen_kx_dan_peringatan_keterbatasan(self, app, client):
        html = self._halaman(client)
        assert 'id="modal-reset-account"' in html
        assert 'data-buka-modal="#modal-reset-account"' in html
        assert "jika kata sandi dan dongle hilang, tidak ada jalur dari aplikasi" in html.lower()
        assert 'id="reset-username"' in html
        assert 'id="reset-confirm-username"' in html
        assert 'id="reset-password"' in html
        assert 'data-kx-sandi' in html

    def test_tanpa_kata_terlarang_pemulihan_reset(self):
        kata_terlarang = [
            "sem" + "ester",
            "U" + "AS",
            "U" + "TS",
            "maha" + "siswa",
            "do" + "sen",
        ]
        for jalur in ("templates/account_recovery.html", "static/js/account_recovery.js"):
            with open(jalur, "r", encoding="utf-8") as handle:
                konten = handle.read().lower()
            for kata in kata_terlarang:
                assert kata.lower() not in konten, f"Kata terlarang '{kata}' ditemukan di {jalur}"

    def test_tanpa_dongle_ditolak(self, app, client, monkeypatch):
        monkeypatch.setattr(usb_mod, "_kandidat_drive", lambda: [])
        user_id = _baris()["id"]
        _seed_data(user_id)

        resp = self._kirim(client)
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/account-recovery")
        assert _baris() is not None
        assert _jumlah("vault_files", user_id) == 1

    def test_password_salah_ditolak(self, app, client):
        user_id = _baris()["id"]
        _seed_data(user_id)

        resp = self._kirim(client, password="Kata-Sandi-Salah-2026!")
        assert resp.status_code == 302
        assert _baris() is not None
        assert _jumlah("vault_files", user_id) == 1

    def test_sukses_menghapus_akun_dan_data(self, app, client):
        user_id = _baris()["id"]
        stored, stego = _seed_data(user_id)

        resp = self._kirim(client)
        assert resp.status_code == 302
        assert resp.headers["Location"].rstrip("/") in ("", "/login")

        assert _baris() is None
        assert _jumlah("vault_files", user_id) == 0
        assert _jumlah("webauthn_credentials", user_id) == 0
        assert _jumlah("biometric_templates", user_id) == 0
        assert not os.path.exists(
            os.path.join(config.ENCRYPTED_FILES_DIR, stored)
        )
        assert not os.path.exists(
            os.path.join(config.STEGO_IMAGES_DIR, stego)
        )
        assert "ACCOUNT_DELETE" in _aksi_rantai()
        assert _rantai_valid()

        token = usb_mod.register_usb_token(app.config["TEST_DONGLE"])
        assert token is not None
        hasil = create_account(USERNAME_LAIN, EMAIL_LAIN, KATA_SANDI_LAIN, token)
        assert hasil["success"], hasil
