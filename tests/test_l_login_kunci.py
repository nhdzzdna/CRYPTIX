"""
tests/test_l_login_kunci.py
──────────────────────────
Tes tambahan checklist 5.1 a–b:
  • kesetaraan waktu respons login antara username tidak ada dan username ada;
  • hash password di basis data tidak dapat dipakai membuka data terenkripsi;
  • ganti kata sandi membungkus ulang DEK tanpa merusak data lama.
"""

import re
import time

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import biometrics
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import create_account, verifikasi_tahap_satu
from modules.blockchain import blockchain as bc
from modules.cryptography.database_encryption import decrypt_record
from modules.cryptography.key_management import purpose_key
from modules.cryptography.super_encryption import super_decrypt

KATA_SANDI = "Rahasia-Awal-2026!"
KATA_SANDI_BARU = "Rahasia-Baru-2026!"
USERNAME = "pengguna_l1"
EMAIL = "l1@contoh.test"

SITUS = "Situs L1"
SITUS_PENGGUNA = "rahasia-l1-user"
SITUS_SANDI = "Rahasia-Kredensial-L1!"
JUDUL_CATATAN = "Judul Catatan L1"
ISI_CATATAN = "Isi catatan rahasia L1"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "l1.db"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    # Iterasi cukup tinggi agar biaya kriptografi terukur di atas overhead.
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 40_000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 40_000)
    monkeypatch.setattr(config, "SUPER_ENC_PBKDF2_ITERATIONS", 1_000)
    monkeypatch.setattr(config, "BIOMETRIC_POLICY", "all_enrolled")
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(tmp_path / "dongle"))
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    monkeypatch.setattr(usb_mod, "_get_removable_drives", lambda: [])
    init_db()
    token = usb_mod.register_usb_token(str(tmp_path / "dongle"))
    assert token is not None
    hasil = create_account(USERNAME, EMAIL, KATA_SANDI, token)
    assert hasil["success"], hasil
    application = create_app()
    application.config["TESTING"] = True
    application.config["TEST_RECOVERY_KEY"] = hasil["recovery_key"]
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _csrf_meta(client, halaman="/login") -> str:
    body = client.get(halaman).get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _csrf_form(client, halaman) -> str:
    body = client.get(halaman).get_data(as_text=True)
    cocok = re.search(r'name="csrf_token" value="([^"]+)"', body)
    assert cocok, "token CSRF form tidak ditemukan"
    return cocok.group(1)


def _masuk(client):
    """Login dua tahap memakai metode biometrik uji; DEK tersimpan di server."""
    biometrics.tambah_metode(
        "uji", "Metode Uji",
        terdaftar=lambda user_id: True,
        verifikasi=lambda user_id, bukti: bukti == {"kunci": "sah"},
    )
    try:
        csrf = _csrf_meta(client)
        tahap1 = client.post(
            "/login",
            json={"username": USERNAME, "password": KATA_SANDI},
            headers={"X-CSRFToken": csrf},
        )
        assert tahap1.status_code == 200, tahap1.get_data(as_text=True)
        tahap2 = client.post(
            "/login/biometric",
            json={
                "pending": tahap1.get_json()["pending"],
                "bukti": {"uji": {"kunci": "sah"}},
            },
            headers={"X-CSRFToken": csrf},
        )
        assert tahap2.status_code == 200, tahap2.get_data(as_text=True)
    finally:
        biometrics.hapus_metode("uji")


def _tambah_data(client):
    """Simpan satu kredensial dan satu catatan lewat rute, lalu kembalikan baris DB."""
    with client.session_transaction() as sess:
        uid = sess["user_id"]

    token = _csrf_form(client, "/account-vault")
    resp = client.post("/account-vault/add", data={
        "csrf_token": token,
        "site_name": SITUS,
        "username": SITUS_PENGGUNA,
        "password": SITUS_SANDI,
        "url": "https://l1.contoh.test",
        "notes": "catatan akun L1",
    })
    assert resp.status_code == 302

    token = _csrf_form(client, "/secure-notes")
    resp = client.post("/secure-notes/add", data={
        "csrf_token": token,
        "title": JUDUL_CATATAN,
        "content": ISI_CATATAN,
    })
    assert resp.status_code == 302

    with get_db() as db:
        kredensial = dict(db.execute(
            "SELECT * FROM account_vault WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (uid,),
        ).fetchone())
        catatan = dict(db.execute(
            "SELECT * FROM secure_notes WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (uid,),
        ).fetchone())
    return uid, kredensial, catatan


def _grant(client, scope="settings.change") -> str:
    csrf = _csrf_meta(client, "/settings")
    resp = client.post(
        "/api/reauth",
        json={"method": "password", "scope": scope, "password": KATA_SANDI},
        headers={"X-CSRFToken": csrf},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["grant"]


class TestWaktuLogin:
    def test_waktu_username_tidak_ada_setara_dengan_username_ada(self, app):
        """Biaya PBKDF2 tiruan menyamakan waktu kedua jalur (toleransi longgar)."""
        # Pemanasan: muat cache dongle dan modul kriptografi.
        assert verifikasi_tahap_satu(USERNAME, KATA_SANDI)["success"] is True
        assert verifikasi_tahap_satu("pemanasan_l1", "salah-l1")["success"] is False

        def ukur(username: str, password: str) -> float:
            mulai = time.perf_counter()
            verifikasi_tahap_satu(username, password)
            return time.perf_counter() - mulai

        waktu_ada, waktu_tidak = [], []
        for _ in range(15):
            # Bergantian, supaya kedua jalur mengalami kondisi mesin yang sama.
            waktu_ada.append(ukur(USERNAME, KATA_SANDI))
            waktu_tidak.append(ukur("pengguna_tidak_ada_l1", "kata-sandi-salah-l1"))

        rata_ada = min(waktu_ada)
        rata_tidak = min(waktu_tidak)

        selisih = abs(rata_ada - rata_tidak)
        ambang = max(0.005, 0.5 * max(rata_ada, rata_tidak))

        assert selisih <= ambang, (
            f"waktu username ada {rata_ada:.4f}s vs tidak ada {rata_tidak:.4f}s"
        )


class TestKunci:
    def test_hash_password_di_db_tidak_dapat_membuka_data(self, client):
        _masuk(client)
        uid, kredensial, catatan = _tambah_data(client)
        with get_db() as db:
            pengguna = dict(db.execute(
                "SELECT password_hash FROM users WHERE id=?", (uid,)
            ).fetchone())

        # Nilai kolom password_hash bukan kunci enkripsi: menurunkannya sebagai
        # purpose_key tetap gagal membuka field terenkripsi.
        kunci_hash = purpose_key(
            bytes.fromhex(pengguna["password_hash"]), "database"
        )
        with pytest.raises(ValueError):
            decrypt_record(
                {"password_enc": kredensial["password_enc"]},
                kunci_hash, uid, "account_vault",
            )
        with pytest.raises(ValueError):
            decrypt_record(
                {"content_enc": catatan["content_enc"]},
                kunci_hash, uid, "secure_notes",
            )

    def test_ganti_kata_sandi_tidak_merusak_data(self, client):
        _masuk(client)
        uid, kredensial, catatan = _tambah_data(client)

        grant = _grant(client, "settings.change")
        csrf = _csrf_meta(client, "/settings")
        resp = client.post("/settings/change-password", data={
            "csrf_token": csrf,
            "reauth_grant": grant,
            "current_password": KATA_SANDI,
            "new_password": KATA_SANDI_BARU,
            "confirm_password": KATA_SANDI_BARU,
        })
        assert resp.status_code == 302

        hasil = verifikasi_tahap_satu(USERNAME, KATA_SANDI_BARU)
        assert hasil["success"], hasil
        dek = hasil["dek"]
        kunci = purpose_key(dek, "database")

        kredensial_plain = decrypt_record(
            {
                "site_name_enc": kredensial["site_name_enc"],
                "username_enc": kredensial["username_enc"],
                "password_enc": kredensial["password_enc"],
                "url_enc": kredensial["url_enc"],
                "notes_enc": kredensial["notes_enc"],
            },
            kunci, uid, "account_vault",
        )
        assert kredensial_plain["site_name_enc"] == SITUS
        assert kredensial_plain["username_enc"] == SITUS_PENGGUNA
        assert kredensial_plain["password_enc"] == SITUS_SANDI

        catatan_plain = decrypt_record(
            {
                "title_enc": catatan["title_enc"],
                "content_enc": catatan["content_enc"],
            },
            kunci, uid, "secure_notes",
        )
        assert catatan_plain["title_enc"] == JUDUL_CATATAN
        assert super_decrypt(
            catatan_plain["content_enc"], master_key=dek
        ) == ISI_CATATAN

        # Kata sandi lama tidak berlaku lagi setelah pembungkusan ulang.
        assert verifikasi_tahap_satu(USERNAME, KATA_SANDI)["success"] is False
