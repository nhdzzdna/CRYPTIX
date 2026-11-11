"""
tests/test_uc1_dongle.py
────────────────────────
Uji sesi UC1 Bagian 3: daftar ulang dongle berulang, penggantian dongle,
dan pemilihan drive eksplisit. Skenario awal dijalankan lebih dahulu untuk
mereproduksi gejala sebelum perbaikan diterapkan.
"""

import os
import sqlite3

import pytest

import config
from database.db import get_db, init_db
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import (
    create_account, reregister_usb_token, verifikasi_tahap_satu,
)
from modules.blockchain import blockchain as bc
from modules.strings import MSG

KATA_SANDI = "Rahasia-Dongle-2026!"
USERNAME = "pengguna_dongle"
EMAIL = "dongle@contoh.test"


class _Konteks:
    pass


@pytest.fixture()
def dongle(tmp_path, monkeypatch):
    """Siapkan dua folder dongle simulasi A dan B serta akun dengan dongle A."""
    dongle_a = tmp_path / "dongle_a"
    dongle_b = tmp_path / "dongle_b"
    dongle_a.mkdir()
    dongle_b.mkdir()
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "dongle.db"))
    monkeypatch.setattr(config, "STORAGE_ROOT", str(tmp_path / "storage"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(dongle_a))
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    monkeypatch.setattr(usb_mod, "_get_removable_drives", lambda: [])

    kandidat = [str(dongle_a), str(dongle_b)]
    monkeypatch.setattr(usb_mod, "_kandidat_drive", lambda: list(kandidat))

    init_db()
    token = usb_mod.register_usb_token(str(dongle_a))
    assert token is not None
    hasil = create_account(USERNAME, EMAIL, KATA_SANDI, token)
    assert hasil["success"], hasil
    usb_mod.lupakan_cache()

    ctx = _Konteks()
    ctx.a = str(dongle_a)
    ctx.b = str(dongle_b)
    ctx.token_a = token
    ctx.kandidat = kandidat
    ctx.monkeypatch = monkeypatch
    ctx.tmp_path = tmp_path
    return ctx


def _pasang_kandidat(ctx, daftar):
    ctx.kandidat[:] = daftar
    usb_mod.lupakan_cache()


def _baris() -> dict:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE username=?", (USERNAME,)
        ).fetchone()
    assert row is not None
    return dict(row)


def _login() -> dict:
    return verifikasi_tahap_satu(USERNAME, KATA_SANDI)


def _berkas_token(path: str) -> bytes:
    with open(os.path.join(path, config.USB_TOKEN_FILENAME), "rb") as handle:
        return handle.read()


class TestReproduksi:
    def test_daftar_ulang_dongle_sama_lalu_login(self, dongle):
        assert _login()["success"] is True
        hasil = reregister_usb_token(
            _baris()["id"], _login()["dek"], KATA_SANDI, dongle.a
        )
        assert hasil["success"] is True, hasil
        usb_mod.lupakan_cache()
        assert _login()["success"] is True

    def test_daftar_ulang_dongle_baru_lalu_login_hanya_b(self, dongle):
        dek = _login()["dek"]
        assert reregister_usb_token(
            _baris()["id"], dek, KATA_SANDI, dongle.b
        )["success"]

        _pasang_kandidat(dongle, [dongle.b])
        assert _login()["success"] is True

        _pasang_kandidat(dongle, [dongle.a])
        assert _login()["success"] is False

    def test_mountpoint_kosong_dua_kandidat_tidak_memilih_diam_diam(self, dongle):
        sebelum = _baris()
        berkas_a = _berkas_token(dongle.a)

        hasil = reregister_usb_token(
            sebelum["id"], _login()["dek"], KATA_SANDI, ""
        )

        assert hasil["success"] is False
        assert hasil["error"] == MSG.SETTINGS_USB_CHOOSE_DRIVE
        assert _baris() == sebelum
        assert _berkas_token(dongle.a) == berkas_a

    def test_gagal_bungkus_ulang_tidak_merusak_dongle_lama(
        self, dongle, monkeypatch
    ):
        from modules.authentication import auth as auth_mod

        sebelum = _baris()
        berkas_a = _berkas_token(dongle.a)

        def _gagal(*_args, **_kwargs):
            raise ValueError("injeksi kegagalan")

        monkeypatch.setattr(auth_mod, "rewrap_dek", _gagal)
        hasil = reregister_usb_token(
            sebelum["id"], _login()["dek"], KATA_SANDI, dongle.a
        )

        assert hasil["success"] is False
        assert _baris() == sebelum
        assert _berkas_token(dongle.a) == berkas_a
        usb_mod.lupakan_cache()
        assert _login()["success"] is True

    def test_mountpoint_kosong_satu_kandidat_dipakai(self, dongle):
        dek = _login()["dek"]
        _pasang_kandidat(dongle, [dongle.b])
        hasil = reregister_usb_token(
            _baris()["id"], dek, KATA_SANDI, ""
        )
        assert hasil["success"] is True, hasil

        _pasang_kandidat(dongle, [dongle.b])
        assert _login()["success"] is True
        _pasang_kandidat(dongle, [dongle.a])
        assert _login()["success"] is False

    def test_mountpoint_bukan_kandidat_ditolak(self, dongle):
        sebelum = _baris()
        berkas_a = _berkas_token(dongle.a)
        hasil = reregister_usb_token(
            sebelum["id"], _login()["dek"], KATA_SANDI,
            os.path.join(dongle.tmp_path, "bukan_dongle"),
        )
        assert hasil["success"] is False
        assert hasil["error"] == MSG.SETTINGS_USB_INVALID_DRIVE
        assert _baris() == sebelum
        assert _berkas_token(dongle.a) == berkas_a

    def test_gagal_tulis_token_tidak_mengubah_apa_pun(self, dongle, monkeypatch):
        sebelum = _baris()
        berkas_a = _berkas_token(dongle.a)
        monkeypatch.setattr(usb_mod, "tulis_token", lambda *_a, **_k: False)

        hasil = reregister_usb_token(
            sebelum["id"], _login()["dek"], KATA_SANDI, dongle.a
        )

        assert hasil["success"] is False
        assert hasil["error"] == MSG.SETTINGS_USB_WRITE_FAILED
        assert _baris() == sebelum
        assert _berkas_token(dongle.a) == berkas_a
        usb_mod.lupakan_cache()
        assert _login()["success"] is True

    def test_gagal_simpan_db_memulihkan_berkas_lama(self, dongle, monkeypatch):
        from database import db as db_mod
        from modules.authentication import auth as auth_mod

        sebelum = _baris()
        berkas_a = _berkas_token(dongle.a)
        dek = _login()["dek"]
        get_db_asli = db_mod.get_db
        hitung = {"n": 0}

        def _get_db_gagal():
            hitung["n"] += 1
            if hitung["n"] == 2:
                raise sqlite3.OperationalError("injeksi kegagalan")
            return get_db_asli()

        monkeypatch.setattr(auth_mod, "get_db", _get_db_gagal)
        hasil = reregister_usb_token(
            sebelum["id"], dek, KATA_SANDI, dongle.a
        )

        assert hasil["success"] is False
        assert hasil["error"] == MSG.SETTINGS_USB_WRITE_FAILED
        assert _baris() == sebelum
        assert _berkas_token(dongle.a) == berkas_a

    def test_dua_dongle_tercolok_login_memakai_token_b(self, dongle):
        dek = _login()["dek"]
        assert reregister_usb_token(
            _baris()["id"], dek, KATA_SANDI, dongle.b
        )["success"]

        _pasang_kandidat(dongle, [dongle.a, dongle.b])
        assert _login()["success"] is True

    def test_daftar_ulang_berurutan_sama_lalu_baru(self, dongle):
        dek = _login()["dek"]
        assert reregister_usb_token(
            _baris()["id"], dek, KATA_SANDI, dongle.a
        )["success"]
        usb_mod.lupakan_cache()
        assert _login()["success"] is True

        dek = _login()["dek"]
        assert reregister_usb_token(
            _baris()["id"], dek, KATA_SANDI, dongle.b
        )["success"]

        _pasang_kandidat(dongle, [dongle.b])
        assert _login()["success"] is True
        _pasang_kandidat(dongle, [dongle.a])
        assert _login()["success"] is False
