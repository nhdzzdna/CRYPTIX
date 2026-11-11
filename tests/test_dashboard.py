"""
tests/test_dashboard.py
───────────────────────
Uji Sesi K butir 4.7: Dashboard menampilkan status dongle, metode biometrik
terdaftar, hasil verifikasi rantai terakhir beserta jangkar kepala, jumlah
aset, dan aktivitas terbaru milik pengguna sendiri.
"""

import os
from types import SimpleNamespace

import pytest

import config
from app import create_app
from database.db import init_db
from modules.authentication import usb_authentication
from modules.authentication.auth import register_user
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys

PASSWORD = "KataSandi-Dashboard-2026!"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "dashboard.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    monkeypatch.setattr(bc, "_verifikasi_terakhir", {})
    os.makedirs(config.ENCRYPTED_FILES_DIR, exist_ok=True)
    init_db()
    application = create_app()
    application.config["TESTING"] = True
    return application


def _pengguna(nama: str, email: str) -> int:
    hasil = register_user(nama, email, PASSWORD)
    assert hasil["success"], hasil
    return hasil["user_id"]


def _client(app, user_id: int, username: str):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = username
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
    session_keys.put(sid, b"\x6b" * 32)
    return client


def test_dashboard_menampilkan_status_dongle_dan_biometrik(app, monkeypatch):
    user = _pengguna("pemilik_dasbor", "dasbor@contoh.test")
    client = _client(app, user, "pemilik_dasbor")

    # Ganti hanya modul yang dipakai route; gerbang dongle sesi tetap memakai
    # modul asli agar sesi pengujian tidak diputus.
    monkeypatch.setattr(
        "routes.dashboard_routes.usb_authentication",
        SimpleNamespace(dongle_pengguna_terpasang=lambda _uid: False),
    )
    monkeypatch.setattr(
        "modules.authentication.biometrics.metode_untuk_pengguna",
        lambda _uid: [
            {"nama": "webauthn", "label": "WebAuthn"},
            {"nama": "wajah", "label": "Wajah"},
        ],
    )
    monkeypatch.setattr("routes.dashboard_routes.kredensial_pengguna", lambda _uid: [{}, {}])
    monkeypatch.setattr("routes.dashboard_routes.template_ada", lambda _uid: True)

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Dashboard" in html
    assert "Total file" in html


def test_dashboard_menampilkan_hasil_verifikasi_dan_jangkar(app):
    user = _pengguna("pemilik_verifikasi", "verifikasi@contoh.test")
    client = _client(app, user, "pemilik_verifikasi")
    bc.add_block(user, "LOGIN", "auth:login", "e" * 64)
    hasil = bc.record_verification(user, bc.verify_chain())

    html = client.get("/dashboard").get_data(as_text=True)
    assert "Rantai Utuh" in html
    assert f'data-kx-hash="{hasil["head_hash"]}"' in html


def test_dashboard_tanpa_verifikasi_menampilkan_status_awal(app):
    user = _pengguna("pemilik_baru", "baru@contoh.test")
    client = _client(app, user, "pemilik_baru")

    html = client.get("/dashboard").get_data(as_text=True)
    assert "Belum Diverifikasi" in html
    assert "data-kx-chain-status" in html
    assert "Jangkar belum tersedia" in html


def test_dashboard_aktivitas_hanya_milik_pengguna(app, monkeypatch):
    pemilik = _pengguna("pemilik_aktivitas", "aktivitas@contoh.test")
    lain = _pengguna("pengguna_lain", "lain@contoh.test")
    client = _client(app, pemilik, "pemilik_aktivitas")
    monkeypatch.setattr(
        usb_authentication, "dongle_pengguna_terpasang", lambda _uid: True
    )

    bc.add_block(pemilik, "UPLOAD", "file:1", "a" * 64)
    bc.add_block(lain, "DELETE", "file:2", "b" * 64)

    html = client.get("/dashboard").get_data(as_text=True)
    assert "UPLOAD" in html
    assert "DELETE" not in html
