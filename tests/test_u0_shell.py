"""
tests/test_u0_shell.py
──────────────────────
Uji fondasi antarmuka U0: kerangka tanpa skrip inline, toast dari flash,
navigasi yang melewati endpoint belum tersedia, rute audio, dan penghapusan
Security Assistant.
"""

import os
import re

import pytest

import config
from app import create_app
from database.db import init_db
from modules.authentication.auth import register_user
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys

PASSWORD = "KataSandi-Fondasi-2026!"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "u0.db"))
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


@pytest.fixture()
def client(app):
    hasil = register_user("pemilik_u0", "u0@contoh.test", PASSWORD)
    assert hasil["success"], hasil
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = hasil["user_id"]
        sess["username"] = "pemilik_u0"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
    session_keys.put(sid, b"\x21" * 32)
    return client


def test_security_assistant_benar_benar_hilang(client):
    assert client.get("/assistant").status_code == 404
    assert client.get("/assistant/chat").status_code == 404
    assert client.get("/assistant/clear").status_code == 404


def test_rute_musik_lama_diarahkan_ke_audio(client):
    resp = client.get("/musik")
    assert resp.status_code == 308
    assert resp.headers["Location"].endswith("/audio")


def test_kerangka_tanpa_skrip_inline(client):
    html = client.get("/dashboard").get_data(as_text=True)
    inline = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html, flags=re.I)
    assert inline == []
    assert "KOSYAK" in html


def test_flash_dirender_sebagai_data_pesan(client):
    with client.session_transaction() as sess:
        sess["_flashes"] = [("success", "Pesan uji toast")]
    html = client.get("/dashboard").get_data(as_text=True)
    assert 'id="kx-flash"' in html
    assert "data-pesan=" in html
    assert "Pesan uji toast" in html


def test_rename_tampilan_kosyak(app):
    html = app.test_client().get("/login").get_data(as_text=True)
    assert "KOSYAK" in html
    assert "CRYPTIX" not in html


def test_menu_audio_memakai_label_audio(client):
    html = client.get("/dashboard").get_data(as_text=True)
    assert ">Audio<" in html
    assert ">Musik<" not in html


def test_nav_melewati_endpoint_yang_belum_ada(app):
    from modules.navigation import daftar_nav

    with app.app_context():
        label = [item["label"] for grup in daftar_nav() for item in grup["items"]]
        assert "Sampah" not in label
        simpan = app.view_functions.pop("settings.index")
        try:
            label = [item["label"] for grup in daftar_nav() for item in grup["items"]]
            assert "Settings" not in label
        finally:
            app.view_functions["settings.index"] = simpan
