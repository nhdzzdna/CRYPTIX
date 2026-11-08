"""
tests/test_assistant_routes.py
──────────────────────────────
Uji Sesi K butir 4.9: riwayat Security Assistant disimpan di sisi server
(bukan cookie), kolom password terpisah tidak pernah masuk riwayat/log/rantai,
dan laporan status memakai skema baru (dongle, WebAuthn/wajah, jangkar rantai).
"""

import os
import re

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.assistant import history as chat_history
from modules.authentication.auth import register_user
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys

PASSWORD = "KataSandi-Assistant-2026!"
PENANDA = "[password diperiksa]"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "assistant.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    monkeypatch.setattr(bc, "_verifikasi_terakhir", {})
    chat_history.clear_all()
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
    session_keys.put(sid, b"\x7c" * 32)
    return client


def _csrf(client) -> str:
    body = client.get("/assistant").get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


def _kirim(client, token: str, payload: dict):
    return client.post(
        "/assistant/chat",
        json=payload,
        headers={"X-CSRFToken": token},
    )


def _isi_cookie(app, client) -> dict:
    kue = client.get_cookie("session")
    return app.session_interface.get_signing_serializer(app).loads(kue.value)


def test_riwayat_disimpan_di_server_bukan_cookie(app):
    user = _pengguna("pemilik_asisten", "asisten@contoh.test")
    client = _client(app, user, "pemilik_asisten")
    token = _csrf(client)

    pesan = "TOKEN-UNIK-RIWAYAT-123"
    assert _kirim(client, token, {"message": pesan}).status_code == 200

    isi = _isi_cookie(app, client)
    assert "chat_history" not in isi
    assert pesan not in str(isi)

    riwayat = chat_history.get(isi["session_id"])
    assert [e["role"] for e in riwayat] == ["user", "agent"]
    assert riwayat[0]["content"] == pesan

    html = client.get("/assistant").get_data(as_text=True)
    assert pesan in html


def test_password_tidak_masuk_riwayat_atau_cookie(app):
    user = _pengguna("pemilik_sandi", "sandi@contoh.test")
    client = _client(app, user, "pemilik_sandi")
    token = _csrf(client)

    rahasia = "Rahasia-Sekali-99!XYZ"
    resp = _kirim(client, token, {"password": rahasia})
    assert resp.status_code == 200
    assert rahasia not in resp.get_data(as_text=True)

    isi = _isi_cookie(app, client)
    assert "chat_history" not in isi
    assert rahasia not in str(isi)

    riwayat = chat_history.get(isi["session_id"])
    assert len(riwayat) == 2
    assert riwayat[0]["content"] == PENANDA
    assert all(rahasia not in e["content"] for e in riwayat)

    html = client.get("/assistant").get_data(as_text=True)
    assert PENANDA in html
    assert rahasia not in html

    with get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM blockchain_log").fetchone()[0] == 0


def test_password_lewat_pesan_teks_tetap_disamarkan(app):
    user = _pengguna("pemilik_pesan", "pesan@contoh.test")
    client = _client(app, user, "pemilik_pesan")
    token = _csrf(client)

    rahasia = "Sandi-Dalam-Pesan-77!"
    resp = _kirim(client, token, {"message": f"cek password: {rahasia}"})
    assert resp.status_code == 200
    assert resp.get_json()["intent"] == "password_check"

    with client.session_transaction() as sess:
        riwayat = chat_history.get(sess["session_id"])
    assert riwayat[0]["content"] == PENANDA
    assert all(rahasia not in e["content"] for e in riwayat)


def test_bersihkan_riwayat_server(app):
    user = _pengguna("pemilik_bersih", "bersih@contoh.test")
    client = _client(app, user, "pemilik_bersih")
    token = _csrf(client)
    unik = "TOKEN-HAPUS-RIWAYAT"

    _kirim(client, token, {"message": unik})
    resp = client.post("/assistant/clear", headers={"X-CSRFToken": token})
    assert resp.status_code == 200

    with client.session_transaction() as sess:
        assert chat_history.get(sess["session_id"]) == []
    assert unik not in client.get("/assistant").get_data(as_text=True)


def test_status_memakai_skema_baru(app):
    user = _pengguna("pemilik_status", "status@contoh.test")
    client = _client(app, user, "pemilik_status")
    token = _csrf(client)

    with get_db() as db:
        db.execute(
            "INSERT INTO webauthn_credentials "
            "(user_id, credential_id, public_key, sign_count, nama) "
            "VALUES (?,?,?,?,?)",
            (user, "kredensial-uji", "kunci-publik", 0, "Laptop"),
        )
        db.execute(
            "INSERT INTO biometric_templates (user_id, metode, template, sampel) "
            "VALUES (?,?,?,?)",
            (user, "wajah", b"template-terenkripsi", 30),
        )
        db.commit()
    bc.add_block(user, "LOGIN", "auth:login", "f" * 64)

    resp = _kirim(client, token, {"message": "Bagaimana status keamanan akun saya?"})
    assert resp.status_code == 200
    jawaban = resp.get_json()["answer"]

    assert "Dongle/USB Token" in jawaban
    assert "**WebAuthn**: 1 kredensial" in jawaban
    assert "**Wajah**: ✅ terdaftar" in jawaban
    assert "Jangkar kepala" in jawaban
    assert "Fingerprint" not in jawaban


def test_riwayat_modul_terisolasi_per_sesi():
    chat_history.clear_all()
    chat_history.append("sesi-a", [{"role": "user", "content": "A", "intent": None}])
    chat_history.append("sesi-b", [{"role": "user", "content": "B", "intent": None}])

    assert [e["content"] for e in chat_history.get("sesi-a")] == ["A"]
    assert [e["content"] for e in chat_history.get("sesi-b")] == ["B"]

    chat_history.clear("sesi-a")
    assert chat_history.get("sesi-a") == []
    assert [e["content"] for e in chat_history.get("sesi-b")] == ["B"]
