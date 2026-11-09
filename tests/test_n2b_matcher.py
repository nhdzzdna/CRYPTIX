"""
tests/test_n2b_matcher.py
─────────────────────────
Uji pencocokan pertanyaan Security Assistant, saran topik, integrasi endpoint,
dan keamanan riwayat.
"""

import os
import re
from pathlib import Path

import pytest

import config
from app import create_app
from database.db import init_db
from modules.assistant import history as chat_history
from modules.assistant import matcher
from modules.assistant.matcher import cari_topik, normalisasi
from modules.authentication.auth import register_user
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys

PENANDA = "[password diperiksa]"
PASSWORD = "KataSandi-Matcher-2026!"

# Daftar topik palsu yang mengikuti kontrak knowledge.py.
TOPIK_PALSU = [
    {
        "id": "wajah",
        "judul": "Pendaftaran Wajah",
        "kata_kunci": ["wajah", "biometrik"],
        "sinonim": ["daftar wajah", "mendaftarkan wajah"],
        "jawaban": "Panduan mendaftarkan wajah.",
    },
    {
        "id": "pemulihan",
        "judul": "Panduan Pemulihan",
        "kata_kunci": ["pemulihan", "kunci cadangan"],
        "sinonim": ["kunci pemulihan"],
        "jawaban": "Panduan kunci pemulihan.",
    },
    {
        "id": "dongle",
        "judul": "Dongle USB",
        "kata_kunci": ["dongle", "usb token"],
        "sinonim": ["token usb"],
        "jawaban": "Panduan dongle USB.",
    },
    {
        "id": "vault",
        "judul": "My Vault",
        "kata_kunci": ["vault"],
        "sinonim": ["penyimpanan file"],
        "jawaban": "Panduan My Vault.",
    },
]


# ── 1. Normalisasi dan pencocokan ──────────────────────────────────────────

class TestNormalisasi:
    def test_huruf_kecil_tanda_baca_dan_kata_hubung(self):
        hasil = normalisasi("  Apa, YANG  ini?! Saya bisa ke Vault... ")
        assert hasil == "apa vault"

    def test_teks_kosong_dan_none(self):
        assert normalisasi("") == ""
        assert normalisasi(None) == ""

    def test_panjang_masukan_dibatasi(self):
        teks = "kata " * 200
        hasil = normalisasi(teks)
        assert len(hasil) <= 500
        assert len(hasil) < len(teks)


class TestCariTopik:
    def test_frasa_sinonim_memilih_topik_tepat(self):
        hasil = cari_topik("Bagaimana cara mendaftarkan wajah saya?", TOPIK_PALSU)
        assert hasil["cocok"] is not None
        assert hasil["cocok"]["id"] == "wajah"
        assert hasil["skor"] >= 0.4

    def test_kata_kunci_memilih_topik_tepat(self):
        hasil = cari_topik("Apakah dongle saya aktif?", TOPIK_PALSU)
        assert hasil["cocok"] is not None
        assert hasil["cocok"]["id"] == "dongle"

    def test_judul_utuh_dapat_dipilih(self):
        topik = [{
            "id": "khusus",
            "judul": "Panduan Khusus",
            "kata_kunci": [],
            "sinonim": [],
            "jawaban": "Jawaban khusus.",
        }]
        hasil = cari_topik("Panduan Khusus", topik)
        assert hasil["cocok"] is not None
        assert hasil["cocok"]["id"] == "khusus"

    def test_toleransi_salah_ketik(self):
        hasil = cari_topik("pemuliham", TOPIK_PALSU)
        assert hasil["cocok"] is not None
        assert hasil["cocok"]["id"] == "pemulihan"

    def test_di_bawah_ambang_tidak_cocok_dan_memberi_saran(self):
        hasil = cari_topik("Apa resep nasi goreng?", TOPIK_PALSU)
        assert hasil["cocok"] is None
        assert hasil["skor"] < 0.4
        assert len(hasil["saran"]) == 3
        assert set(hasil["saran"][0]) == {"id", "judul"}

    def test_batas_saran_dihormati(self):
        assert len(cari_topik("xyz", TOPIK_PALSU, batas=2)["saran"]) == 2
        assert cari_topik("xyz", TOPIK_PALSU, batas=0)["saran"] == []

    def test_masukan_panjang_tidak_error(self):
        hasil = cari_topik("wajah " * 300, TOPIK_PALSU)
        assert set(hasil) == {"cocok", "skor", "saran"}

    def test_knowledge_tidak_tersedia_mengembalikan_kosong(self, monkeypatch):
        monkeypatch.setattr(matcher, "muat_topik", lambda: [])
        hasil = cari_topik("pertanyaan apa pun")
        assert hasil["cocok"] is None
        assert hasil["saran"] == []


# ── 2. Integrasi endpoint ──────────────────────────────────────────────────

@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "n2b.db"))
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


def test_endpoint_menjawab_topik_cocok(app, monkeypatch):
    monkeypatch.setattr(matcher, "muat_topik", lambda: TOPIK_PALSU)
    user = _pengguna("pemilik_topik", "topik@contoh.test")
    client = _client(app, user, "pemilik_topik")
    token = _csrf(client)

    resp = _kirim(client, token, {
        "message": "Bagaimana cara mendaftarkan wajah?",
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["intent"] == "topik"
    assert data["answer"] == TOPIK_PALSU[0]["jawaban"]


def test_endpoint_memberi_saran_saat_tidak_cocok(app, monkeypatch):
    monkeypatch.setattr(matcher, "muat_topik", lambda: TOPIK_PALSU)
    user = _pengguna("pemilik_saran", "saran@contoh.test")
    client = _client(app, user, "pemilik_saran")
    token = _csrf(client)

    resp = _kirim(client, token, {"message": "Apa resep nasi goreng?"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["intent"] == "fallback"
    assert "Saya belum punya jawaban untuk itu" in data["answer"]
    assert len(data["saran"]) == 3
    assert all(set(item) == {"id", "judul"} for item in data["saran"])


def test_halaman_merender_tombol_saran_dari_topik(app, monkeypatch):
    monkeypatch.setattr(matcher, "muat_topik", lambda: TOPIK_PALSU)
    user = _pengguna("pemilik_tombol", "tombol@contoh.test")
    client = _client(app, user, "pemilik_tombol")

    html = client.get("/assistant").get_data(as_text=True)
    assert 'data-pertanyaan="Pendaftaran Wajah"' in html
    assert 'data-pertanyaan="Dongle USB"' in html
    assert html.count("data-pertanyaan=") == 4


def test_halaman_tanpa_tombol_bila_topik_kosong(app, monkeypatch):
    monkeypatch.setattr(matcher, "muat_topik", lambda: [])
    user = _pengguna("pemilik_kosong", "kosong@contoh.test")
    client = _client(app, user, "pemilik_kosong")

    html = client.get("/assistant").get_data(as_text=True)
    assert "data-pertanyaan=" not in html


def test_password_tidak_masuk_riwayat(app, monkeypatch):
    monkeypatch.setattr(matcher, "muat_topik", lambda: TOPIK_PALSU)
    user = _pengguna("pemilik_rahasia", "rahasia@contoh.test")
    client = _client(app, user, "pemilik_rahasia")
    token = _csrf(client)

    rahasia = "Rahasia-Matcher-99!XYZ"
    resp = _kirim(client, token, {"password": rahasia})
    assert resp.status_code == 200
    assert rahasia not in resp.get_data(as_text=True)

    with client.session_transaction() as sess:
        riwayat = chat_history.get(sess["session_id"])
    assert riwayat[0]["content"] == PENANDA
    assert all(rahasia not in entri["content"] for entri in riwayat)


def test_halaman_tanpa_javascript_inline(app, monkeypatch):
    monkeypatch.setattr(matcher, "muat_topik", lambda: TOPIK_PALSU)
    user = _pengguna("pemilik_csp", "csp@contoh.test")
    client = _client(app, user, "pemilik_csp")
    html = client.get("/assistant").get_data(as_text=True)

    assert not re.search(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", html, re.I)
    assert not re.search(r"\son[a-z]+\s*=", html, re.I)
    assert not re.search(r"javascript:", html, re.I)


# ── 3. Integrasi knowledge.py asli (dilewati bila belum tersedia) ───────────

def test_integrasi_knowledge_asli():
    knowledge = pytest.importorskip("modules.assistant.knowledge")
    topik = getattr(knowledge, "TOPIK", [])
    if not topik:
        pytest.skip("TOPIK masih kosong")

    kasus = [
        ("Bagaimana cara mendaftarkan wajah?", ("wajah", "face")),
        ("Di mana saya bisa melihat kunci pemulihan?", ("pemulihan", "recovery")),
        ("Apa itu dongle?", ("dongle", "usb")),
    ]

    for pertanyaan, akar in kasus:
        hasil = cari_topik(pertanyaan, topik=topik)
        assert hasil["cocok"] is not None, pertanyaan
        teks = " ".join([
            str(hasil["cocok"].get("id", "")),
            str(hasil["cocok"].get("judul", "")),
            " ".join(map(str, hasil["cocok"].get("kata_kunci", []))),
            " ".join(map(str, hasil["cocok"].get("sinonim", []))),
        ]).lower()
        assert any(kata in teks for kata in akar), (pertanyaan, teks)


# ── 4. Template tidak memakai JavaScript inline ─────────────────────────────

def test_template_assistant_tanpa_javascript_inline():
    root = Path(__file__).resolve().parent.parent
    teks = (root / "templates" / "assistant.html").read_text(encoding="utf-8")
    assert not re.search(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", teks, re.I)
    assert not re.search(r"\son[a-z]+\s*=", teks, re.I)
    assert not re.search(r"javascript:", teks, re.I)
