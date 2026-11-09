"""
tests/test_headers_csp.py
─────────────────────────
Uji header keamanan, CSP, dan ketiadaan JavaScript inline pada template.
"""

import os
import re
from pathlib import Path

import pytest

import config
from app import create_app
from database.db import init_db
from modules.blockchain import blockchain as bc

CSP = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; media-src 'self'; connect-src 'self'; "
    "frame-ancestors 'none'"
)

SUMBER_FONT_DIIZINKAN = (
    "https://fonts.googleapis.com/",
    "https://fonts.gstatic.com/",
)

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
STATIC_JS = ROOT / "static" / "js"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "headers.db"))
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


def _periksa_header(header):
    assert header.get("Cache-Control") and "no-store" in header["Cache-Control"]
    assert header.get("Pragma") == "no-cache"
    assert header.get("X-Content-Type-Options") == "nosniff"
    assert header.get("X-Frame-Options") == "DENY"
    assert header.get("Referrer-Policy") == "no-referrer"
    assert header.get("Content-Security-Policy") == CSP


def test_header_pada_html_json_dan_404(app):
    client = app.test_client()

    halaman = client.get("/login")
    assert halaman.status_code == 200
    _periksa_header(halaman.headers)

    json_resp = client.get("/api/usb_drives")
    assert json_resp.status_code == 200
    assert json_resp.is_json
    _periksa_header(json_resp.headers)

    tidak_ada = client.get("/halaman-tidak-ada")
    assert tidak_ada.status_code == 404
    assert tidak_ada.content_type.startswith("text/html")
    _periksa_header(tidak_ada.headers)

    json_404 = client.get("/api/halaman-tidak-ada")
    assert json_404.status_code == 404
    assert json_404.is_json
    _periksa_header(json_404.headers)


def test_static_tidak_disimpan_no_store(app):
    client = app.test_client()
    resp = client.get("/static/js/reauth.js")
    assert resp.status_code == 200
    assert "no-store" not in resp.headers.get("Cache-Control", "")


def _berkas_template():
    return sorted(TEMPLATES.rglob("*.html"))


def test_tidak_ada_javascript_inline():
    pola_script = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", re.IGNORECASE)
    pola_handler = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
    pola_javascript = re.compile(r"javascript:", re.IGNORECASE)

    for berkas in _berkas_template():
        teks = berkas.read_text(encoding="utf-8")
        assert not pola_script.search(teks), f"script inline di {berkas}"
        assert not pola_handler.search(teks), f"handler inline di {berkas}"
        assert not pola_javascript.search(teks), f"URL javascript: di {berkas}"


def test_tidak_ada_sumber_luar():
    pola = re.compile(r"https?://", re.IGNORECASE)
    for berkas in sorted(STATIC_JS.rglob("*.js")):
        teks = berkas.read_text(encoding="utf-8")
        assert not pola.search(teks), f"sumber luar di {berkas}"

    pola_url = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
    for berkas in _berkas_template():
        teks = berkas.read_text(encoding="utf-8")
        for url in pola_url.findall(teks):
            assert url.startswith(SUMBER_FONT_DIIZINKAN), (
                f"sumber luar di {berkas}: {url}"
            )
