"""
tests/test_vigenere_classic.py
──────────────────────────────
Uji alat Vigenere mandiri: kunci hanya huruf A-Z, huruf besar/kecil
dipertahankan, karakter bukan huruf tidak memajukan indeks kunci, dan
penolakan kunci tidak valid di rute Crypto Tools.
"""

import html
import re
from pathlib import Path

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.cryptography import session_keys
from modules.cryptography.classical_cipher_1 import (
    is_valid_vigenere_key,
    vigenere_letter_decrypt,
    vigenere_letter_encrypt,
)
from modules.strings import MSG


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "vigenere_uji.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    init_db()
    with get_db() as db:
        db.execute(
            """INSERT INTO users
               (id, username, email, password_hash, salt) VALUES (?,?,?,?,?)""",
            (1, "pengujian", "pengujian@contoh.test", "hash", "garam"),
        )
        db.commit()

    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "pengujian"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, b"\x5a" * 32)
    return c


def _csrf_token(client) -> str:
    page = client.get("/crypto-tools")
    assert page.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True))
    assert match, "token CSRF tidak ditemukan pada form"
    return match.group(1)


def _post(client, **fields):
    fields.setdefault("csrf_token", _csrf_token(client))
    return client.post("/crypto-tools", data=fields)


def _first_output(html_text: str):
    match = re.search(r'<pre class="kx-code[^"]*"[^>]*>(.*?)</pre>', html_text, re.S)
    return html.unescape(match.group(1)) if match else None


class TestVigenereClassicCipher:
    def test_numeric_key_rejected(self):
        assert not is_valid_vigenere_key("kunci1")
        with pytest.raises(ValueError):
            vigenere_letter_encrypt("Halo", "kunci1")
        with pytest.raises(ValueError):
            vigenere_letter_decrypt("Halo", "kunci1")

    def test_empty_and_symbol_key_rejected(self):
        for key in ("", " ", "kunci rahasia", "kunci-!", "kuncié"):
            assert not is_valid_vigenere_key(key)

    def test_mixed_case_key_same_as_upper(self):
        assert (
            vigenere_letter_encrypt("Hello World", "SeCrEt")
            == vigenere_letter_encrypt("Hello World", "SECRET")
        )

    def test_case_preserved(self):
        assert vigenere_letter_encrypt("aB", "B") == "bC"

    def test_nonletters_unchanged_and_do_not_advance_key(self):
        # Kunci "BC": huruf pertama memakai B, spasi tidak memajukan indeks,
        # sehingga huruf kedua memakai C.
        assert vigenere_letter_encrypt("A A", "BC") == "B C"
        assert vigenere_letter_encrypt("A-1! A", "BC") == "B-1! C"

    def test_roundtrip_with_spaces_punctuation_and_numbers(self):
        pesan = "Halo, Dunia! 2026. Uji Vigenere klasik."
        sandi = vigenere_letter_encrypt(pesan, "KunciRahasia")
        assert sandi != pesan
        assert vigenere_letter_decrypt(sandi, "KunciRahasia") == pesan


class TestVigenereClassicRoute:
    def test_numeric_key_returns_json_400(self, client):
        page = client.post(
            "/crypto-tools",
            data={
                "csrf_token": _csrf_token(client),
                "cipher": "vigenere",
                "action": "encrypt",
                "text": "Halo",
                "key": "kunci1",
            },
            headers={"Accept": "application/json"},
        )
        assert page.status_code == 400
        assert page.get_json()["error"] == MSG.CRYPTO_VIGENERE_KEY_INVALID

    def test_symbol_key_returns_html_400(self, client):
        page = _post(
            client, cipher="vigenere", action="encrypt",
            text="Halo", key="kunci rahasia",
        )
        body = page.get_data(as_text=True)
        assert page.status_code == 400
        assert MSG.CRYPTO_VIGENERE_KEY_INVALID in body
        assert "kx-infobox-danger" in body

    def test_empty_key_returns_html_400(self, client):
        page = _post(
            client, cipher="vigenere", action="encrypt",
            text="Halo", key="",
        )
        assert page.status_code == 400
        assert MSG.CRYPTO_VIGENERE_KEY_INVALID in page.get_data(as_text=True)

    def test_mixed_case_key_encrypts(self, client):
        page = _post(
            client, cipher="vigenere", action="encrypt",
            text="Halo Dunia", key="SeCrEt",
        )
        body = page.get_data(as_text=True)
        assert page.status_code == 200
        assert "kx-infobox-danger" not in body
        assert _first_output(body)

    def test_route_roundtrip(self, client):
        pesan = "Halo, Dunia! 2026."
        enc = _post(
            client, cipher="vigenere", action="encrypt",
            text=pesan, key="KunciRahasia",
        )
        sandi = _first_output(enc.get_data(as_text=True))
        assert sandi
        dec = _post(
            client, cipher="vigenere", action="decrypt",
            text=sandi, key="KunciRahasia",
        )
        assert pesan in dec.get_data(as_text=True)


def test_js_filters_nonletter_vigenere_key():
    js = (Path(__file__).resolve().parents[1] / "static" / "js" / "crypto_tools.js").read_text(
        encoding="utf-8"
    )
    assert "replace(/[^A-Za-z]/g" in js
