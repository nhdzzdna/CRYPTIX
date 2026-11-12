"""
tests/test_crypto_routes.py
────────────────────────────
Uji rute Crypto Tools: form ber-CSRF, kunci teks ChaCha20/Blowfish,
tahapan Super Encryption, dan ketiadaan keluaran di cookie.
"""

import html
import re

import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.cryptography import session_keys

PASSPHRASE = "passphrase-rute-uji-42"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "crypto_uji.db"))
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


class TestCryptoToolsForm:
    def test_form_contains_csrf_and_steps_option(self, client):
        page = client.get("/crypto-tools")
        body = page.get_data(as_text=True)
        assert page.status_code == 200
        assert 'name="csrf_token"' in body
        assert 'name="show_steps"' in body
        assert "Tampilkan tahapan" in body

    def test_hint_vigenere_dan_pbkdf2_tersembunyi_bawaan(self, client):
        body = client.get("/crypto-tools").get_data(as_text=True)
        assert re.search(r'data-hint-vigenere[^>]*\bhidden\b', body)
        assert re.search(r'data-hint-kunci[^>]*\bhidden\b', body)
        assert re.search(r'id="ct-passphrase-field"[^>]*\bhidden\b', body)

    def test_post_without_csrf_rejected(self, client):
        page = client.post("/crypto-tools", data={
            "cipher": "super", "action": "encrypt",
            "text": "uji", "passphrase": PASSPHRASE,
        })
        assert page.status_code == 400


class TestSuperEncryptionRoute:
    def test_encrypt_with_steps_shows_each_layer(self, client):
        page = _post(
            client, cipher="super", action="encrypt",
            text="Halo Super Encryption", passphrase=PASSPHRASE,
            show_steps="1",
        )
        body = page.get_data(as_text=True)
        assert page.status_code == 200
        assert "CXSE2." in body
        for label in (
            "Layer 1 — Vigenere", "Layer 2 — Playfair",
            "Layer 3 — ChaCha20", "Layer 4 — Blowfish-CBC",
        ):
            assert label in body

    def test_encrypt_without_steps_hides_layers(self, client):
        page = _post(
            client, cipher="super", action="encrypt",
            text="Halo", passphrase=PASSPHRASE,
        )
        body = page.get_data(as_text=True)
        assert "CXSE2." in body
        assert "Layer 1 — Vigenere" not in body

    def test_decrypt_roundtrip(self, client):
        pesan = "Pesan terenkripsi lewat rute"
        enc = _post(
            client, cipher="super", action="encrypt",
            text=pesan, passphrase=PASSPHRASE,
        )
        ciphertext = _first_output(enc.get_data(as_text=True))
        assert ciphertext and ciphertext.startswith("CXSE2.")
        dec = _post(
            client, cipher="super", action="decrypt",
            text=ciphertext, passphrase=PASSPHRASE,
        )
        assert pesan in dec.get_data(as_text=True)

    def test_wrong_passphrase_shows_error(self, client):
        enc = _post(
            client, cipher="super", action="encrypt",
            text="rahasia", passphrase=PASSPHRASE,
        )
        ciphertext = _first_output(enc.get_data(as_text=True))
        dec = _post(
            client, cipher="super", action="decrypt",
            text=ciphertext, passphrase="salah",
        )
        body = dec.get_data(as_text=True)
        assert "CXSE2." not in (_first_output(body) or "")
        assert "kx-infobox-danger" in body

    def test_output_not_written_to_cookie(self, client):
        enc = _post(
            client, cipher="super", action="encrypt",
            text="larangan-ke-cookie", passphrase=PASSPHRASE,
        )
        ciphertext = _first_output(enc.get_data(as_text=True))
        assert ciphertext
        for header in enc.headers.getlist("Set-Cookie"):
            assert ciphertext not in header
            assert "larangan-ke-cookie" not in header


class TestIndividualCipherRoute:
    def test_chacha20_with_text_key_encrypts(self, client):
        """Kunci berupa teks tidak lagi membuat bytes.fromhex gagal."""
        page = _post(
            client, cipher="chacha20", action="encrypt",
            text="pesan chacha", key="kunci teks biasa",
        )
        body = page.get_data(as_text=True)
        assert page.status_code == 200
        assert "kx-infobox-danger" not in body
        token = _first_output(body)
        assert token and ":" in token

    def test_chacha20_text_key_roundtrip(self, client):
        enc = _post(
            client, cipher="chacha20", action="encrypt",
            text="putar balik chacha", key="kunci teks biasa",
        )
        token = _first_output(enc.get_data(as_text=True))
        dec = _post(
            client, cipher="chacha20", action="decrypt",
            text=token, key="kunci teks biasa",
        )
        assert "putar balik chacha" in dec.get_data(as_text=True)

    def test_blowfish_text_key_roundtrip(self, client):
        """Kunci Blowfish diturunkan dengan PBKDF2 bersalt, bukan SHA-256 polos."""
        enc = _post(
            client, cipher="blowfish", action="encrypt",
            text="putar balik blowfish", key="rahasia-123",
        )
        body = enc.get_data(as_text=True)
        assert "kx-infobox-danger" not in body
        token = _first_output(body)
        assert token and ":" in token
        dec = _post(
            client, cipher="blowfish", action="decrypt",
            text=token, key="rahasia-123",
        )
        assert "putar balik blowfish" in dec.get_data(as_text=True)

    def test_blowfish_wrong_key_shows_error(self, client):
        enc = _post(
            client, cipher="blowfish", action="encrypt",
            text="rahasia", key="kunci-satu",
        )
        token = _first_output(enc.get_data(as_text=True))
        dec = _post(
            client, cipher="blowfish", action="decrypt",
            text=token, key="kunci-dua",
        )
        assert "kx-infobox-danger" in dec.get_data(as_text=True)

    def test_empty_key_shows_error(self, client):
        page = _post(
            client, cipher="chacha20", action="encrypt",
            text="pesan", key="",
        )
        assert "kx-infobox-danger" in page.get_data(as_text=True)


class TestSuperEncryptionTraceRoute:
    def test_steps_show_trace_tables_and_limits(self, client):
        page = _post(
            client, cipher="super", action="encrypt",
            text="A" * 300, passphrase=PASSPHRASE, show_steps="1",
        )
        body = page.get_data(as_text=True)
        assert page.status_code == 200
        assert "kx-ct-trace" in body
        assert "Pasangan Asal" in body
        assert "Sebelum (hex)" in body
        assert "ditampilkan 200 pertama" in body
        assert "ditampilkan 100 pasangan pertama" in body
        assert "ditampilkan 64 byte pertama" in body
        assert PASSPHRASE not in body

    def test_steps_mask_vigenere_key(self, client):
        page = _post(
            client, cipher="super", action="encrypt",
            text="Halo Dunia", passphrase=PASSPHRASE, show_steps="1",
        )
        body = page.get_data(as_text=True)
        assert "***" in body
        assert PASSPHRASE not in body
