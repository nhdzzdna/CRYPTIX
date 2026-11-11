"""
tests/test_u3_ui.py
───────────────────
Uji kontrak markup U3 untuk Account Vault, Secure Notes, Crypto Tools,
dan Steganography: struktur kx-*, empty state, grant reauth, elemen yang
dipakai JS (id/data-*), serta perbaikan input use_encryption ganda di
halaman Steganography.
"""

import io
import os
import re

import numpy as np
import pytest
from PIL import Image

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth
from modules.authentication.auth import register_user
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys
from modules.strings import MSG

PASSWORD = "KataSandi-U3-2026!"
DEK = b"\x33" * 32

HALAMAN_U3 = (
    ("/account-vault", "account_vault"),
    ("/secure-notes", "secure_notes"),
    ("/crypto-tools", "crypto_tools"),
    ("/steganography", "steganography"),
)


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "u3ui.db"))
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
    reauth.clear()
    return application


@pytest.fixture()
def client(app):
    hasil = register_user("pemilik_u3", "u3@contoh.test", PASSWORD)
    assert hasil["success"], hasil
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = hasil["user_id"]
        sess["username"] = "pemilik_u3"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
    session_keys.put(sid, DEK)
    return c


def _halaman(client, url: str) -> str:
    resp = client.get(url)
    assert resp.status_code == 200
    return resp.get_data(as_text=True)


def _csrf(client, url: str) -> str:
    cocok = re.search(r'name="csrf_token" value="([^"]+)"', _halaman(client, url))
    assert cocok
    return cocok.group(1)


def _png_bytes(lebar: int = 120, tinggi: int = 120) -> bytes:
    penyangga = io.BytesIO()
    piksel = np.full((tinggi, lebar, 3), 255, dtype=np.uint8)
    Image.fromarray(piksel, "RGB").save(penyangga, format="PNG")
    return penyangga.getvalue()


# ── Kerangka bersama empat halaman ───────────────────────────────────────────


class TestKerangkaBersama:
    def test_halaman_termuat_dengan_css_halaman(self, client):
        for url, nama in HALAMAN_U3:
            body = _halaman(client, url)
            assert f"css/halaman/{nama}.css" in body

    def test_tanpa_skrip_inline_atau_handler_inline(self, client):
        for url, _ in HALAMAN_U3:
            body = _halaman(client, url)
            assert re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", body, flags=re.I) == []
            for aksi in ("onchange=", "oninput=", "onsubmit=", "onclick="):
                assert aksi not in body

    def test_markup_baru_bebas_style_dan_kelas_lama(self):
        for _, nama in HALAMAN_U3:
            with open(os.path.join("templates", f"{nama}.html"),
                      encoding="utf-8") as berkas:
                sumber = berkas.read()
            assert 'style="' not in sumber
            assert "form-control" not in sumber

    def test_pesan_js_lewat_data_msg(self, client):
        penanda = {
            "/account-vault": "data-msg-delete-title",
            "/secure-notes": "data-msg-search-empty",
            "/crypto-tools": "data-msg-copy-done",
            "/steganography": "data-msg-extract-failed",
        }
        for url, atribut in penanda.items():
            body = _halaman(client, url)
            assert atribut in body
            assert "{{" not in body

    def test_tanpa_kata_terlarang(self, client):
        pola = re.compile(r"\b(semester|uas|uts|mahasiswa|dosen)\b", re.I)
        for url, _ in HALAMAN_U3:
            assert pola.search(_halaman(client, url)) is None


# ── Account Vault ────────────────────────────────────────────────────────────


class TestAccountVault:
    def test_kosong_dengan_empty_state_dan_form_tambah(self, client):
        body = _halaman(client, "/account-vault")
        assert "Kredensial tersimpan (0)" in body
        assert "Belum ada kredensial tersimpan" in body
        assert "data-av-fokus" in body
        assert 'id="av-add-form"' in body
        assert 'action="/account-vault/add"' in body
        for nama in ("site_name", "username", "password", "url", "notes"):
            assert f'name="{nama}"' in body
        assert 'id="av-buat-otomatis"' in body
        assert "Buat otomatis" in body
        assert "data-kx-meter" in body
        assert "Simpan terenkripsi" in body
        assert ">Terenkripsi<" in body
        sandi = re.search(r'<input type="password"[^>]*id="av-add-password"[^>]*>', body)
        assert sandi and 'name="password"' in sandi.group(0)

    def test_baris_dengan_detail_edit_dan_hapus(self, client):
        token = _csrf(client, "/account-vault")
        resp = client.post("/account-vault/add", data={
            "csrf_token": token,
            "site_name": "Situs U3",
            "username": "pengguna@contoh.test",
            "password": "SandiKuat-123",
            "url": "",
            "notes": "",
        }, follow_redirects=False)
        assert resp.status_code == 302

        body = _halaman(client, "/account-vault")
        assert "Kredensial tersimpan (1)" in body
        assert "Belum ada kredensial tersimpan" not in body
        assert re.search(r'data-entry="\d+"', body)

        # Detail mode lihat tersembunyi sampai tombol Tampilkan (grant reveal).
        assert 'data-reauth="account.reveal"' in body
        assert re.search(r'data-reveal-id="\d+"', body)
        assert re.search(r'data-reveal-box="\d+"[^>]*\bhidden\b', body)
        assert re.search(r'type="password"[^>]*data-field-password="\d+"', body)

        # Form edit tersembunyi sampai tombol Edit ditekan.
        assert re.search(r'data-edit-form="\d+"[^>]*\bhidden\b', body)
        assert 'action="/account-vault/edit/' in body
        assert re.search(r'id="edit-password-\d+"', body)

        # Hapus menyebut sumber daya lewat tombol baris, bukan form dasar.
        assert re.search(r'data-av-hapus="\d+"', body)
        assert "/account-vault/delete/" in body

        # Kata sandi selalu tersamar (input password) di semua mode.
        assert body.count('type="password"') >= 3


# ── Secure Notes ─────────────────────────────────────────────────────────────


class TestSecureNotes:
    def test_kosong_dengan_empty_state_editor(self, client):
        body = _halaman(client, "/secure-notes")
        assert "Catatan tersimpan (0)" in body
        assert "Belum ada catatan" in body
        assert "Belum ada catatan dipilih" in body
        assert "data-sn-baru" in body
        assert 'id="sn-form"' in body
        assert 'action="/secure-notes/add"' in body
        assert 'name="title"' in body
        assert 'name="content"' in body
        assert "Simpan terenkripsi" in body
        assert 'id="sn-editor-isi" hidden' in body

    def test_baris_dengan_grant_buka(self, client):
        token = _csrf(client, "/secure-notes")
        resp = client.post("/secure-notes/add", data={
            "csrf_token": token,
            "title": "Catatan U3",
            "content": "Isi rahasia catatan",
        }, follow_redirects=False)
        assert resp.status_code == 302

        body = _halaman(client, "/secure-notes")
        assert "Catatan tersimpan (1)" in body
        assert "Belum ada catatan dipilih" in body  # panel kanan tetap kosong
        assert re.search(r'data-sn-id="\d+"', body)
        assert re.search(r'data-sn-open-url="[^"]*/secure-notes/open/\d+"', body)
        assert re.search(r'data-sn-edit-url="[^"]*/secure-notes/edit/\d+"', body)
        assert re.search(r'data-sn-hapus-url="[^"]*/secure-notes/delete/\d+"', body)
        assert 'data-reauth="note.open"' in body
        assert 'id="sn-buka"' in body
        assert re.search(r'id="sn-hapus"[^>]*\bhidden\b', body)
        assert 'id="sn-cari"' in body


# ── Crypto Tools ─────────────────────────────────────────────────────────────


class TestCryptoTools:
    def test_lima_kartu_algoritma_dengan_deskripsi(self, client):
        body = _halaman(client, "/crypto-tools")
        for cipher in ("super", "vigenere", "playfair", "chacha20", "blowfish"):
            assert f'data-cipher="{cipher}"' in body
            assert f'data-deskripsi="{cipher}"' in body
        assert body.count('class="kx-ct-algo is-aktif"') == 1
        assert 'id="ct-cipher" value="super"' in body
        assert 'id="ct-aksi" value="encrypt"' in body
        assert 'data-aksi="encrypt"' in body
        assert 'data-aksi="decrypt"' in body

        # Hanya deskripsi algoritma terpilih yang terlihat.
        assert re.search(r'data-deskripsi="super"(?![^>]*\bhidden\b)', body)
        for cipher in ("vigenere", "playfair", "chacha20", "blowfish"):
            assert re.search(rf'data-deskripsi="{cipher}"[^>]*\bhidden\b', body)

        # Keterangan kunci + checkbox tahapan + hasil kosong.
        assert 'id="ct-passphrase"' in body
        assert "data-kx-sandi" in body
        assert 'name="show_steps"' in body
        assert "Tampilkan tahapan" in body
        assert "Belum ada hasil" in body
        assert "data-ct-fokus" in body
        assert 'id="ct-salin"' not in body

    def test_galat_dirender_sebagai_infobox_merah(self, client):
        token = _csrf(client, "/crypto-tools")
        resp = client.post("/crypto-tools", data={
            "csrf_token": token,
            "cipher": "super", "action": "encrypt",
            "text": "uji", "passphrase": "",
        })
        body = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert "kx-infobox-danger" in body

    def test_hasil_dan_tahapan_setelah_proses(self, client):
        token = _csrf(client, "/crypto-tools")
        resp = client.post("/crypto-tools", data={
            "csrf_token": token,
            "cipher": "super", "action": "encrypt",
            "text": "A" * 300, "passphrase": "frasa-u3",
            "show_steps": "1",
        })
        body = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert 'id="ct-hasil"' in body
        assert 'id="ct-salin"' in body
        assert "Belum ada hasil" not in body
        assert "Tahapan Super Encryption" in body
        assert "kx-stepper" in body
        assert "Tabel jejak" in body
        assert "ditampilkan 200 pertama" in body


# ── Steganography ─────────────────────────────────────────────────────────────


class TestSteganography:
    def test_dua_kartu_dan_kontrak_sisip_ekstrak(self, client):
        body = _halaman(client, "/steganography")
        assert 'id="sg-sisip-title"' in body
        assert 'id="sg-ekstrak-title"' in body
        assert body.count("data-kx-dropzone") == 3

        # Segmented jenis muatan dan pilihan kunci.
        assert 'data-sg-jenis="text"' in body
        assert 'data-sg-jenis="file"' in body
        assert 'name="payload_type" id="sg-jenis" value="text"' in body
        assert 'data-sg-kunci="account"' in body
        assert 'data-sg-kunci="passphrase"' in body
        assert 'name="key_mode" id="sg-kunci-mode" value="account"' in body

        # Kunci akun: penjelasan tampil, kolom kunci rahasia tersembunyi.
        assert 'id="sg-kunci-akun-info"' in body
        assert MSG.STEGO_ACCOUNT_KEY_NOTE in body
        assert re.search(r'id="sg-kunci-rahasia-field"[^>]*\bhidden\b', body)

        # Indikator kapasitas + peringatan PNG + detail teknis.
        assert 'id="sg-kapasitas"' in body
        assert MSG.STEGO_PNG_WARNING in body
        assert "Detail teknis" in body
        assert "CRXS" in body
        assert re.search(r'<details[^>]*kx-sg-teknis', body)

        # Kartu ekstrak: unggahan + kunci opsional + grant.
        assert 'action="/steganography/extract-upload"' in body
        assert 'data-stego-upload="1"' in body
        assert 'id="sg-ekstrak-btn"' in body
        assert 'data-reauth="stego.extract"' in body
        assert 'id="stego-result"' in body
        assert "Belum ada hasil ekstraksi" in body

        # Tabel tersimpan kosong dengan tombol aksi.
        assert "Belum ada stego image tersimpan" in body
        assert "data-sg-fokus-sisip" in body

    def test_use_encryption_hanya_satu_input(self, client):
        """Perbaikan: dulu ada hidden use_encryption=0 plus checkbox bernama
        sama sehingga nilai pertama yang dibaca dan enkripsi mati diam-diam."""
        body = _halaman(client, "/steganography")
        bernama = re.findall(r'<input[^>]*name="use_encryption"[^>]*>', body)
        assert len(bernama) == 1
        assert 'id="sg-use-enc"' in bernama[0]
        assert 'value="1"' in bernama[0]
        kotak = re.search(r'<input[^>]*id="sg-enkripsi"[^>]*>', body)
        assert kotak
        assert 'name="' not in kotak.group(0)

    def test_baris_tersimpan_tanpa_kunci_per_baris(self, client):
        token = _csrf(client, "/steganography")
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_png_bytes()), "pembawa.png"),
            "payload_type": "text",
            "message": "rahasia u3",
            "key_mode": "account",
            "use_encryption": "1",
        }, content_type="multipart/form-data", follow_redirects=False)
        assert resp.status_code == 302

        body = _halaman(client, "/steganography")
        assert "Belum ada stego image tersimpan" not in body
        assert re.search(r'data-sg-id="\d+"', body)
        assert re.search(r'data-sg-ekstrak-url="[^"]*/steganography/extract/\d+"', body)
        assert "/steganography/download/" in body
        assert "/steganography/delete/" in body

        # Menu tiga titik memuat Ekstrak, Unduh (grant), Hapus.
        assert "data-sg-menu" in body
        assert 'aria-haspopup="menu"' in body
        assert "data-sg-ekstrak" in body
        assert 'data-reauth="stego.download"' in body
        assert re.search(r'data-reauth-resource="\d+"', body)
        assert "data-sg-hapus" in body

        # Kolom kunci hanya tiga: sisip, ekstrak unggahan, modal per baris.
        identitas = re.findall(r'name="passphrase" id="([a-z-]+)"', body)
        assert sorted(identitas) == [
            "sg-ekstrak-passphrase", "sg-modal-passphrase", "sg-passphrase",
        ]
        assert 'id="sg-modal-ekstrak"' in body
        assert 'id="sg-modal-passphrase"' in body
        assert "data-sg-tutup-modal" in body

    def test_embed_tanpa_kolom_use_encryption_tetap_enkripsi(self, client):
        """Tanpa JS, hidden default "1" menjaga muatan tetap terenkripsi."""
        token = _csrf(client, "/steganography")
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_png_bytes()), "pembawa.png"),
            "payload_type": "text",
            "message": "tanpa kolom",
            "key_mode": "account",
        }, content_type="multipart/form-data", follow_redirects=False)
        assert resp.status_code == 302
        with get_db() as db:
            baris = db.execute(
                "SELECT has_encryption FROM stego_images WHERE original_name != ''"
            ).fetchall()
        assert baris and all(r["has_encryption"] == 1 for r in baris)

    def test_passphrase_wajib_bila_kunci_rahasia(self, client):
        token = _csrf(client, "/steganography")
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_png_bytes()), "pembawa.png"),
            "payload_type": "text",
            "message": "pesan",
            "key_mode": "passphrase",
            "passphrase": "",
        }, content_type="multipart/form-data", follow_redirects=True)
        body = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert MSG.STEGO_PASSPHRASE_REQUIRED in body
