"""
tests/test_database_encryption.py
──────────────────────────────────
Uji enkripsi field basis data: format "v1:<nonce>:<ciphertext>",
ikatan AAD ke pengguna/tabel/kolom, dan penolakan pemindahan token.
"""

import hashlib

import pytest

from modules.cryptography.database_encryption import (
    decrypt_field,
    decrypt_record,
    encrypt_field,
    encrypt_record,
    field_aad,
)


def _key(seed: str = "kunci-field-uji") -> bytes:
    return hashlib.sha256(seed.encode()).digest()


AAD = field_aad(1, "account_vault", "password_enc")


class TestFormatField:
    def test_format_v1_dengan_nonce_dan_ciphertext(self):
        token = encrypt_field("rahasia", _key(), AAD)
        version, nonce_hex, body_hex = token.split(":")
        assert version == "v1"
        assert len(bytes.fromhex(nonce_hex)) == 12
        assert len(bytes.fromhex(body_hex)) == 16 + len("rahasia".encode())

    def test_aad_memakai_pola_pengguna_tabel_kolom(self):
        assert field_aad(7, "secure_notes", "content_enc") == b"7:secure_notes:content_enc"

    def test_nonce_berbeda_setiap_enkripsi(self):
        key = _key()
        assert encrypt_field("sama", key, AAD) != encrypt_field("sama", key, AAD)

    def test_plaintext_tidak_muncul_di_token(self):
        token = encrypt_field("kata-sandi-tersembunyi", _key(), AAD)
        assert "kata-sandi-tersembunyi" not in token
        assert "kata" not in token

    def test_unicode_dan_string_kosong_roundtrip(self):
        key = _key()
        for nilai in ("Pesan ኣ_berkas ✅", ""):
            assert decrypt_field(encrypt_field(nilai, key, AAD), key, AAD) == nilai


class TestIkatAAD:
    def test_gagal_bila_pengguna_berbeda(self):
        key = _key()
        token = encrypt_field("milik-saya", key, AAD)
        with pytest.raises(ValueError):
            decrypt_field(token, key, field_aad(2, "account_vault", "password_enc"))

    def test_gagal_bila_tabel_berbeda(self):
        key = _key()
        token = encrypt_field("milik-kolom-ini", key, AAD)
        with pytest.raises(ValueError):
            decrypt_field(token, key, field_aad(1, "secure_notes", "password_enc"))

    def test_gagal_bila_kolom_berbeda(self):
        key = _key()
        token = encrypt_field("rahasia", key, AAD)
        with pytest.raises(ValueError):
            decrypt_field(token, key, field_aad(1, "account_vault", "username_enc"))

    def test_gagal_bila_aad_dihapus(self):
        key = _key()
        token = encrypt_field("rahasia", key, AAD)
        with pytest.raises(ValueError):
            decrypt_field(token, key, b"")

    def test_enkripsi_menolak_aad_kosong(self):
        with pytest.raises(ValueError):
            encrypt_field("rahasia", _key(), b"")

    def test_enkripsi_menolak_kunci_bukan_32_byte(self):
        with pytest.raises(ValueError):
            encrypt_field("rahasia", b"pendek", AAD)


class TestKegagalanDekripsi:
    def test_kunci_salah_ditolak(self):
        token = encrypt_field("rahasia", _key("kunci-satu"), AAD)
        with pytest.raises(ValueError):
            decrypt_field(token, _key("kunci-dua"), AAD)

    def test_ciphertext_dimodifikasi_ditolak(self):
        key = _key()
        version, nonce_hex, body_hex = encrypt_field("penting", key, AAD).split(":")
        badan = bytearray(bytes.fromhex(body_hex))
        badan[0] ^= 0xFF
        with pytest.raises(ValueError):
            decrypt_field(f"{version}:{nonce_hex}:{badan.hex()}", key, AAD)

    def test_format_tidak_valid_ditolak(self):
        key = _key()
        for token in ("", "hanya-dua:bagian", "v2:aabb:ccdd", None):
            with pytest.raises(ValueError):
                decrypt_field(token, key, AAD)


class TestRekamanField:
    def test_roundtrip_dengan_nilai_kosong(self):
        key = _key()
        asli = {
            "site_name_enc": "Contoh Situs",
            "username_enc": "pengguna",
            "password_enc": "",
            "url_enc": "",
            "notes_enc": "catatan singkat",
        }
        enc = encrypt_record(asli, key, 3, "account_vault")
        assert enc["password_enc"] == "" and enc["url_enc"] == ""
        assert decrypt_record(enc, key, 3, "account_vault") == asli

    def test_nilai_terenkripsi_bukan_plaintext(self):
        key = _key()
        enc = encrypt_record(
            {"title_enc": "Judul Catatan", "content_enc": "Isi catatan"},
            key, 3, "secure_notes",
        )
        assert "Judul Catatan" not in enc["title_enc"]
        assert "Isi catatan" not in enc["content_enc"]

    def test_gagal_bila_baris_dipindahkan_ke_pengguna_lain(self):
        key = _key()
        enc = encrypt_record(
            {"title_enc": "Judul", "content_enc": "Isi"}, key, 1, "secure_notes",
        )
        with pytest.raises(ValueError):
            decrypt_record(enc, key, 2, "secure_notes")
