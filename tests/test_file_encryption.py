"""
tests/test_file_encryption.py
──────────────────────────────
Uji enkripsi berkas per chunk AES-256-GCM: struktur header, roundtrip,
rentang dekripsi, penolakan pemotongan/penukaran/pemodifan chunk, dan nama
simpan acak. Bagian terakhir menguji API lama yang masih ber-DEPRECATED.
"""

import hashlib
import io
import os
import re

import pytest

from cryptography.exceptions import InvalidTag

import config

from modules.cryptography.file_encryption import (
    CHUNK_SIZE,
    decrypt_all,
    decrypt_file,
    decrypt_range,
    encrypt_file,
    encrypt_stream,
    file_aad,
    generate_stored_name,
    load_encrypted_file,
    save_encrypted_file,
)

HEADER_LENGTH = 37
AAD = file_aad(1, "berkas-uji.bin")


def _key(seed: str = "kunci-berkas-uji") -> bytes:
    return hashlib.sha256(seed.encode()).digest()


def _encrypt(data: bytes, key: bytes | None = None, aad: bytes | None = None) -> tuple[bytes, dict]:
    """Enkripsi dari memori ke memori; plaintext tidak pernah menyentuh disk."""
    keluaran = io.BytesIO()
    info = encrypt_stream(io.BytesIO(data), keluaran, key or _key(), aad or AAD)
    return keluaran.getvalue(), info


def _simpan(tmp_path, blob: bytes, nama: str = "berkas.bin") -> str:
    tujuan = tmp_path / nama
    tujuan.write_bytes(blob)
    return str(tujuan)


class TestStrukturHeader:
    def test_header_berisi_magic_versi_chunk_salt_dan_jumlah(self):
        data = os.urandom(CHUNK_SIZE + 1000)
        blob, info = _encrypt(data)
        header = blob[:HEADER_LENGTH]

        assert header[:8] == b"CRYPTIX1"
        assert header[8] == 1
        assert int.from_bytes(header[9:13], "big") == CHUNK_SIZE
        assert len(header[13:29]) == 16
        assert int.from_bytes(header[29:37], "big") == 2

        assert info["chunk_count"] == 2
        assert info["size"] == len(data)
        assert len(blob) == HEADER_LENGTH + (CHUNK_SIZE + 16) + (1000 + 16)

    def test_salt_berkas_acak_setiap_enkripsi(self):
        blob1, _ = _encrypt(b"isi sama")
        blob2, _ = _encrypt(b"isi sama")
        assert blob1[13:29] != blob2[13:29]
        assert blob1 != blob2

    def test_hash_plaintext_dan_hash_ciphertext_sesuai(self):
        data = b"konten uji hash"
        blob, info = _encrypt(data)
        assert info["sha256_plaintext"] == hashlib.sha256(data).hexdigest()
        assert info["sha256_ciphertext"] == hashlib.sha256(blob).hexdigest()

    def test_kunci_per_berkas_berasal_dari_salt(self):
        key = _key()
        data = b"isi"
        blob1, _ = _encrypt(data, key=key)
        blob2, _ = _encrypt(data, key=key)
        # Salt berbeda → kunci chunk berbeda → ciphertext berbeda walau kunci sama.
        assert blob1[HEADER_LENGTH:] != blob2[HEADER_LENGTH:]

    def test_input_tanpa_seek_ditolak(self):
        class HanyaBaca:
            def read(self, _n=-1):
                return b""

        with pytest.raises(ValueError):
            encrypt_stream(HanyaBaca(), io.BytesIO(), _key(), AAD)


class TestRoundtrip:
    @pytest.mark.parametrize("ukuran", [0, 1, 100, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE + 5])
    def test_decrypt_all_mengembalikan_plaintext_utuh(self, tmp_path, ukuran):
        data = os.urandom(ukuran) if ukuran else b""
        blob, info = _encrypt(data)
        path = _simpan(tmp_path, blob)

        assert decrypt_all(path, _key(), AAD) == data
        assert info["chunk_count"] == (ukuran + CHUNK_SIZE - 1) // CHUNK_SIZE

    def test_keluaran_dapat_ditulis_langsung_ke_path(self, tmp_path):
        tujuan = tmp_path / "keluaran.bin"
        data = b"tulis langsung ke path"
        info = encrypt_stream(io.BytesIO(data), str(tujuan), _key(), AAD)
        assert info["sha256_plaintext"] == hashlib.sha256(data).hexdigest()
        assert decrypt_all(str(tujuan), _key(), AAD) == data


class TestRentangDekripsi:
    @pytest.fixture()
    def berkas(self, tmp_path):
        data = os.urandom(2 * CHUNK_SIZE + 500)
        blob, _ = _encrypt(data)
        return _simpan(tmp_path, blob), data

    def test_rentang_di_dalam_chunk_pertama(self, berkas):
        path, data = berkas
        assert decrypt_range(path, _key(), AAD, 0, 99) == data[0:100]

    def test_rentang_melintasi_batas_chunk(self, berkas):
        path, data = berkas
        mulai, akhir = CHUNK_SIZE - 5, CHUNK_SIZE + 4
        assert decrypt_range(path, _key(), AAD, mulai, akhir) == data[mulai:akhir + 1]

    def test_rentang_pada_chunk_terakhir(self, berkas):
        path, data = berkas
        mulai = 2 * CHUNK_SIZE + 10
        assert decrypt_range(path, _key(), AAD, mulai, len(data) - 1) == data[mulai:]

    def test_rentang_penuh_sama_dengan_decrypt_all(self, berkas):
        path, data = berkas
        assert decrypt_range(path, _key(), AAD, 0, len(data) - 1) == data
        assert decrypt_range(path, _key(), AAD, 0, len(data) + 9999) == data

    def test_rentang_mulai_di_luar_berkas_menghasilkan_kosong(self, berkas):
        path, data = berkas
        assert decrypt_range(path, _key(), AAD, len(data), len(data) + 10) == b""

    def test_rentang_tidak_valid_ditolak(self, berkas):
        path, _ = berkas
        with pytest.raises(ValueError):
            decrypt_range(path, _key(), AAD, -1, 10)
        with pytest.raises(ValueError):
            decrypt_range(path, _key(), AAD, 50, 10)


class TestIntegritas:
    @pytest.fixture()
    def berkas(self, tmp_path):
        data = os.urandom(CHUNK_SIZE + 500)
        blob, _ = _encrypt(data)
        return _simpan(tmp_path, blob), data, blob

    def test_kunci_salah_ditolak(self, berkas):
        path, _data, _blob = berkas
        with pytest.raises(InvalidTag):
            decrypt_all(path, _key("kunci-lain"), AAD)

    def test_aad_pengguna_lain_ditolak(self, berkas):
        path, _data, _blob = berkas
        with pytest.raises(InvalidTag):
            decrypt_all(path, _key(), file_aad(2, "berkas-uji.bin"))

    def test_chunk_dimodifikasi_ditolak(self, berkas, tmp_path):
        path, _data, blob = berkas
        rusak = bytearray(blob)
        rusak[HEADER_LENGTH + 7] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_all(_simpan(tmp_path, bytes(rusak), "rusak.bin"), _key(), AAD)

    def test_dua_chunk_bertukar_urutan_ditolak(self, tmp_path):
        data = os.urandom(2 * CHUNK_SIZE)
        blob, _ = _encrypt(data)
        awal = blob[:HEADER_LENGTH]
        chunk0 = blob[HEADER_LENGTH:HEADER_LENGTH + CHUNK_SIZE + 16]
        chunk1 = blob[HEADER_LENGTH + CHUNK_SIZE + 16:]
        tertukar = awal + chunk1 + chunk0

        with pytest.raises(InvalidTag):
            decrypt_all(_simpan(tmp_path, tertukar), _key(), AAD)

    def test_pemotongan_chunk_terakhir_ditolak(self, berkas, tmp_path):
        _path, _data, blob = berkas
        potong = blob[: HEADER_LENGTH + CHUNK_SIZE + 16]
        with pytest.raises(ValueError):
            decrypt_all(_simpan(tmp_path, potong), _key(), AAD)

    def test_pemotongan_sebagian_menimbulkan_invalid_tag(self, berkas, tmp_path):
        _path, _data, blob = berkas
        potong = blob[:-100]
        with pytest.raises(InvalidTag):
            decrypt_all(_simpan(tmp_path, potong), _key(), AAD)

    def test_jumlah_chunk_pada_header_dimodifikasi_ditolak(self, berkas, tmp_path):
        _path, _data, blob = berkas
        rusak = bytearray(blob)
        rusak[29:37] = (1).to_bytes(8, "big")   # 2 chunk diklaim jadi 1
        with pytest.raises(InvalidTag):
            decrypt_all(_simpan(tmp_path, bytes(rusak)), _key(), AAD)

    def test_header_bukan_format_cryptix_ditolak(self, berkas, tmp_path):
        _path, _data, blob = berkas
        rusak = bytearray(blob)
        rusak[:8] = b"BUKANCXP"
        with pytest.raises(ValueError):
            decrypt_all(_simpan(tmp_path, bytes(rusak)), _key(), AAD)

    def test_rentang_hanya_mendekripsi_chunk_yang_beririsan(self, berkas, tmp_path):
        _path, data, blob = berkas
        rusak = bytearray(blob)
        rusak[HEADER_LENGTH + 3] ^= 0xFF          # chunk 0 rusak
        path_rusak = _simpan(tmp_path, bytes(rusak), "rusak.bin")

        mulai = CHUNK_SIZE + 1
        hasil = decrypt_range(path_rusak, _key(), AAD, mulai, mulai + 9)
        assert hasil == data[mulai:mulai + 10]

        with pytest.raises(InvalidTag):
            decrypt_all(path_rusak, _key(), AAD)


class TestNamaSimpan:
    def test_bentuk_heksadesimal_tanpa_ekstensi_asli(self):
        assert re.fullmatch(r"[0-9a-f]{32}\.bin", generate_stored_name())

    def test_berbeda_setiap_panggilan(self):
        assert generate_stored_name() != generate_stored_name()


class TestApiLamaDeprecated:
    """API lama tetap berfungsi sampai dihapus pada tahap transisi akhir."""

    def test_encrypt_file_roundtrip(self):
        key = _key()
        data = b"isi berkas lama"
        res = encrypt_file(data, key)
        assert decrypt_file(res["ciphertext"], res["nonce_hex"], key) == data
        assert res["sha256_hex"] == hashlib.sha256(data).hexdigest()

    def test_encrypt_file_kunci_salah_ditolak(self):
        res = encrypt_file(b"data", _key("satu"))
        with pytest.raises(InvalidTag):
            decrypt_file(res["ciphertext"], res["nonce_hex"], _key("dua"))

    def test_simpan_dan_muat_berkas(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path))
        hasil = encrypt_file(b"isi", _key())
        nama = save_encrypted_file(hasil["ciphertext"], "arsip.enc")
        assert os.path.isfile(nama)
        assert load_encrypted_file("arsip.enc") == hasil["ciphertext"]
