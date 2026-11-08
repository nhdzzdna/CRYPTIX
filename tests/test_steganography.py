"""
tests/test_steganography.py
────────────────────────────
Uji LSB: round trip teks dan berkas, penolakan gambar tanpa pesan,
kapasitas terlampaui, kunci salah, posisi bit tidak berurutan, batas
dimensi, serta rute web (kapasitas, sisip berkas, ekstrak unggahan).
"""

import io
import os
import re
import struct
import tempfile
import zlib

import pytest
from PIL import Image
import numpy as np

import config
from modules.strings import MSG
from modules.cryptography import session_keys
from modules.steganography.lsb import (
    HEADER_BITS, MAGIC, VERSION,
    _payload_positions,
    embed_file, embed_message, extract_file, extract_message, extract_payload,
    image_capacity,
)

DEK = bytes(range(32))
DEK_LAIN = bytes(range(1, 33))
PASSPHRASE = "frasa-sandi-tersembunyi"


def _make_white_png(path: str, width: int = 200, height: int = 200) -> None:
    arr = np.full((height, width, 3), 255, dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(path, format="PNG")


class TestLSBUnit:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.src = os.path.join(self.tmpdir, "carrier.png")
        _make_white_png(self.src)

    def test_round_trip_teks_terenkripsi(self):
        out = os.path.join(self.tmpdir, "stego.png")
        msg = "Pesan rahasia LSB"
        result = embed_message(self.src, msg, out, master_key=DEK)
        assert result["success"] is True
        assert result["encrypted"] is True

        ext = extract_message(out, master_key=DEK)
        assert ext["success"] is True
        assert ext["message"] == msg
        assert ext["encrypted"] is True

    def test_round_trip_teks_tanpa_enkripsi(self):
        out = os.path.join(self.tmpdir, "plain.png")
        result = embed_message(self.src, "tampil polos", out,
                               master_key=DEK, encrypt=False)
        assert result["success"] is True
        assert result["encrypted"] is False

        ext = extract_message(out, master_key=DEK)
        assert ext["success"] is True
        assert ext["message"] == "tampil polos"
        assert ext["encrypted"] is False

    def test_round_trip_berkas(self):
        out = os.path.join(self.tmpdir, "stego_file.png")
        isi = bytes(range(256)) * 20
        sumber = os.path.join(self.tmpdir, "rahasia.bin")
        with open(sumber, "wb") as f:
            f.write(isi)

        result = embed_file(self.src, sumber, out, master_key=DEK)
        assert result["success"] is True
        assert result["encrypted"] is True

        tujuan = os.path.join(self.tmpdir, "keluaran.bin")
        ext = extract_file(out, tujuan, master_key=DEK)
        assert ext["success"] is True
        assert ext["filename"] == "rahasia.bin"
        with open(tujuan, "rb") as f:
            assert f.read() == isi

    def test_round_trip_passphrase(self):
        out = os.path.join(self.tmpdir, "stego_pass.png")
        assert embed_message(self.src, "pesan sandi", out,
                             passphrase=PASSPHRASE)["success"]
        ext = extract_message(out, passphrase=PASSPHRASE)
        assert ext["success"] is True
        assert ext["message"] == "pesan sandi"

        assert extract_message(out, passphrase="salah")["success"] is False

    def test_gambar_tanpa_pesan_ditolak_jelas(self):
        plain = os.path.join(self.tmpdir, "biasa.png")
        _make_white_png(plain, 80, 80)
        result = extract_message(plain, master_key=DEK)
        assert result["success"] is False
        assert result["error"] == MSG.STEGO_NO_MESSAGE

    def test_kapasitas_terlampaui_ditolak(self):
        kecil = os.path.join(self.tmpdir, "kecil.png")
        _make_white_png(kecil, 10, 10)
        out = os.path.join(self.tmpdir, "kecil_stego.png")
        result = embed_message(kecil, "A" * 500, out, master_key=DEK)
        assert result["success"] is False
        assert "terlalu besar" in result["error"].lower()

    def test_kunci_salah_gagal(self):
        out = os.path.join(self.tmpdir, "stego_key.png")
        embed_message(self.src, "kunci asli", out, master_key=DEK)
        ext = extract_message(out, master_key=DEK_LAIN)
        assert ext["success"] is False
        assert ext["error"] in {MSG.STEGO_TAMPERED, MSG.STEGO_DECRYPT_FAILED}

    def test_tanpa_kunci_ditolak(self):
        out = os.path.join(self.tmpdir, "stego_noke.png")
        result = embed_message(self.src, "tanpa kunci", out)
        assert result["success"] is False
        assert result["error"] == MSG.STEGO_KEY_REQUIRED

        berkunci = os.path.join(self.tmpdir, "stego_ok.png")
        embed_message(self.src, "rahasia", berkunci, master_key=DEK)
        assert extract_message(berkunci)["error"] == MSG.STEGO_KEY_REQUIRED

    def test_posisi_bit_tidak_berurutan(self):
        out = os.path.join(self.tmpdir, "stego_pos.png")
        embed_message(self.src, "acakkan posisi", out, master_key=DEK)

        flat = np.array(Image.open(out).convert("RGB"), dtype=np.uint8).reshape(-1)
        header = np.packbits(flat[:HEADER_BITS] & np.uint8(1)).tobytes()
        magic, version, _type, length, crc = struct.unpack(">4sBBII", header)
        assert magic == MAGIC and version == VERSION

        # Bit muatan pada posisi berurutan setelah header tidak cocok CRC32.
        berurutan = np.packbits(
            (flat[HEADER_BITS:HEADER_BITS + length * 8] & np.uint8(1))
        ).tobytes()
        assert zlib.crc32(berurutan) & 0xFFFFFFFF != crc

        # Sedangkan posisi hasil acakan deterministik dan tidak berurutan.
        acak = np.concatenate(list(
            _payload_positions(HEADER_BITS, 1000, flat.size,
                               int.from_bytes(DEK[:8], "big"))
        ))
        assert not np.array_equal(acak, np.arange(HEADER_BITS, HEADER_BITS + 1000))
        acak_lagi = np.concatenate(list(
            _payload_positions(HEADER_BITS, 1000, flat.size,
                               int.from_bytes(DEK[:8], "big"))
        ))
        assert np.array_equal(acak, acak_lagi)

    def test_dimensi_lewat_batas_ditolak(self):
        lebar = os.path.join(self.tmpdir, "lebar.png")
        _make_white_png(lebar, 4001, 4)
        out = os.path.join(self.tmpdir, "lebar_stego.png")
        result = embed_message(lebar, "x", out, master_key=DEK)
        assert result["success"] is False
        assert "4000" in result["error"]
        assert "4000" in extract_message(lebar, master_key=DEK)["error"]

    def test_header_bermagic_cr_xs(self):
        out = os.path.join(self.tmpdir, "stego_magic.png")
        embed_message(self.src, "magic", out, master_key=DEK)
        flat = np.array(Image.open(out).convert("RGB"), dtype=np.uint8).reshape(-1)
        assert np.packbits(flat[:HEADER_BITS] & np.uint8(1)).tobytes()[:4] == MAGIC

    def test_image_capacity(self):
        info = image_capacity(self.src)
        assert info["width"] == 200 and info["height"] == 200
        assert info["capacity"] == (200 * 200 * 3 - HEADER_BITS) // 8
        assert "error" in image_capacity(os.path.join(self.tmpdir, "hilang.png"))


# ── Rute web ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "stego_uji.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted_files"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego_images"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary_files"))
    from database.db import init_db, get_db
    init_db()
    with get_db() as db:
        db.execute(
            """INSERT OR IGNORE INTO users
               (id, username, email, password_hash, salt) VALUES (?,?,?,?,?)""",
            (1, "penguji", "penguji@contoh.test", "hash", "garam"),
        )
        db.commit()

    from app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "penguji"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, DEK)
    return c


def _csrf(client, halaman: str = "/steganography") -> str:
    page = client.get(halaman)
    assert page.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True))
    assert match
    return match.group(1)


def _gambar_png(ukuran: int = 120) -> bytes:
    arr = np.full((ukuran, ukuran, 3), (12, 90, 200), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="PNG")
    return buf.getvalue()


class TestRuteStego:
    def test_kapasitas_ditampilkan_sebelum_sisip(self, client):
        token = _csrf(client)
        resp = client.post("/steganography/capacity", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_gambar_png()), "pembawa.png"),
        }, content_type="multipart/form-data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["capacity"] == (120 * 120 * 3 - HEADER_BITS) // 8

    def test_sisipkan_teks_lalu_unduh_png(self, client):
        token = _csrf(client)
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_gambar_png()), "foto.jpg"),
            "payload_type": "text",
            "message": "pesan tersembunyi",
        }, content_type="multipart/form-data")
        assert resp.status_code == 302

        from database.db import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM stego_images WHERE user_id=1"
            ).fetchone()
        assert row["has_encryption"] == 1

        unduhan = client.get(f"/steganography/download/{row['id']}")
        assert unduhan.status_code == 200
        disp = unduhan.headers.get("Content-Disposition", "")
        assert "foto.png" in disp and ".jpg" not in disp.split("filename=")[-1]

        from modules.blockchain.blockchain import add_block  # noqa: F401
        with get_db() as db:
            aksi = [b["action"] for b in db.execute(
                "SELECT action FROM blockchain_log ORDER BY block_index"
            )]
        assert "STEGO_EMBED" in aksi

    def test_sisipkan_berkas_lalu_ekstrak_dari_unggahan(self, client):
        # Sisipkan berkas lewat rute.
        token = _csrf(client)
        isi = b"isi berkas tersembunyi " * 10
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_gambar_png(160)), "pembawa.png"),
            "payload_type": "file",
            "payload_file": (io.BytesIO(isi), "dokumen.txt"),
        }, content_type="multipart/form-data")
        assert resp.status_code == 302

        from database.db import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT stored_name FROM stego_images WHERE user_id=1"
            ).fetchone()
        with open(os.path.join(config.STEGO_IMAGES_DIR, row["stored_name"]), "rb") as f:
            png_bytes = f.read()

        # Ekstrak dari gambar yang diunggah pengguna (tanpa passphrase).
        token = _csrf(client)
        resp = client.post("/steganography/extract-upload", data={
            "csrf_token": token,
            "stego_image": (io.BytesIO(png_bytes), "hasil.png"),
            "passphrase": "",
        }, content_type="multipart/form-data")
        assert resp.status_code == 200
        assert resp.data == isi
        assert "dokumen.txt" in resp.headers.get("Content-Disposition", "")

    def test_ekstrak_unggahan_teks_dengan_passphrase(self, client, tmp_path):
        # Sisipkan memakai passphrase kustom di luar rute.
        pembawa = tmp_path / "pembawa.png"
        Image.new("RGB", (160, 160), color=(1, 2, 3)).save(pembawa, format="PNG")
        hasil = tmp_path / "hasil.png"
        assert embed_message(str(pembawa), "rahasia passphrase", str(hasil),
                             passphrase=PASSPHRASE)["success"]

        token = _csrf(client)
        resp = client.post("/steganography/extract-upload", data={
            "csrf_token": token,
            "stego_image": (io.BytesIO(hasil.read_bytes()), "stego.png"),
            "passphrase": PASSPHRASE,
        }, content_type="multipart/form-data", follow_redirects=True)
        assert resp.status_code == 200
        assert "rahasia passphrase" in resp.get_data(as_text=True)

        # Tanpa passphrase pun tetap terbaca bila kunci sesi tidak dipakai
        # — gambar ini memakai passphrase, sehingga tanpa passphrase gagal.
        token = _csrf(client)
        resp = client.post("/steganography/extract-upload", data={
            "csrf_token": token,
            "stego_image": (io.BytesIO(hasil.read_bytes()), "stego.png"),
            "passphrase": "",
        }, content_type="multipart/form-data", follow_redirects=True)
        body = resp.get_data(as_text=True)
        assert "rahasia passphrase" not in body
        assert MSG.STEGO_KEY_REQUIRED.split(".")[0] in body or \
            MSG.STEGO_TAMPERED.split(".")[0] in body

    def test_unggahan_bukan_gambar_stego_ditolak(self, client):
        biasa = _gambar_png(60)
        token = _csrf(client)
        resp = client.post("/steganography/extract-upload", data={
            "csrf_token": token,
            "stego_image": (io.BytesIO(biasa), "biasa.png"),
            "passphrase": "",
        }, content_type="multipart/form-data", follow_redirects=True)
        assert MSG.STEGO_NO_MESSAGE in resp.get_data(as_text=True)

    def test_ekstraksi_teks_lewat_json_dan_tampil_di_halaman(self, client):
        token = _csrf(client)
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_gambar_png()), "pembawa.png"),
            "payload_type": "text",
            "message": "pesan json tersembunyi",
        }, content_type="multipart/form-data")
        assert resp.status_code == 302

        from database.db import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM stego_images WHERE user_id=1"
            ).fetchone()

        token = _csrf(client)
        hasil = client.post(f"/steganography/extract/{row['id']}", data={
            "csrf_token": token,
        })
        assert hasil.status_code == 200
        assert hasil.is_json
        data = hasil.get_json()
        assert data["success"] is True
        assert data["type"] == "text"
        assert data["text"] == "pesan json tersembunyi"
        assert data["encrypted"] is True
        assert hasil.headers.get("X-Cryptix-Extract") == "text"

    def test_kunci_otomatis_dek_dapat_diekstrak(self, client):
        token = _csrf(client)
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_gambar_png()), "pembawa.png"),
            "payload_type": "text",
            "key_mode": "account",
            "message": "kunci akun otomatis",
        }, content_type="multipart/form-data")
        assert resp.status_code == 302

        from database.db import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM stego_images WHERE user_id=1"
            ).fetchone()
        token = _csrf(client)
        hasil = client.post(f"/steganography/extract/{row['id']}", data={
            "csrf_token": token,
        })
        assert hasil.status_code == 200
        assert hasil.get_json()["text"] == "kunci akun otomatis"

    def test_sisip_teks_dengan_passphrase_lalu_ekstrak(self, client):
        token = _csrf(client)
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_gambar_png()), "pembawa.png"),
            "payload_type": "text",
            "key_mode": "passphrase",
            "passphrase": PASSPHRASE,
            "message": "pesan dengan passphrase",
        }, content_type="multipart/form-data")
        assert resp.status_code == 302

        from database.db import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT stored_name FROM stego_images WHERE user_id=1"
            ).fetchone()
        with open(os.path.join(config.STEGO_IMAGES_DIR, row["stored_name"]), "rb") as f:
            png_bytes = f.read()

        token = _csrf(client)
        benar = client.post("/steganography/extract-upload", data={
            "csrf_token": token,
            "stego_image": (io.BytesIO(png_bytes), "stego.png"),
            "passphrase": PASSPHRASE,
        }, content_type="multipart/form-data")
        assert benar.status_code == 200
        assert benar.get_json()["text"] == "pesan dengan passphrase"

        token = _csrf(client)
        salah = client.post("/steganography/extract-upload", data={
            "csrf_token": token,
            "stego_image": (io.BytesIO(png_bytes), "stego.png"),
            "passphrase": "passphrase-salah",
        }, content_type="multipart/form-data")
        assert salah.status_code == 400
        assert salah.is_json
        assert salah.get_json()["success"] is False
        assert salah.get_json()["error"] in {
            MSG.STEGO_TAMPERED, MSG.STEGO_DECRYPT_FAILED,
        }

    def test_sisip_berkas_dengan_passphrase_lalu_ekstrak(self, client):
        isi = b"berkas rahasia dengan passphrase " * 8
        token = _csrf(client)
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_gambar_png(180)), "pembawa.png"),
            "payload_type": "file",
            "key_mode": "passphrase",
            "passphrase": PASSPHRASE,
            "payload_file": (io.BytesIO(isi), "rahasia.txt"),
        }, content_type="multipart/form-data")
        assert resp.status_code == 302

        from database.db import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT stored_name FROM stego_images WHERE user_id=1"
            ).fetchone()
        with open(os.path.join(config.STEGO_IMAGES_DIR, row["stored_name"]), "rb") as f:
            png_bytes = f.read()

        sebelum = set(os.listdir(config.TEMPORARY_FILES_DIR))
        token = _csrf(client)
        hasil = client.post("/steganography/extract-upload", data={
            "csrf_token": token,
            "stego_image": (io.BytesIO(png_bytes), "stego.png"),
            "passphrase": PASSPHRASE,
        }, content_type="multipart/form-data")
        assert hasil.status_code == 200
        assert hasil.data == isi
        assert "rahasia.txt" in hasil.headers.get("Content-Disposition", "")
        assert set(os.listdir(config.TEMPORARY_FILES_DIR)) == sebelum

        token = _csrf(client)
        salah = client.post("/steganography/extract-upload", data={
            "csrf_token": token,
            "stego_image": (io.BytesIO(png_bytes), "stego.png"),
            "passphrase": "passphrase-salah",
        }, content_type="multipart/form-data")
        assert salah.status_code == 400
        assert salah.is_json

    def test_kapasitas_terlampaui_lewat_rute(self, client):
        token = _csrf(client)
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_gambar_png(20)), "kecil.png"),
            "payload_type": "text",
            "message": "A" * 500,
        }, content_type="multipart/form-data", follow_redirects=True)
        assert resp.status_code == 200
        assert "terlalu besar" in resp.get_data(as_text=True).lower()

    def test_passphrase_tidak_disimpan_di_session(self, client):
        token = _csrf(client)
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(_gambar_png()), "pembawa.png"),
            "payload_type": "text",
            "key_mode": "passphrase",
            "passphrase": PASSPHRASE,
            "message": "jangan simpan passphrase",
        }, content_type="multipart/form-data")
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert PASSPHRASE not in str(dict(sess))
        assert PASSPHRASE not in resp.headers.get("Set-Cookie", "")

    def test_halaman_memakai_js_eksternal_dan_panel_hasil(self, client):
        body = client.get("/steganography").get_data(as_text=True)
        assert 'id="stego-result"' in body
        assert "js/steganography.js" in body
        assert "onchange=" not in body
        assert "oninput=" not in body
        assert "onsubmit=" not in body
        assert "<script>" not in body
        assert 'type="password"' in body
