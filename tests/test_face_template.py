"""
tests/test_face_template.py
───────────────────────────
Uji butir 2.6: pendaftaran wajah di wizard (30 frame/3 detik, minimal 25
sampel valid), template terenkripsi di biometric_templates, verifikasi
5 frame, penolakan gambar beku, dan tahap 2 login akun hanya-wajah.

Deteksi wajah dan LBPH diganti tiruan deterministik agar pengujian tidak
bergantung pada kamera atau berkas citra.
"""

import hashlib
import json
import os
import re

import numpy as np
import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import biometrics, face_recognition as face_mod
from modules.authentication import usb_authentication as usb_mod
from modules.authentication.auth import create_account
from modules.blockchain import blockchain as bc
from modules.cryptography.key_management import unlock_dek
from modules.strings import MSG

KATA_SANDI = "Rahasia-Wajah-2026!"
USERNAME = "pengguna_wajah"
EMAIL = "wajah@contoh.test"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "wajah.db"))
    monkeypatch.setattr(config, "STORAGE_ROOT", str(tmp_path / "storage"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "KEK_PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(config, "FACE_CONFIDENCE_THRESHOLD", 70.0)
    monkeypatch.setattr(config, "BIOMETRIC_POLICY", "all_enrolled")
    monkeypatch.setattr(config, "CRYPTIX_DEV_MODE", True)
    monkeypatch.setattr(config, "DEV_DONGLE_DIR", str(tmp_path / "dongle"))
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    monkeypatch.setattr(usb_mod, "_get_removable_drives", lambda: [])
    init_db()
    token = usb_mod.register_usb_token(str(tmp_path / "dongle"))
    assert token is not None
    hasil = create_account(USERNAME, EMAIL, KATA_SANDI, token)
    assert hasil["success"], hasil
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def pengguna():
    with get_db() as db:
        baris = db.execute(
            "SELECT * FROM users WHERE username=?", (USERNAME,)
        ).fetchone()
    return dict(baris)


@pytest.fixture()
def dek(pengguna, tmp_path):
    path = os.path.join(str(tmp_path / "dongle"), config.USB_TOKEN_FILENAME)
    with open(path, encoding="utf-8") as handle:
        rahasia = bytes.fromhex(json.load(handle)["secret"])
    return unlock_dek(KATA_SANDI, rahasia, pengguna)


def _nilai(teks: str) -> int:
    return int(hashlib.sha256(teks.encode("utf-8")).hexdigest(), 16) % 256


def _pasang_deteksi(monkeypatch):
    monkeypatch.setattr(face_mod, "_decode_frame", lambda item: item)

    def _roi(frame):
        if frame is None:
            return None
        return np.full((200, 200), _nilai(str(frame)), dtype=np.uint8)

    def _wajah(frame):
        roi = _roi(frame)
        return [] if roi is None else [roi]

    monkeypatch.setattr(face_mod, "_deteksi_roi", _roi)
    # Pendaftaran memakai deteksi seluruh wajah agar dapat menolak frame
    # tanpa wajah atau dengan lebih dari satu wajah.
    monkeypatch.setattr(face_mod, "_deteksi_semua_wajah", _wajah)
    # Mata dianggap terbuka pada data sintetis; kasus mata tertutup diuji
    # terpisah dengan fungsi ini dimock secara eksplisit.
    monkeypatch.setattr(face_mod, "_mata_terbuka", lambda roi: True)


def _konfidensi(monkeypatch, angka):
    daftar = iter(angka)
    monkeypatch.setattr(face_mod, "_latih", lambda samples: object())
    monkeypatch.setattr(face_mod, "_prediksi", lambda pen, roi: float(next(daftar)))


def _daftar(uid, dek, monkeypatch, n=30):
    _pasang_deteksi(monkeypatch)
    return face_mod.daftarkan_wajah(
        uid, [f"frame-{i}" for i in range(n)], dek
    )


def _csrf(client, halaman="/login") -> str:
    body = client.get(halaman).get_data(as_text=True)
    cocok = re.search(r'<meta name="csrf-token" content="([^"]+)"', body)
    assert cocok, "meta csrf-token tidak ditemukan"
    return cocok.group(1)


class TestDeteksiWajah:
    def _pasang_cascade(self, monkeypatch, kotak):
        class _Cascade:
            def detectMultiScale(self, _abu, **_kwargs):
                return list(kotak)

        monkeypatch.setattr(face_mod, "_get_cascade", lambda: _Cascade())

    def test_kotak_tumpang_tindih_dihitung_satu_wajah(self, monkeypatch):
        # Beberapa bounding box bertumpang tindih untuk satu wajah yang sama.
        self._pasang_cascade(monkeypatch, [
            (50, 60, 120, 120),
            (54, 63, 118, 117),
            (48, 58, 110, 112),
        ])
        frame = np.zeros((240, 240, 3), dtype=np.uint8)
        hasil = face_mod._deteksi_semua_wajah(frame)
        assert len(hasil) == 1
        assert hasil[0].shape == (200, 200)

    def test_dua_wajah_berbeda_dihitung_dua_wajah(self, monkeypatch):
        self._pasang_cascade(monkeypatch, [
            (10, 10, 80, 80),
            (150, 10, 80, 80),
        ])
        frame = np.zeros((240, 240, 3), dtype=np.uint8)
        hasil = face_mod._deteksi_semua_wajah(frame)
        assert len(hasil) == 2
        assert all(roi.shape == (200, 200) for roi in hasil)

    def test_registrasi_menolak_frame_lebih_dari_satu_wajah(
        self, app, pengguna, dek, monkeypatch
    ):
        monkeypatch.setattr(face_mod, "_decode_frame", lambda item: item)
        roi = np.full((200, 200), 9, dtype=np.uint8)
        # Setiap frame benar-benar berisi dua wajah berbeda.
        monkeypatch.setattr(
            face_mod, "_deteksi_semua_wajah", lambda frame: [roi, roi]
        )
        monkeypatch.setattr(face_mod, "_mata_terbuka", lambda roi: True)
        hasil = face_mod.daftarkan_wajah(
            pengguna["id"], [f"frame-{i}" for i in range(30)], dek
        )
        assert hasil["success"] is False
        assert hasil["error"] == MSG.FACE_MULTIPLE_FACES


class TestPendaftaran:
    def test_pendaftaran_sukses_dan_terenkripsi(self, app, pengguna, dek,
                                                monkeypatch):
        hasil = _daftar(pengguna["id"], dek, monkeypatch)
        assert hasil["success"] is True, hasil
        assert hasil["sampel"] == 30

        with get_db() as db:
            baris = db.execute(
                "SELECT metode, template, sampel FROM biometric_templates "
                "WHERE user_id=?", (pengguna["id"],),
            ).fetchone()
        blob = bytes(baris["template"])
        assert baris["metode"] == "wajah"
        assert baris["sampel"] == 30
        assert blob.startswith(b"FG1")
        assert b"frame" not in blob
        assert "wajah" in biometrics.metode_biometrik_terdaftar(pengguna["id"])

        # hanya DEK pengguna yang dapat membuka template
        assert face_mod._buka_template(dek, pengguna["id"], blob)
        with pytest.raises(ValueError):
            face_mod._buka_template(os.urandom(32), pengguna["id"], blob)

        # penyimpanan wajah lama tidak dibuat
        assert not os.path.exists(os.path.join(config.STORAGE_ROOT, "face_data"))

    def test_sampel_kurang_dari_25_ditolak(self, app, pengguna, dek,
                                           monkeypatch):
        monkeypatch.setattr(face_mod, "_decode_frame", lambda item: item)
        # 24 dari 30 frame terdeteksi (tepat 80%) sehingga lolos ambang
        # deteksi, tetapi jumlah sampel masih di bawah 25.
        monkeypatch.setattr(
            face_mod, "_deteksi_roi",
            lambda frame: None if int(str(frame).split("-")[1]) >= 24
            else np.full((200, 200), 7, dtype=np.uint8),
        )
        monkeypatch.setattr(
            face_mod, "_deteksi_semua_wajah",
            lambda frame: [] if int(str(frame).split("-")[1]) >= 24
            else [np.full((200, 200), 7, dtype=np.uint8)],
        )
        monkeypatch.setattr(face_mod, "_mata_terbuka", lambda roi: True)
        hasil = face_mod.daftarkan_wajah(
            pengguna["id"], [f"frame-{i}" for i in range(30)], dek
        )
        assert hasil["success"] is False
        assert hasil["error"] == MSG.FACE_NOT_ENOUGH_SAMPLES

    def test_variasi_terlalu_rendah_ditolak(self, app, pengguna, dek,
                                            monkeypatch):
        _pasang_deteksi(monkeypatch)
        hasil = face_mod.daftarkan_wajah(
            pengguna["id"], ["sama"] * 30, dek
        )
        assert hasil["success"] is False
        assert "Variasi" in hasil["error"]


class TestVerifikasi:
    def test_tiga_dari_lima_lolos_diterima(self, app, pengguna, dek,
                                           monkeypatch):
        assert _daftar(pengguna["id"], dek, monkeypatch)["success"] is True
        _pasang_deteksi(monkeypatch)
        _konfidensi(monkeypatch, [10, 20, 30, 100, 100])
        hasil = face_mod.verifikasi_wajah(
            pengguna["id"], [f"v-{i}" for i in range(5)], dek=dek
        )
        assert hasil["success"] is True, hasil
        assert hasil["lolos"] == 3
        assert hasil["median"] == 30.0

    def test_kurang_dari_tiga_lolos_ditolak(self, app, pengguna, dek,
                                            monkeypatch):
        assert _daftar(pengguna["id"], dek, monkeypatch)["success"] is True
        _pasang_deteksi(monkeypatch)
        _konfidensi(monkeypatch, [10, 100, 100, 100, 100])
        hasil = face_mod.verifikasi_wajah(
            pengguna["id"], [f"v-{i}" for i in range(5)], dek=dek
        )
        assert hasil["success"] is False

    def test_gambar_beku_ditolak(self, app, pengguna, dek, monkeypatch):
        assert _daftar(pengguna["id"], dek, monkeypatch)["success"] is True
        _pasang_deteksi(monkeypatch)
        _konfidensi(monkeypatch, [10, 20, 30, 40, 50])
        hasil = face_mod.verifikasi_wajah(
            pengguna["id"], ["beku"] * 5, dek=dek
        )
        assert hasil["success"] is False
        assert hasil["beku"] is True

    def test_wajah_ikut_registri_stage_dua(self, app, pengguna, dek,
                                           monkeypatch):
        assert _daftar(pengguna["id"], dek, monkeypatch)["success"] is True
        assert biometrics.metode_biometrik_terdaftar(pengguna["id"]) == ["wajah"]
        _pasang_deteksi(monkeypatch)
        _konfidensi(monkeypatch, [10, 20, 30, 100, 100])
        hasil = biometrics.verifikasi_tahap_biometrik(
            pengguna["id"],
            {"wajah": [f"v-{i}" for i in range(5)]},
            konteks={"dek": dek},
        )
        assert hasil == {"wajah": True}


class TestRuteWajah:
    def test_login_akun_hanya_wajah_menyelesaikan_tahap_dua(
        self, app, client, pengguna, dek, monkeypatch
    ):
        assert _daftar(pengguna["id"], dek, monkeypatch)["success"] is True
        csrf = _csrf(client)
        tahap1 = client.post(
            "/login",
            json={"username": USERNAME, "password": KATA_SANDI},
            headers={"X-CSRFToken": csrf},
        ).get_json()
        assert tahap1["success"] is True, tahap1
        assert [m["nama"] for m in tahap1["metode"]] == ["wajah"]

        _pasang_deteksi(monkeypatch)
        _konfidensi(monkeypatch, [10, 20, 30, 100, 100])
        tahap2 = client.post(
            "/login/biometric",
            json={
                "pending": tahap1["pending"],
                "bukti": {"wajah": [f"v-{i}" for i in range(5)]},
            },
            headers={"X-CSRFToken": csrf},
        )
        assert tahap2.status_code == 200, tahap2.get_data(as_text=True)
        assert tahap2.get_json()["success"] is True
        with client.session_transaction() as sess:
            assert sess["user_id"] == pengguna["id"]

    def test_verify_face_tanpa_tahap_login_ditolak(self, app, client):
        csrf = _csrf(client)
        resp = client.post(
            "/api/verify_face",
            json={"username": USERNAME, "frames": ["a"] * 5},
            headers={"X-CSRFToken": csrf},
        )
        assert resp.status_code == 401
        assert resp.get_json()["success"] is False

    def test_verify_face_pada_sesi_login_menampilkan_confidence(
        self, app, client, pengguna, dek, monkeypatch
    ):
        assert _daftar(pengguna["id"], dek, monkeypatch)["success"] is True
        csrf = _csrf(client)
        tahap1 = client.post(
            "/login",
            json={"username": USERNAME, "password": KATA_SANDI},
            headers={"X-CSRFToken": csrf},
        ).get_json()
        assert tahap1["success"] is True, tahap1

        _pasang_deteksi(monkeypatch)
        _konfidensi(monkeypatch, [10, 20, 30, 100, 100])
        resp = client.post(
            "/api/verify_face",
            json={
                "pending": tahap1["pending"],
                "frames": [f"v-{i}" for i in range(5)],
            },
            headers={"X-CSRFToken": csrf},
        )
        data = resp.get_json()
        assert resp.status_code == 200, data
        assert data["success"] is True
        assert data["verified"] is True
        assert data["confidences"] == [10.0, 20.0, 30.0, 100.0, 100.0]
        assert data["median"] == 30.0
