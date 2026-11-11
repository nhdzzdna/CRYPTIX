"""
tests/test_uc1_wajah.py
───────────────────────
Uji sesi UC1 Bagian 1: penyaringan deteksi wajah palsu, keputusan wajah
sekunder berbasis frame, dan pemeriksaan mata terbuka pada pendaftaran
maupun verifikasi login.
"""

import numpy as np
import pytest

import config
from database.db import get_db, init_db
from modules.authentication import face_recognition as face_mod
from modules.authentication.password_hash import hash_password
from modules.strings import MSG

DEK = bytes(range(32))


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "wajah_uc1.db"))
    monkeypatch.setattr(config, "STORAGE_ROOT", str(tmp_path / "storage"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "FACE_CONFIDENCE_THRESHOLD", 70.0)
    init_db()
    pw_hash, salt = hash_password("Rahasia-Wajah-UC1-2026!")
    with get_db() as db:
        db.execute(
            "INSERT INTO users (id, username, email, password_hash, salt) "
            "VALUES (?,?,?,?,?)",
            (1, "pengguna_uc1", "uc1@contoh.test", pw_hash, salt),
        )
        db.commit()
    return None


class _Cascade:
    """Cascade palsu yang mengembalikan daftar kotak tetap."""

    def __init__(self, kotak):
        self.kotak = list(kotak)

    def detectMultiScale(self, _abu, **_kwargs):
        return list(self.kotak)


def _pasang_cascade(monkeypatch, kotak):
    monkeypatch.setattr(face_mod, "_get_cascade", lambda: _Cascade(kotak))


def _pasang_deteksi(monkeypatch, mata=True):
    monkeypatch.setattr(face_mod, "_decode_frame", lambda item: item)
    monkeypatch.setattr(
        face_mod, "_deteksi_semua_wajah",
        lambda frame: [np.full((200, 200), 7, dtype=np.uint8)],
    )
    monkeypatch.setattr(face_mod, "_mata_terbuka", lambda roi: mata)


class TestDeteksiWajah:
    def test_satu_wajah_dan_kandidat_palsu_kecil_lolos(self, monkeypatch):
        # Kotak besar adalah wajah utama; kotak kecil di latar hanya deteksi
        # palsu karena luasnya jauh di bawah 40% wajah terbesar.
        _pasang_cascade(monkeypatch, [(40, 40, 120, 120), (5, 5, 20, 20)])
        frame = np.zeros((240, 240, 3), dtype=np.uint8)
        hasil = face_mod._deteksi_semua_wajah(frame)
        assert len(hasil) == 1

    def test_dua_wajah_sebanding_dihitung_dua(self, monkeypatch):
        _pasang_cascade(monkeypatch, [(10, 10, 80, 80), (150, 10, 80, 80)])
        frame = np.zeros((240, 240, 3), dtype=np.uint8)
        assert len(face_mod._deteksi_semua_wajah(frame)) == 2


class TestMataTerbuka:
    def test_dua_kotak_mata_tak_tumpang_tindih_lolos(self, monkeypatch):
        kotak = [(10, 10, 20, 20), (60, 10, 20, 20)]
        monkeypatch.setattr(
            face_mod, "_get_cascade_mata", lambda nama="": _Cascade(kotak)
        )
        roi = np.full((200, 200), 5, dtype=np.uint8)
        assert face_mod._mata_terbuka(roi) is True

    def test_kacamata_memakai_cascade_cadangan(self, monkeypatch):
        def _cascade(nama=""):
            if nama == face_mod._CASCADE_MATA_CADANGAN:
                return _Cascade([(10, 10, 20, 20), (60, 10, 20, 20)])
            return _Cascade([])

        monkeypatch.setattr(face_mod, "_get_cascade_mata", _cascade)
        roi = np.full((200, 200), 5, dtype=np.uint8)
        assert face_mod._mata_terbuka(roi) is True

    def test_tanpa_kotak_mata_dianggap_tertutup(self, monkeypatch):
        monkeypatch.setattr(
            face_mod, "_get_cascade_mata", lambda nama="": _Cascade([])
        )
        roi = np.full((200, 200), 5, dtype=np.uint8)
        assert face_mod._mata_terbuka(roi) is False


class TestPendaftaran:
    def test_frame_dengan_kandidat_palsu_tetap_lolos(self, app, monkeypatch):
        monkeypatch.setattr(face_mod, "_decode_frame", lambda item: item)

        def _wajah(frame):
            nilai = int(str(frame).split("-")[1]) % 256
            return [np.full((200, 200), nilai, dtype=np.uint8)]

        monkeypatch.setattr(face_mod, "_deteksi_semua_wajah", _wajah)
        monkeypatch.setattr(face_mod, "_mata_terbuka", lambda roi: True)
        hasil = face_mod.daftarkan_wajah(
            1, [f"frame-{i}" for i in range(30)], DEK
        )
        assert hasil["success"] is True, hasil
        assert hasil["sampel"] == 30

    def test_mata_tertutup_dibuang_dari_sampel(self, app, monkeypatch):
        monkeypatch.setattr(face_mod, "_decode_frame", lambda item: item)

        def _wajah(frame):
            nilai = int(str(frame).split("-")[1]) % 256
            return [np.full((200, 200), nilai, dtype=np.uint8)]

        monkeypatch.setattr(face_mod, "_deteksi_semua_wajah", _wajah)
        nomor = {"n": 0}

        def _mata(roi):
            nomor["n"] += 1
            return nomor["n"] > 5

        monkeypatch.setattr(face_mod, "_mata_terbuka", _mata)
        hasil = face_mod.daftarkan_wajah(
            1, [f"frame-{i}" for i in range(30)], DEK
        )
        assert hasil["success"] is True, hasil
        assert hasil["sampel"] == 25

    def test_semua_frame_mata_tertutup_ditolak(self, app, monkeypatch):
        _pasang_deteksi(monkeypatch, mata=False)
        hasil = face_mod.daftarkan_wajah(
            1, [f"frame-{i}" for i in range(30)], DEK
        )
        assert hasil["success"] is False
        assert hasil["error"] == MSG.FACE_ENROLL_EYES_CLOSED


class TestVerifikasi:
    def _siapkan(self, monkeypatch, mata_per_frame, confidence):
        samples = [
            np.full((200, 200), nilai, dtype=np.uint8)
            for nilai in range(1, 6)
        ]
        face_mod._simpan_template(1, DEK, samples)
        daftar_mata = iter(mata_per_frame)
        monkeypatch.setattr(face_mod, "_decode_frame", lambda item: item)
        monkeypatch.setattr(
            face_mod, "_deteksi_roi",
            lambda frame: np.full((200, 200), 9, dtype=np.uint8),
        )
        monkeypatch.setattr(
            face_mod, "_mata_terbuka", lambda roi: next(daftar_mata)
        )
        daftar_conf = iter(confidence)
        monkeypatch.setattr(face_mod, "_latih", lambda samples: object())
        monkeypatch.setattr(
            face_mod, "_prediksi", lambda pen, roi: float(next(daftar_conf))
        )

    def test_mata_tertutup_ditolak_dengan_kode(self, app, monkeypatch):
        self._siapkan(monkeypatch, [False] * 5, [10] * 5)
        hasil = face_mod.verifikasi_wajah(
            1, [f"v-{i}" for i in range(5)], dek=DEK
        )
        assert hasil["success"] is False
        assert hasil["code"] == "mata_tertutup"
        assert hasil["error"] == MSG.FACE_EYES_CLOSED

    def test_tiga_dari_lima_mata_terbuka_ditolak(self, app, monkeypatch):
        self._siapkan(monkeypatch, [True, True, True, False, False], [10] * 5)
        hasil = face_mod.verifikasi_wajah(
            1, [f"v-{i}" for i in range(5)], dek=DEK
        )
        assert hasil["success"] is False
        assert hasil["code"] == "mata_tertutup"

    def test_empat_dari_lima_mata_terbuka_lolos(self, app, monkeypatch):
        self._siapkan(monkeypatch, [True, True, True, True, False], [10] * 5)
        hasil = face_mod.verifikasi_wajah(
            1, [f"v-{i}" for i in range(5)], dek=DEK
        )
        assert hasil["success"] is True, hasil
