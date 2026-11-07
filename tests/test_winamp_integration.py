"""
tests/test_winamp_integration.py
────────────────────────────────
Uji integrasi Winamp: nama berkas sementara acak, timer 60 detik, pembersihan
startup/atexit, penimpaan nol, batas direktori, dan penanganan error hapus.
"""

import inspect
import os

import pytest

import config
from modules.media import winamp_integration as winamp


@pytest.fixture(autouse=True)
def _siapkan(monkeypatch, tmp_path):
    monkeypatch.setattr(
        config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary_files")
    )
    winamp._ACTIVE_TEMP_FILES.clear()
    yield
    for path in list(winamp._ACTIVE_TEMP_FILES):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass
    winamp._ACTIVE_TEMP_FILES.clear()


def _tulis_sementara(nama: str = "lagu-rahasia.mp3", isi: bytes = b"audio") -> str:
    return winamp.save_temp_audio(isi, nama)


class TestNamaSementara:
    def test_nama_acak_tidak_memakai_nama_asli(self):
        nama = winamp._random_temp_name("lagu rahasia.mp3")
        assert nama.startswith("cryptix_winamp_")
        assert nama.endswith(".mp3")
        assert "lagu" not in nama.lower()
        assert "rahasia" not in nama.lower()

    def test_ekstensi_tidak_aman_dibuang(self):
        nama = winamp._random_temp_name("berkas.evil/../x")
        assert nama.startswith("cryptix_winamp_")
        assert "/" not in nama and "\\" not in nama

    def test_save_temp_audio_menulis_isi(self):
        path = _tulis_sementara(isi=b"isi-audio")
        assert os.path.dirname(os.path.abspath(path)) == os.path.abspath(
            config.TEMPORARY_FILES_DIR
        )
        assert os.path.basename(path) != "lagu-rahasia.mp3"
        with open(path, "rb") as handle:
            assert handle.read() == b"isi-audio"


class TestPembersihan:
    def test_cleanup_menimpa_nol_lalu_menghapus(self, monkeypatch):
        path = _tulis_sementara()
        dipanggil = {"path": None}
        asli = winamp._zero_overwrite

        def _spy(target):
            dipanggil["path"] = target
            return asli(target)

        monkeypatch.setattr(winamp, "_zero_overwrite", _spy)
        assert winamp.cleanup_temp_file(path) is True
        assert dipanggil["path"] == path
        assert not os.path.exists(path)

    def test_cleanup_menolak_path_di_luar_direktori(self, tmp_path):
        luar = tmp_path / "berkas-luar.txt"
        luar.write_bytes(b"jangan dihapus")
        assert winamp.cleanup_temp_file(str(luar)) is False
        assert luar.exists()

    def test_cleanup_menangani_error_penghapusan(self, monkeypatch):
        path = _tulis_sementara()
        monkeypatch.setattr(
            os, "remove", lambda _p: (_ for _ in ()).throw(PermissionError())
        )
        assert winamp.cleanup_temp_file(path) is False
        assert os.path.exists(path)

    def test_timer_default_60_detik(self):
        parameter = inspect.signature(winamp._schedule_delete).parameters
        assert parameter["delay_seconds"].default == 60

    def test_penjadwalan_menghapus_berkas(self):
        path = _tulis_sementara()
        thread = winamp._schedule_delete(path, delay_seconds=0.05)
        thread.join(2)
        assert not os.path.exists(path)

    def test_cleanup_stale_hanya_prefix_cryptix(self):
        os.makedirs(config.TEMPORARY_FILES_DIR, exist_ok=True)
        sisa = os.path.join(config.TEMPORARY_FILES_DIR, "cryptix_winamp_sisa.mp3")
        lain = os.path.join(config.TEMPORARY_FILES_DIR, "stego_in_lain.png")
        for path in (sisa, lain):
            with open(path, "wb") as handle:
                handle.write(b"x")

        assert winamp.cleanup_stale_temp_files() == 1
        assert not os.path.exists(sisa)
        assert os.path.exists(lain)

    def test_atexit_membersihkan_berkas_aktif(self):
        path = _tulis_sementara()
        assert path in winamp._ACTIVE_TEMP_FILES
        winamp._cleanup_active_temp_files()
        assert not os.path.exists(path)
        assert path not in winamp._ACTIVE_TEMP_FILES


class TestWinamp:
    def test_tidak_tersedia(self, monkeypatch, tmp_path):
        monkeypatch.setattr(config, "WINAMP_PATH", str(tmp_path / "tidak-ada.exe"))
        hasil = winamp.play_with_winamp("x.mp3")
        assert hasil["success"] is False
        assert hasil["winamp_available"] is False

    def test_membuka_winamp_dan_menjadwalkan_hapus(self, monkeypatch, tmp_path):
        palsu = tmp_path / "winamp.exe"
        palsu.write_bytes(b"x")
        monkeypatch.setattr(config, "WINAMP_PATH", str(palsu))
        dipanggil = {}
        monkeypatch.setattr(
            winamp.subprocess, "Popen",
            lambda args: dipanggil.setdefault("args", args),
        )
        dijadwalkan = {}
        monkeypatch.setattr(
            winamp, "_schedule_delete",
            lambda path, delay_seconds=60: dijadwalkan.update(
                {"path": path, "delay": delay_seconds}
            ),
        )

        hasil = winamp.play_with_winamp("berkas.mp3")
        assert hasil["success"] is True
        assert dipanggil["args"][-1] == "berkas.mp3"
        assert dijadwalkan == {"path": "berkas.mp3", "delay": 60}

    def test_menangani_kegagalan_menjalankan_winamp(self, monkeypatch, tmp_path):
        palsu = tmp_path / "winamp.exe"
        palsu.write_bytes(b"x")
        monkeypatch.setattr(config, "WINAMP_PATH", str(palsu))

        def _gagal(_args):
            raise OSError("gagal")

        monkeypatch.setattr(winamp.subprocess, "Popen", _gagal)
        hasil = winamp.play_with_winamp("berkas.mp3")
        assert hasil["success"] is False
        assert hasil["winamp_available"] is True
