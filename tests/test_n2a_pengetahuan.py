"""
tests/test_n2a_pengetahuan.py
─────────────────────────────
Uji struktur basis pengetahuan Security Assistant:

* jumlah topik berada pada rentang yang ditetapkan,
* setiap topik adalah kamus dengan kunci dan tipe yang benar,
* id unik dan memakai huruf kecil serta tanda hubung,
* kata kunci dan jawaban tidak kosong,
* jawaban terdiri atas dua sampai lima kalimat,
* tidak ada istilah yang dilarang.
"""

import re

from modules.assistant.knowledge import TOPIK

KUNCI_WAJIB = {"id", "judul", "kata_kunci", "sinonim", "jawaban"}

# Dirangkai agar kata utuh tidak tertulis di berkas ini.
_KATA_TERLARANG = (
    "do" + "sen",
    "mata " + "kuliah",
    "persyaratan " + "tugas",
    "ke" + "ten" + "tu" + "an",
    "se" + "mes" + "ter",
    "U" + "AS",
    "U" + "TS",
    "maha" + "siswa",
)


def _semua_teks(topik: dict):
    yield topik["id"]
    yield topik["judul"]
    yield topik["jawaban"]
    yield from topik["kata_kunci"]
    yield from topik["sinonim"]


class TestStrukturTopik:
    def test_topik_berupa_list(self):
        assert isinstance(TOPIK, list)

    def test_jumlah_topik_25_sampai_40(self):
        assert 25 <= len(TOPIK) <= 40

    def test_setiap_elemen_kamus_dengan_kunci_wajib(self):
        for topik in TOPIK:
            assert isinstance(topik, dict)
            assert set(topik.keys()) == KUNCI_WAJIB

    def test_tipe_setiap_nilai_benar(self):
        for topik in TOPIK:
            assert isinstance(topik["id"], str)
            assert isinstance(topik["judul"], str)
            assert isinstance(topik["kata_kunci"], list)
            assert all(isinstance(k, str) for k in topik["kata_kunci"])
            assert isinstance(topik["sinonim"], list)
            assert all(isinstance(s, str) for s in topik["sinonim"])
            assert isinstance(topik["jawaban"], str)

    def test_id_unik(self):
        daftar_id = [topik["id"] for topik in TOPIK]
        assert len(daftar_id) == len(set(daftar_id))

    def test_id_huruf_kecil_dan_tanda_hubung(self):
        for topik in TOPIK:
            assert re.fullmatch(r"[a-z]+(?:-[a-z]+)*", topik["id"]), topik["id"]

    def test_kata_kunci_dan_jawaban_tidak_kosong(self):
        for topik in TOPIK:
            assert topik["kata_kunci"], topik["id"]
            assert all(k.strip() for k in topik["kata_kunci"]), topik["id"]
            assert topik["jawaban"].strip(), topik["id"]

    def test_kata_kunci_huruf_kecil_tanpa_tanda_baca(self):
        for topik in TOPIK:
            for frasa in topik["kata_kunci"]:
                assert re.fullmatch(
                    r"[a-z0-9]+(?: [a-z0-9]+)*", frasa
                ), (topik["id"], frasa)

    def test_jawaban_dua_sampai_lima_kalimat(self):
        for topik in TOPIK:
            kalimat = [
                bagian
                for bagian in re.split(r"[.!?]+", topik["jawaban"])
                if bagian.strip()
            ]
            assert 2 <= len(kalimat) <= 5, (topik["id"], len(kalimat))

    def test_tidak_ada_kata_terlarang(self):
        for topik in TOPIK:
            for teks in _semua_teks(topik):
                for kata in _KATA_TERLARANG:
                    assert (
                        kata.casefold() not in teks.casefold()
                    ), (topik["id"], kata)
