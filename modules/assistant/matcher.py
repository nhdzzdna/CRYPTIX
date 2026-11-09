"""
modules/assistant/matcher.py
────────────────────────────
Pencocokan pertanyaan pengguna dengan basis pengetahuan Security Assistant.

Modul ini murni berbasis aturan: normalisasi teks, pencocokan frasa sinonim,
kata kunci, kata pada judul, serta toleransi salah ketik memakai
``difflib.SequenceMatcher``. Tidak ada model bahasa dan tidak ada panggilan
keluar.

Basis pengetahuan dimuat secara tertunda dari
``modules.assistant.knowledge.TOPIK``. Bila modul tersebut belum tersedia atau
``TOPIK`` kosong, fungsi tetap berjalan dan tidak menghasilkan kecocokan.
"""

from __future__ import annotations

import importlib
import re
from difflib import SequenceMatcher

# Batas panjang masukan agar pencocokan tetap ringan.
BATAS_KARAKTER = 500

# Ambang minimum skor agar sebuah topik dianggap cocok.
_AMBANG = 0.40

_KATA_HUBUNG = frozenset({
    "yang", "dan", "di", "ke", "dari", "untuk", "dengan", "itu", "ini",
    "saya", "aku", "bisa", "kah", "dong", "sih", "nih", "ya", "atau",
    "pada", "adalah",
})

_POLA_BUKAN_KATA = re.compile(r"[\W_]+", re.UNICODE)
_POLA_SPASI = re.compile(r"\s+")

# Bobot tiap jenis kecocokan.
_BOBOT_SINONIM = 1.0
_BOBOT_KATA_KUNCI = 0.55
_BOBOT_JUDUL = 0.20
_BATAS_JUDUL = 0.30
_BOBOT_TYPO_SINONIM = 0.70
_BOBOT_TYPO_KATA_KUNCI = 0.50
_BOBOT_TYPO_JUDUL = 0.15
_AMBANG_TYPO = 0.85


def normalisasi(teks: str) -> str:
    """Normalisasi teks: huruf kecil, tanpa tanda baca, spasi rapi.

    Kata hubung umum bahasa Indonesia dibuang. Masukan dipotong maksimal
    ``BATAS_KARAKTER`` karakter sebelum diproses.
    """
    if teks is None:
        return ""
    if not isinstance(teks, str):
        teks = str(teks)

    teks = teks[:BATAS_KARAKTER].lower()
    teks = _POLA_BUKAN_KATA.sub(" ", teks)
    teks = _POLA_SPASI.sub(" ", teks).strip()
    if not teks:
        return ""
    return " ".join(kata for kata in teks.split(" ") if kata not in _KATA_HUBUNG)


def muat_topik() -> list[dict]:
    """Muat ``TOPIK`` dari knowledge.py secara tertunda dan terlindungi."""
    try:
        modul = importlib.import_module("modules.assistant.knowledge")
    except Exception:
        return []

    topik = getattr(modul, "TOPIK", None)
    if not isinstance(topik, list):
        return []
    return [item for item in topik if isinstance(item, dict)]


def _daftar_frasa(nilai) -> list[str]:
    """Ubah satu nilai atau daftar nilai menjadi frasa ternormalisasi."""
    if isinstance(nilai, str):
        nilai = [nilai]
    if not isinstance(nilai, (list, tuple)):
        return []
    hasil: list[str] = []
    for item in nilai:
        frasa = normalisasi(item)
        if frasa and frasa not in hasil:
            hasil.append(frasa)
    return hasil


def _kata_terdekat(kata: str, kosakata: dict[str, float]) -> tuple[str, float]:
    """Kembalikan kata kosakata dengan rasio kemiripan tertinggi."""
    terbaik = ""
    rasio_terbaik = 0.0
    for kandidat in kosakata:
        rasio = SequenceMatcher(None, kata, kandidat).ratio()
        if rasio > rasio_terbaik:
            terbaik, rasio_terbaik = kandidat, rasio
    return terbaik, rasio_terbaik


def _skor_topik(teks: str, kata_teks: set[str], topik: dict) -> float:
    """Hitung skor mentah sebuah topik terhadap teks pertanyaan."""
    sinonim = _daftar_frasa(topik.get("sinonim"))
    kata_kunci = _daftar_frasa(topik.get("kata_kunci"))
    judul = _daftar_frasa(topik.get("judul"))

    sinonim_cocok = sum(1 for frasa in sinonim if frasa in teks)
    kunci_cocok = sum(1 for frasa in kata_kunci if frasa in teks)

    frasa_judul = " ".join(judul) if judul else ""
    kata_judul = set(frasa_judul.split()) if frasa_judul else set()
    judul_cocok = len(kata_judul & kata_teks)

    # Judul utuh yang diketik pengguna (misalnya dari tombol saran) tetap
    # bernilai rendah, tetapi cukup untuk memilih topik yang dimaksud.
    bobot_judul = 0.50 if frasa_judul and frasa_judul in teks else min(
        _BATAS_JUDUL, _BOBOT_JUDUL * judul_cocok
    )

    skor = (
        _BOBOT_SINONIM * sinonim_cocok
        + _BOBOT_KATA_KUNCI * kunci_cocok
        + bobot_judul
    )

    # Toleransi salah ketik per kata. Kata yang sudah persis ada di kosakata
    # tidak dihitung ulang agar tidak menggandakan skor.
    kosakata: dict[str, float] = {}
    for frasa in sinonim:
        for kata in frasa.split():
            kosakata[kata] = max(kosakata.get(kata, 0.0), _BOBOT_TYPO_SINONIM)
    for frasa in kata_kunci:
        for kata in frasa.split():
            kosakata[kata] = max(kosakata.get(kata, 0.0), _BOBOT_TYPO_KATA_KUNCI)
    for kata in kata_judul:
        kosakata[kata] = max(kosakata.get(kata, 0.0), _BOBOT_TYPO_JUDUL)

    for kata in kata_teks:
        if len(kata) < 4 or kata in kosakata:
            continue
        _, rasio = _kata_terdekat(kata, kosakata)
        if rasio >= _AMBANG_TYPO:
            # Ambil bobot kata terbaik yang memenuhi ambang.
            bobot = 0.0
            for kandidat in kosakata:
                if SequenceMatcher(None, kata, kandidat).ratio() >= _AMBANG_TYPO:
                    bobot = max(bobot, kosakata[kandidat])
            skor += bobot

    return skor


def _saran(daftar: list[tuple[float, dict]], batas: int) -> list[dict]:
    """Ambil hingga ``batas`` topik terdekat sebagai saran id dan judul."""
    if batas <= 0:
        return []
    urut = sorted(
        daftar,
        key=lambda item: (-item[0], str(item[1].get("id", ""))),
    )
    hasil: list[dict] = []
    for _, topik in urut[:batas]:
        judul = topik.get("judul")
        if not judul:
            continue
        hasil.append({"id": str(topik.get("id", "")), "judul": str(judul)})
    return hasil


def cari_topik(pertanyaan: str, topik: list[dict] | None = None,
               batas: int = 3) -> dict:
    """Cari topik paling cocok untuk ``pertanyaan``.

    Parameters
    ----------
    pertanyaan : str
        Pertanyaan pengguna (dipotong maksimal 500 karakter saat normalisasi).
    topik : list[dict] | None
        Daftar topik. ``None`` berarti memuat ``TOPIK`` dari knowledge.py.
    batas : int
        Jumlah maksimal saran yang dikembalikan.

    Returns
    -------
    dict
        ``{"cocok": topik|None, "skor": float, "saran": [{"id","judul"}]}``.
        ``cocok`` bernilai ``None`` bila skor terbaik berada di bawah ambang.
    """
    if topik is None:
        topik = muat_topik()

    try:
        batas = max(0, int(batas))
    except (TypeError, ValueError):
        batas = 3

    daftar_topik = [item for item in (topik or []) if isinstance(item, dict)]
    teks = normalisasi(pertanyaan)
    kata_teks = set(teks.split()) if teks else set()

    skor_per_topik: list[tuple[float, dict]] = []
    for item in daftar_topik:
        skor_per_topik.append((_skor_topik(teks, kata_teks, item), item))

    skor_terbaik = max((skor for skor, _ in skor_per_topik), default=0.0)
    kandidat = None
    for skor, item in skor_per_topik:
        jawaban = item.get("jawaban")
        if (skor >= _AMBANG and skor == skor_terbaik
                and isinstance(jawaban, str) and jawaban.strip()):
            kandidat = item
            break

    return {
        "cocok": kandidat,
        "skor": round(min(1.0, float(skor_terbaik)), 3),
        "saran": _saran(skor_per_topik, batas),
    }
