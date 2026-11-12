"""
tests/test_u2e_spacing.py
─────────────────────────
Kontrak jarak antarelemen aksi dan keadaan tersembunyi bawaan (U2e).

Uji ini hanya membaca berkas CSS/template sehingga tidak memerlukan peramban.
"""

import re
from pathlib import Path

AKAR = Path(__file__).resolve().parents[1]
CSS_HALAMAN = AKAR / "static" / "css" / "halaman"


def _baca(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _blok(css: str, selektor: str) -> str:
    pola = re.escape(selektor) + r"\s*\{(.*?)\}"
    cocok = re.search(pola, css, re.S)
    assert cocok, f"Selektor {selektor} tidak ditemukan"
    return cocok.group(1)


def test_tombol_bar_aksi_mengambang_berjarak():
    css = _baca(AKAR / "static" / "css" / "components.css")
    isi = _blok(css, ".kx-aksi-mengambang-tombol")
    assert "display: flex" in isi
    assert "gap: var(--kx-space-2)" in isi


def test_css_halaman_bebas_token_jarak_tak_terdefinisi():
    for path in CSS_HALAMAN.glob("*.css"):
        css = _baca(path)
        assert "--kx-sp-" not in css, f"Token jarak tak terdefinisi di {path.name}"


def test_settings_form_dan_aksi_berjarak():
    css = _baca(CSS_HALAMAN / "settings.css")
    form = _blok(css, ".kx-settings-page .kx-card-body > form")
    assert "gap: var(--kx-space-3)" in form
    aksi = _blok(css, ".kx-settings-page .kx-card-actions")
    assert "gap: var(--kx-space-2)" in aksi


def test_aksi_item_account_vault_berjarak():
    css = _baca(CSS_HALAMAN / "account_vault.css")
    for selektor in (".kx-av-aksi", ".kx-av-reveal-aksi"):
        isi = _blok(css, selektor)
        assert "gap: var(--kx-space-2)" in isi


def test_keadaan_awal_tersembunyi():
    stego = _baca(AKAR / "templates" / "steganography.html")
    assert re.search(r'id="sg-berkas-field"[^>]*\bhidden\b', stego)
    assert re.search(r'id="sg-kunci-rahasia-field"[^>]*\bhidden\b', stego)

    settings = _baca(AKAR / "templates" / "settings.html")
    for pane in ("pane-keamanan", "pane-biometrik", "pane-sesi", "pane-akun"):
        assert re.search(r'id="' + pane + r'"[^>]*\bhidden\b', settings)

    media = _baca(AKAR / "templates" / "media_vault.html")
    assert re.search(r'id="album-detail"[^>]*\bhidden\b', media)
