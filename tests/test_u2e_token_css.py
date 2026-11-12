"""
tests/test_u2e_token_css.py
───────────────────────────
Kontrak token CSS (U2e): setiap var(--kx-...) harus terdefinisi di tokens.css
atau pada berkas CSS yang sama.
"""

import re
from pathlib import Path

AKAR = Path(__file__).resolve().parents[1]
CSS = AKAR / "static" / "css"
BERKAS = [CSS / "tokens.css", CSS / "components.css", CSS / "base.css"]
BERKAS += sorted((CSS / "halaman").glob("*.css"))

POLA_PAKAI = re.compile(r"var\(\s*(--kx-[a-z0-9-]+)")
POLA_DEFINISI = re.compile(r"(--kx-[a-z0-9-]+)\s*:")


def _baca(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_semua_token_kx_terdefinisi():
    global_ = set(POLA_DEFINISI.findall(_baca(CSS / "tokens.css")))
    hilang = {}
    for path in BERKAS:
        css = _baca(path)
        dipakai = set(POLA_PAKAI.findall(css))
        lokal = set(POLA_DEFINISI.findall(css))
        kurang = sorted(dipakai - global_ - lokal)
        if kurang:
            hilang[path.name] = kurang

    assert not hilang, "Token --kx-* tak terdefinisi: " + repr(hilang)
