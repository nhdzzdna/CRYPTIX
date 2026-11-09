"""
modules/username_masking.py
──────────────────────────
Penyamar username untuk tampilan daftar tanpa membocorkan nilai lengkap.

Aturan:
  - email "ab@domain"   -> "ab***@domain"
  - bukan email "abcd"  -> "ab***"
  - nilai sangat pendek -> "***" (atau "***@domain" bila domain tersedia)
"""


def samarkan_username(nilai) -> str:
    """Kembalikan bentuk tersamar yang aman untuk ditampilkan di daftar."""
    teks = str(nilai or "").strip()
    if not teks:
        return "***"

    if "@" in teks:
        lokal, domain = teks.split("@", 1)
        if domain:
            if len(lokal) < 2:
                return "***@" + domain
            return lokal[:2] + "***@" + domain

    if len(teks) < 2:
        return "***"
    return teks[:2] + "***"
