"""
modules/navigation.py
─────────────────────
Daftar menu sidebar dan konteks navigasi bersama.

Item yang endpoint-nya belum terdaftar dilewati otomatis supaya sesi halaman
yang belum selesai tidak membuat seluruh kerangka gagal dirender.
"""

from __future__ import annotations

from flask import current_app, session, url_for

from modules.cryptography import session_keys

NAV = (
    {
        "judul": "VAULT",
        "items": (
            {"label": "Dashboard", "endpoint": "dashboard.index",
             "ikon": "layout-grid", "aktif": ("dashboard.index",)},
            {"label": "Dokumen", "endpoint": "documents.index",
             "ikon": "file-text", "aktif": ("documents.index", "vault.index")},
            {"label": "Account Vault", "endpoint": "account.index",
             "ikon": "key", "aktif": ("account.index",)},
            {"label": "Media", "endpoint": "media.index",
             "ikon": "image", "aktif": ("media.index",)},
            {"label": "Audio", "endpoint": "collection.musik",
             "ikon": "headphones", "aktif": ("collection.musik", "collection.musik_lama")},
            {"label": "Secure Notes", "endpoint": "notes.index",
             "ikon": "file-text", "aktif": ("notes.index",)},
            {"label": "Sampah", "endpoint": "trash.index",
             "ikon": "trash", "aktif": ("trash.index",)},
        ),
    },
    {
        "judul": "TOOLS",
        "items": (
            {"label": "Crypto Tools", "endpoint": "crypto.index",
             "ikon": "layers", "aktif": ("crypto.index",)},
            {"label": "Steganography", "endpoint": "stego.index",
             "ikon": "file", "aktif": ("stego.index",)},
        ),
    },
    {
        "judul": "KEAMANAN",
        "items": (
            {"label": "Security Center", "endpoint": "security.index",
             "ikon": "shield", "aktif": ("security.index",)},
        ),
    },
    {
        "judul": "AKUN",
        "items": (
            {"label": "Settings", "endpoint": "settings.index",
             "ikon": "settings", "aktif": ("settings.index",)},
        ),
    },
)


def daftar_nav() -> list[dict]:
    """Menu yang endpoint-nya benar-benar terdaftar pada aplikasi."""
    hasil = []
    for grup in NAV:
        item_tersedia = []
        for item in grup["items"]:
            endpoint = item["endpoint"]
            if endpoint not in current_app.view_functions:
                continue
            try:
                href = url_for(endpoint)
            except Exception:
                continue
            item_tersedia.append({**item, "href": href})
        if item_tersedia:
            hasil.append({"judul": grup["judul"], "items": item_tersedia})
    return hasil


def nav_context() -> dict:
    """Konteks template: NAV dan sisa detik sesi untuk badge topbar."""
    sisa = 0
    if session.get("user_id") is not None:
        sisa = session_keys.sisa_detik(session.get("session_id", ""))
    return {"NAV": daftar_nav(), "sesi_sisa_detik": sisa}
