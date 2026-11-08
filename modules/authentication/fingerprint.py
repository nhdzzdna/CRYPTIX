"""
modules/authentication/fingerprint.py
──────────────────────────────────────
Lapisan tipis penanda sidik jari (butir 2.5).

Pencocokan ORB dan unggahan citra sidik jari dihapus: kini pendaftaran
serta verifikasi sidik jari berjalan lewat WebAuthn (lihat
modules/authentication/webauthn.py) yang memakai autentikator platform
bawaan perangkat. Berkas ini dipertahankan sebagai lapisan pemeriksaan
keberadaan metode bagi pemanggil lama.

Status sidik jari kini setara dengan adanya kredensial WebAuthn.
"""

from modules.authentication import webauthn


def has_fingerprint(user_id: int) -> bool:
    """
    True bila pengguna punya kredensial WebAuthn — pengganti citra
    referensi sidik jari pada skema lama.
    """
    return webauthn.ada_kredensial(user_id)
