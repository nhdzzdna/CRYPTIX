"""
modules/authentication/webauthn.py
───────────────────────────────────
WebAuthn (butir 2.5): pendaftaran dan verifikasi kredensial platform
lewat paket py_webauthn — misalnya sidik jari terintegrasi atau
Windows Hello pada mesin pengembangan.

RP ID dan origin dibaca dari .env lewat config.RP_ID dan config.RP_ORIGIN
(bawaan localhost dan http://localhost:5000). Opsi selalu memakai
authenticator_attachment="platform" dan user_verification="required".

Challenge disimpan di sisi server, berlaku sementara, dan sekali pakai:
  • kunci_daftar(user_id) — pendaftaran (wizard penyiapan dan Settings)
  • kunci_masuk(user_id)  — tahap 2 login
  • kunci_reauth(user_id) — autentikasi ulang (step-up) lewat
    verifikasi_webauthn() dan buat_opsi_reauth().

Saat modul ini dimuat, metode biometrik "webauthn" didaftarkan ke
registry biometrics sehingga tahap 2 login cukup menerima bukti berbentuk
respons navigator.credentials.get(). Pengenalan wajah disediakan pada
sesi G sebagai metode terpisah.
"""

from __future__ import annotations

import secrets
import sqlite3
import threading
import time

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json_dict,
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    UserVerificationRequirement,
)

import config
from database.db import get_db
from modules.authentication import biometrics
from modules.strings import MSG

TTL_TANTANGAN = 300.0     # detik: tantangan berlaku lima menit

_tantangan: dict[str, tuple[bytes, float]] = {}
_kunci_tantangan = threading.Lock()


def kunci_daftar(user_id: int) -> str:
    """Kunci tantangan pendaftaran untuk ``user_id``."""
    return f"daftar:{user_id}"


def kunci_masuk(user_id: int) -> str:
    """Kunci tantangan masuk (tahap 2) untuk ``user_id``."""
    return f"masuk:{user_id}"


def kunci_reauth(user_id: int) -> str:
    """Kunci tantangan autentikasi ulang (step-up) untuk ``user_id``."""
    return f"reauth:{user_id}"


def _simpan(kunci: str, tantangan: bytes) -> None:
    kini = time.time()
    with _kunci_tantangan:
        basi = [k for k, (_, t) in _tantangan.items() if kini - t > TTL_TANTANGAN]
        for k in basi:
            _tantangan.pop(k, None)
        _tantangan[kunci] = (tantangan, kini)


def tantangan_baru(kunci: str) -> bytes:
    """Buat tantangan baru untuk ``kunci``; tantangan lama diganti."""
    tantangan = secrets.token_bytes(32)
    _simpan(kunci, tantangan)
    return tantangan


def periksa_tantangan(kunci: str) -> bytes | None:
    """Ambil tantangan aktif tanpa membuangnya (verifikasi gagal boleh ulang)."""
    with _kunci_tantangan:
        entri = _tantangan.get(kunci)
        if entri is None:
            return None
        tantangan, dibuat = entri
        if time.time() - dibuat > TTL_TANTANGAN:
            _tantangan.pop(kunci, None)
            return None
        return tantangan


def hapus_tantangan(kunci: str) -> None:
    """Buang tantangan setelah berhasil dipakai (sekali pakai)."""
    with _kunci_tantangan:
        _tantangan.pop(kunci, None)


def kosongkan_tantangan() -> None:
    """Kosongkan seluruh tantangan (dipakai pengujian)."""
    with _kunci_tantangan:
        _tantangan.clear()


def ada_kredensial(user_id: int) -> bool:
    """True bila pengguna sudah punya kredensial WebAuthn."""
    with get_db() as db:
        baris = db.execute(
            "SELECT 1 FROM webauthn_credentials WHERE user_id=? LIMIT 1",
            (user_id,),
        ).fetchone()
    return baris is not None


def kredensial_pengguna(user_id: int) -> list[dict]:
    """Daftar kredensial pengguna (credential_id, nama, dibuat)."""
    with get_db() as db:
        baris = db.execute(
            "SELECT credential_id, nama, dibuat FROM webauthn_credentials "
            "WHERE user_id=? ORDER BY dibuat, credential_id",
            (user_id,),
        ).fetchall()
    return [dict(b) for b in baris]


def hapus_kredensial(user_id: int, credential_id: str) -> bool:
    """Hapus satu kredensial milik ``user_id``; False bila bukan miliknya."""
    if not credential_id:
        return False
    with get_db() as db:
        kursor = db.execute(
            "DELETE FROM webauthn_credentials WHERE user_id=? AND credential_id=?",
            (user_id, credential_id),
        )
        db.commit()
        return kursor.rowcount > 0


def _deskriptor(credential_id: str) -> PublicKeyCredentialDescriptor:
    return PublicKeyCredentialDescriptor(
        id=base64url_to_bytes(credential_id),
        type=PublicKeyCredentialType.PUBLIC_KEY,
    )


def buat_opsi_pendaftaran(user_id: int, username: str) -> dict:
    """
    Opsi navigator.credentials.create() untuk ``user_id``.

    Tantangan disimpan di sisi server pada kunci_daftar(user_id); kredensial
    yang sudah ada dimasukkan ke exclude_credentials agar tidak didaftarkan
    dua kali.
    """
    tantangan = tantangan_baru(kunci_daftar(user_id))
    ada = [_deskriptor(k["credential_id"]) for k in kredensial_pengguna(user_id)]
    opsi = generate_registration_options(
        rp_id=config.RP_ID,
        rp_name="CRYPTIX",
        user_name=username,
        user_id=str(user_id).encode("utf-8"),
        challenge=tantangan,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=ada or None,
    )
    return options_to_json_dict(opsi)


def daftarkan_kredensial(
    user_id: int, respons: dict, nama: str = ""
) -> dict:
    """
    Verifikasi respons navigator.credentials.create() lalu simpan kredensial.

    Tantangan pada kunci_daftar(user_id) dipakai sekali pakai: dibuang
    setelah pendaftaran berhasil.
    """
    tantangan = periksa_tantangan(kunci_daftar(user_id))
    if tantangan is None:
        return {"success": False, "error": MSG.WEBAUTHN_CHALLENGE_EXPIRED}
    try:
        hasil = verify_registration_response(
            credential=respons,
            expected_challenge=tantangan,
            expected_rp_id=config.RP_ID,
            expected_origin=config.RP_ORIGIN,
            require_user_verification=True,
        )
    except Exception:
        return {"success": False, "error": MSG.WEBAUTHN_REGISTER_FAILED}

    credential_id = bytes_to_base64url(hasil.credential_id)
    with get_db() as db:
        try:
            db.execute(
                "INSERT INTO webauthn_credentials "
                "(user_id, credential_id, public_key, sign_count, nama) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    user_id,
                    credential_id,
                    hasil.credential_public_key.hex(),
                    hasil.sign_count,
                    str(nama)[:64],
                ),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return {"success": False, "error": MSG.WEBAUTHN_DUPLICATE}

    hapus_tantangan(kunci_daftar(user_id))
    return {"success": True, "credential_id": credential_id}


def buat_opsi_login(user_id: int) -> dict:
    """Opsi navigator.credentials.get() untuk tahap 2 login ``user_id``."""
    tantangan = tantangan_baru(kunci_masuk(user_id))
    ada = [_deskriptor(k["credential_id"]) for k in kredensial_pengguna(user_id)]
    opsi = generate_authentication_options(
        rp_id=config.RP_ID,
        challenge=tantangan,
        allow_credentials=ada or None,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json_dict(opsi)


def buat_opsi_reauth(user_id: int) -> dict:
    """
    Opsi navigator.credentials.get() untuk autentikasi ulang (step-up).

    Tantangan disimpan pada kunci_reauth(user_id), terpisah dari tantangan
    tahap 2 login, dan dibuang setelah verifikasi berhasil.
    """
    tantangan = tantangan_baru(kunci_reauth(user_id))
    ada = [_deskriptor(k["credential_id"]) for k in kredensial_pengguna(user_id)]
    opsi = generate_authentication_options(
        rp_id=config.RP_ID,
        challenge=tantangan,
        allow_credentials=ada or None,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json_dict(opsi)


def verifikasi_webauthn(user_id: int, respons, kunci: str) -> dict:
    """
    Verifikasi respons navigator.credentials.get() milik ``user_id``
    terhadap tantangan pada ``kunci`` (lihat kunci_masuk()).

    Dipakai tahap 2 login dan modul autentikasi ulang (butir 3.5).
    Berhasil: tantangan dibuang (sekali pakai) dan sign_count diperbarui.
    Gagal: tantangan tetap sehingga percobaan ulang masih mungkin sampai
    masa berlakunya habis.
    """
    if not isinstance(respons, dict):
        return {"success": False, "error": MSG.WEBAUTHN_FAILED}
    tantangan = periksa_tantangan(kunci)
    if tantangan is None:
        return {"success": False, "error": MSG.WEBAUTHN_CHALLENGE_EXPIRED}

    credential_id = str(respons.get("id", ""))
    with get_db() as db:
        baris = db.execute(
            "SELECT public_key, sign_count FROM webauthn_credentials "
            "WHERE user_id=? AND credential_id=?",
            (user_id, credential_id),
        ).fetchone()
        if baris is None:
            return {"success": False, "error": MSG.WEBAUTHN_NO_CREDENTIAL}
        entri = dict(baris)

    try:
        hasil = verify_authentication_response(
            credential=respons,
            expected_challenge=tantangan,
            expected_rp_id=config.RP_ID,
            expected_origin=config.RP_ORIGIN,
            credential_public_key=bytes.fromhex(entri["public_key"]),
            credential_current_sign_count=entri["sign_count"],
            require_user_verification=True,
        )
    except Exception:
        return {"success": False, "error": MSG.WEBAUTHN_FAILED}

    with get_db() as db:
        db.execute(
            "UPDATE webauthn_credentials SET sign_count=? "
            "WHERE user_id=? AND credential_id=?",
            (hasil.new_sign_count, user_id, credential_id),
        )
        db.commit()
    hapus_tantangan(kunci)
    return {
        "success": True,
        "credential_id": credential_id,
        "sign_count": hasil.new_sign_count,
    }


# Metode biometrik tahap 2: bukti berupa respons navigator.credentials.get().
biometrics.tambah_metode(
    "webauthn",
    "WebAuthn (sidik jari platform)",
    terdaftar=ada_kredensial,
    verifikasi=lambda user_id, bukti: verifikasi_webauthn(
        user_id, bukti, kunci_masuk(user_id)
    )["success"],
)
