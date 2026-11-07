"""
modules/authentication/auth.py
───────────────────────────────
High-level authentication orchestrator.
Combines password, face, fingerprint, and USB checks.
All DB access goes through database.db — no Flask imports here.
"""

import os
import re
import sqlite3

import config
from modules.strings import MSG
from modules.authentication.password_hash import hash_password, verify_password
from modules.authentication import face_recognition as face_mod
from modules.authentication import fingerprint as fp_mod
from modules.authentication import usb_authentication as usb_mod
from modules.cryptography.key_management import create_key_bundle
from database.db import get_db


# ── Registration policy (butir 2.1) ──────────────────────────────────────────

PASSWORD_MIN_LENGTH = 12

_POLA_USERNAME = re.compile(r"^[A-Za-z0-9._]{3,32}$")
_POLA_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

# Daftar password umum bawaan; dicocokkan tanpa membedakan huruf besar/kecil.
_COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "password1234", "passw0rd1234",
    "passwordpassword", "123456789012", "1234567890123", "12345678901234",
    "qwerty123456", "qwertyuiop123", "qwertyuiopasdf", "asdfghjkl1234",
    "zxcvbnmasdfgh", "1q2w3e4r5t6y", "1qaz2wsx3edc", "qazwsxedcrfv1",
    "administrator", "administrator1", "letmein12345", "welcome12345",
    "iloveyou1234", "monkey123456", "dragon123456", "football1234",
    "baseball1234", "sunshine1234", "princess1234", "trustno12345",
    "superman1234", "michael12345", "shadow123456", "master123456",
    "login1234567", "abc123456789", "changeme1234", "secret123456",
    "computer1234", "internet1234", "whatever1234", "freedom12345",
    "starwars1234", "test123456789", "demo123456789", "user123456789",
    "root123456789", "trustme12345", "letmeinwelcome",
})


def validate_username(username: str) -> str | None:
    """Kembalikan pesan galat bila format username tidak sah, else None."""
    if not _POLA_USERNAME.match(username or ""):
        return MSG.REGISTER_USERNAME_INVALID
    return None


def validate_email(email: str) -> str | None:
    """Kembalikan pesan galat bila format surel tidak sah, else None."""
    if not _POLA_EMAIL.match(email or ""):
        return MSG.REGISTER_EMAIL_INVALID
    return None


def validate_password(password: str, username: str = "") -> str | None:
    """
    Kebijakan kata sandi: minimal 12 karakter, tanpa username, tidak termasuk
    daftar password umum bawaan, dan memuat 3 dari 4 jenis karakter.
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return MSG.REGISTER_PASSWORD_TOO_SHORT
    if username and username.lower() in password.lower():
        return MSG.REGISTER_PASSWORD_USERNAME
    if password.lower() in _COMMON_PASSWORDS:
        return MSG.REGISTER_PASSWORD_COMMON
    jenis = (
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    )
    if sum(jenis) < 3:
        return MSG.REGISTER_PASSWORD_COMPLEX
    return None


def validate_registration(username: str, email: str, password: str,
                          confirm: str) -> str | None:
    """Validasi seluruh isian pendaftaran; kembalikan pesan galat pertama atau None."""
    if not username or not email or not password:
        return MSG.REGISTER_FIELDS_REQUIRED
    if password != confirm:
        return MSG.REGISTER_PASSWORD_MISMATCH
    galat = validate_username(username)
    if galat:
        return galat
    galat = validate_email(email)
    if galat:
        return galat
    return validate_password(password, username)


# ── Registration ──────────────────────────────────────────────────────────────

def register_user(username: str, email: str, password: str) -> dict:
    """
    Create a new user account (hash autentikasi saja; lihat create_account
    untuk akun lengkap dengan key bundle dan dongle).

    Returns
    -------
    dict with ``success`` bool and ``user_id`` / ``error`` keys.
    """
    galat = validate_registration(username, email, password, password)
    if galat:
        return {"success": False, "error": galat}
    pw_hash, salt = hash_password(password)
    with get_db() as db:
        try:
            cur = db.execute(
                "INSERT INTO users (username, email, password_hash, salt) VALUES (?,?,?,?)",
                (username.strip(), email.strip().lower(), pw_hash, salt),
            )
            db.commit()
            return {"success": True, "user_id": cur.lastrowid}
        except sqlite3.IntegrityError:
            return {"success": False, "error": MSG.AUTH_REGISTER_CONFLICT}
        except Exception:
            return {"success": False, "error": MSG.AUTH_REGISTER_ERROR}


def create_account(username: str, email: str, password: str,
                   dongle_token: dict) -> dict:
    """
    Buat akun lengkap: baris users, key bundle (KEK + kunci pemulihan), dan
    data dongle (token_id, verifier, serial volume) dalam satu rangkaian.

    ``dongle_token`` adalah hasil usb_authentication.register_usb_token().
    Rahasia dongle dipakai untuk KEK dan tidak pernah disimpan di basis data.

    Returns
    -------
    dict ``success``, ``user_id``, ``recovery_key`` (tampilkan sekali) bila
    berhasil; ``success`` False dengan pesan generik bila gagal.
    """
    hasil = register_user(username, email, password)
    if not hasil["success"]:
        return hasil
    user_id = hasil["user_id"]
    try:
        bundle = create_key_bundle(password, dongle_token["secret"], user_id)
        store_key_bundle(user_id, bundle)
        store_usb_token(
            user_id,
            dongle_token["token_id"],
            dongle_token["verifier"],
            dongle_token["volume_serial"],
        )
    except Exception:
        # Bungkus ulang gagal: baris akun dibuang agar tidak ada akun setengah jadi.
        with get_db() as db:
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
        return {"success": False, "error": MSG.AUTH_REGISTER_ERROR}
    usb_mod.lupakan_cache(user_id)
    return {
        "success": True,
        "user_id": user_id,
        "recovery_key": bundle["recovery_key"],
    }



def authenticate_user(
    username: str,
    password: str,
    face_frame=None,           # numpy BGR array, optional
    fingerprint_path: str | None = None,  # path to probe image
) -> dict:
    """
    Full authentication pipeline.

    Steps:
      1. Fetch user from DB.
      2. Verify password hash.
      3. Verify USB token (if USB_REQUIRED).
      4. Verify face (if model exists and frame provided).
      5. Verify fingerprint (if model exists and path provided).

    Returns
    -------
    dict with ``success`` bool, ``user`` row dict, and ``error`` string.
    """
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE username = ?", (username.strip(),)
        ).fetchone()

    if row is None:
        return {"success": False, "error": MSG.AUTH_INVALID_CREDENTIALS}

    # ── 1. Password ──────────────────────────────────────────────────────────
    if not verify_password(password, row["password_hash"], row["salt"]):
        return {"success": False, "error": MSG.AUTH_INVALID_CREDENTIALS}

    # ── 2. USB Token ─────────────────────────────────────────────────────────
    if config.USB_REQUIRED:
        if not row["usb_token_id"] or not row["usb_verifier"]:
            return {"success": False, "error": MSG.AUTH_USB_NOT_REGISTERED}
        ok, _rahasia = usb_mod.verify_usb_token(
            row["usb_verifier"], row["usb_volume_serial"], row["usb_token_id"]
        )
        if not ok:
            return {"success": False, "error": MSG.AUTH_USB_INVALID}

    # ── 3. Face Recognition ──────────────────────────────────────────────────
    if face_frame is not None and face_mod.has_face_model(row["id"]):
        if not face_mod.verify_face_from_frame(row["id"], face_frame):
            return {"success": False, "error": MSG.AUTH_FACE_FAILED}

    # ── 4. Fingerprint ───────────────────────────────────────────────────────
    if fingerprint_path and fp_mod.has_fingerprint(row["id"]):
        if not fp_mod.verify_fingerprint(row["id"], fingerprint_path):
            return {"success": False, "error": MSG.AUTH_FINGERPRINT_FAILED}

    # ── Update last_login ────────────────────────────────────────────────────
    with get_db() as db:
        db.execute(
            "UPDATE users SET last_login = datetime('now') WHERE id = ?", (row["id"],)
        )
        db.commit()

    return {"success": True, "user": dict(row)}


def get_user_by_id(user_id: int) -> dict | None:
    """Fetch a user row by primary key. Returns dict or None."""
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def store_key_bundle(user_id: int, bundle: dict) -> None:
    """Simpan kek_salt, wrapped_dek, dan recovery_wrapped_dek milik pengguna."""
    with get_db() as db:
        db.execute(
            "UPDATE users SET kek_salt=?, wrapped_dek=?, recovery_wrapped_dek=? "
            "WHERE id=?",
            (bundle["kek_salt"], bundle["wrapped_dek"],
             bundle["recovery_wrapped_dek"], user_id),
        )
        db.commit()


def store_usb_token(user_id: int, token_id: str, verifier: str,
                    volume_serial: str) -> None:
    """Simpan token_id, verifier, dan serial volume dongle milik pengguna."""
    with get_db() as db:
        db.execute(
            "UPDATE users SET usb_token_id=?, usb_verifier=?, usb_volume_serial=? "
            "WHERE id=?",
            (token_id, verifier, volume_serial, user_id),
        )
        db.commit()


def update_face_model_path(user_id: int, path: str) -> None:
    with get_db() as db:
        db.execute("UPDATE users SET face_model_path=? WHERE id=?", (path, user_id))
        db.commit()


def update_fingerprint_path(user_id: int, path: str) -> None:
    with get_db() as db:
        db.execute("UPDATE users SET fingerprint_path=? WHERE id=?", (path, user_id))
        db.commit()
