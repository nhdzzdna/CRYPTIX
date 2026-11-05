"""
modules/authentication/auth.py
───────────────────────────────
High-level authentication orchestrator.
Combines password, face, fingerprint, and USB checks.
All DB access goes through database.db — no Flask imports here.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from modules.authentication.password_hash import hash_password, verify_password
from modules.authentication import face_recognition as face_mod
from modules.authentication import fingerprint as fp_mod
from modules.authentication import usb_authentication as usb_mod
from database.db import get_db


# ── Registration ──────────────────────────────────────────────────────────────

def register_user(username: str, email: str, password: str) -> dict:
    """
    Create a new user account.

    Returns
    -------
    dict with ``success`` bool and ``user_id`` / ``error`` keys.
    """
    pw_hash, salt = hash_password(password)
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (username, email, password_hash, salt) VALUES (?,?,?,?)",
            (username.strip(), email.strip().lower(), pw_hash, salt),
        )
        db.commit()
        return {"success": True, "user_id": cur.lastrowid}
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


def authenticate_user(
    username: str,
    password: str,
    secret_key: str,
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
    db = get_db()
    try:
        row = db.execute(
            "SELECT * FROM users WHERE username = ?", (username.strip(),)
        ).fetchone()
    finally:
        db.close()

    if row is None:
        return {"success": False, "error": "Invalid username or password."}

    # ── 1. Password ──────────────────────────────────────────────────────────
    if not verify_password(password, row["password_hash"], row["salt"]):
        return {"success": False, "error": "Invalid username or password."}

    # ── 2. USB Token ─────────────────────────────────────────────────────────
    if config.USB_REQUIRED:
        if not row["usb_token_hmac"] or not row["usb_volume_serial"]:
            return {"success": False, "error": "No USB token registered for this account."}
        if not usb_mod.verify_usb_token(
            row["usb_token_hmac"], row["usb_volume_serial"], secret_key
        ):
            return {"success": False, "error": "USB token not detected or invalid."}

    # ── 3. Face Recognition ──────────────────────────────────────────────────
    if face_frame is not None and face_mod.has_face_model(row["id"]):
        if not face_mod.verify_face_from_frame(row["id"], face_frame):
            return {"success": False, "error": "Face verification failed."}

    # ── 4. Fingerprint ───────────────────────────────────────────────────────
    if fingerprint_path and fp_mod.has_fingerprint(row["id"]):
        if not fp_mod.verify_fingerprint(row["id"], fingerprint_path):
            return {"success": False, "error": "Fingerprint verification failed."}

    # ── Update last_login ────────────────────────────────────────────────────
    db2 = get_db()
    try:
        db2.execute(
            "UPDATE users SET last_login = datetime('now') WHERE id = ?", (row["id"],)
        )
        db2.commit()
    finally:
        db2.close()

    return {"success": True, "user": dict(row)}


def get_user_by_id(user_id: int) -> dict | None:
    """Fetch a user row by primary key. Returns dict or None."""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        db.close()


def update_usb_token(user_id: int, hmac_hex: str, volume_serial: str) -> None:
    """Store USB token data for a user."""
    db = get_db()
    try:
        db.execute(
            "UPDATE users SET usb_token_hmac=?, usb_volume_serial=? WHERE id=?",
            (hmac_hex, volume_serial, user_id),
        )
        db.commit()
    finally:
        db.close()


def update_face_model_path(user_id: int, path: str) -> None:
    db = get_db()
    try:
        db.execute("UPDATE users SET face_model_path=? WHERE id=?", (path, user_id))
        db.commit()
    finally:
        db.close()


def update_fingerprint_path(user_id: int, path: str) -> None:
    db = get_db()
    try:
        db.execute("UPDATE users SET fingerprint_path=? WHERE id=?", (path, user_id))
        db.commit()
    finally:
        db.close()
