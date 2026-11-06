"""
modules/authentication/usb_authentication.py
─────────────────────────────────────────────
USB Token (dongle) authentication layer.

How it works:
  1. On registration the user calls register_usb_token() which:
       • Finds a removable drive via psutil.
       • Reads its volume serial number (Windows: vol command).
       • Creates a signed HMAC token file (.cryptix_token) on the drive.
       • Returns the HMAC hex and volume serial to store in the DB.

  2. On login verify_usb_token() checks:
       • A removable drive is present.
       • The token file exists and its HMAC verifies correctly.
       • The volume serial matches the one stored for the user.
"""

import hmac
import hashlib
import os

import config

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

import subprocess
import platform


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_removable_drives() -> list[str]:
    """Return list of mount-points for removable drives."""
    if not _PSUTIL_AVAILABLE:
        return []
    drives = []
    for part in psutil.disk_partitions(all=False):
        if "removable" in part.opts.lower() or part.fstype.lower() in ("fat32", "fat", "exfat"):
            drives.append(part.mountpoint)
    return drives


def _get_volume_serial(mountpoint: str) -> str:
    """
    Get the volume serial number for a Windows drive.
    Falls back to empty string on non-Windows.
    """
    if platform.system() != "Windows":
        return ""
    try:
        drive_letter = mountpoint.rstrip("\\/")
        result = subprocess.run(
            ["vol", drive_letter],
            capture_output=True, text=True, shell=True, timeout=5
        )
        # Output line: "Volume Serial Number is XXXX-XXXX"
        for line in result.stdout.splitlines():
            if "serial" in line.lower():
                parts = line.strip().split()
                return parts[-1]  # e.g. "1A2B-3C4D"
    except Exception:
        pass
    return ""


def _compute_token_hmac(serial: str, secret_key: str) -> str:
    """HMAC-SHA256 of serial number with app secret."""
    key = (secret_key + serial).encode("utf-8")
    msg = f"CRYPTIX-USB-TOKEN:{serial}".encode("utf-8")
    return hmac.new(key, msg, config.HMAC_ALGO).hexdigest()


def _token_file_path(mountpoint: str) -> str:
    return os.path.join(mountpoint, config.USB_TOKEN_FILENAME)


# ── public API ────────────────────────────────────────────────────────────────

def register_usb_token(secret_key: str) -> dict | None:
    """
    Register the first available removable drive as a USB token.

    Parameters
    ----------
    secret_key : str  The application's SECRET_KEY (from config / session).

    Returns
    -------
    dict with keys ``hmac_hex`` and ``volume_serial``, or None if no
    removable drive is found.
    """
    drives = _get_removable_drives()
    if not drives:
        return None

    mountpoint = drives[0]
    serial = _get_volume_serial(mountpoint)
    token_hmac = _compute_token_hmac(serial, secret_key)

    # Write the signed token file onto the drive
    token_path = _token_file_path(mountpoint)
    with open(token_path, "w", encoding="utf-8") as f:
        f.write(f"{serial}:{token_hmac}\n")

    return {"hmac_hex": token_hmac, "volume_serial": serial}


def verify_usb_token(stored_hmac_hex: str, stored_serial: str, secret_key: str) -> bool:
    """
    Verify that the registered USB drive is currently inserted.

    Returns True if:
      • A removable drive is present.
      • Its volume serial matches stored_serial.
      • The token file HMAC verifies correctly.
    """
    if not config.USB_REQUIRED:
        return True   # USB check disabled in dev mode

    drives = _get_removable_drives()
    if not drives:
        return False

    for mountpoint in drives:
        serial = _get_volume_serial(mountpoint)
        if serial != stored_serial:
            continue

        token_path = _token_file_path(mountpoint)
        if not os.path.exists(token_path):
            continue

        expected_hmac = _compute_token_hmac(serial, secret_key)
        if hmac.compare_digest(expected_hmac, stored_hmac_hex):
            return True

    return False


def is_any_removable_present() -> bool:
    """Quick check — is any removable drive currently plugged in?"""
    return bool(_get_removable_drives())
