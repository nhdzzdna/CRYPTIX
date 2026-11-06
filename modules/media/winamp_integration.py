"""
modules/media/winamp_integration.py
─────────────────────────────────────
Winamp integration for Media Vault.

Flow:
  1. Decrypt the encrypted audio file to storage/temporary_files/.
  2. Open it in Winamp via subprocess (Windows).
  3. Schedule deletion of the temporary file after playback starts.

If Winamp is not found at config.WINAMP_PATH, the function returns
``winamp_available=False`` and the caller should fall back to the
HTML5 <audio> player in the template.
"""

import os
import subprocess
import threading
import time

import config
from modules.strings import MSG


def _schedule_delete(path: str, delay_seconds: int = 60) -> None:
    """Delete *path* after *delay_seconds* in a background thread."""
    def _worker():
        time.sleep(delay_seconds)
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass
    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def is_winamp_available() -> bool:
    """Return True if Winamp executable exists at config.WINAMP_PATH."""
    return bool(config.WINAMP_PATH) and os.path.isfile(config.WINAMP_PATH)


def play_with_winamp(decrypted_audio_path: str) -> dict:
    """
    Open *decrypted_audio_path* in Winamp.

    Parameters
    ----------
    decrypted_audio_path : str  Full path to the (temporary) audio file.

    Returns
    -------
    dict with ``success`` bool, ``winamp_available`` bool, ``error`` str.
    """
    if not is_winamp_available():
        return {
            "success": False,
            "winamp_available": False,
            "error": MSG.WINAMP_NOT_FOUND,
        }

    try:
        subprocess.Popen([config.WINAMP_PATH, decrypted_audio_path])
        # Schedule the temp file for deletion after 60 s
        _schedule_delete(decrypted_audio_path, delay_seconds=60)
        return {"success": True, "winamp_available": True}
    except Exception:
        return {"success": False, "winamp_available": True, "error": MSG.WINAMP_START_FAILED}


def save_temp_audio(decrypted_bytes: bytes, filename: str) -> str:
    """
    Write decrypted audio bytes to storage/temporary_files/ and return path.

    Parameters
    ----------
    decrypted_bytes : bytes  Raw audio data.
    filename        : str    Safe filename (no path traversal).

    Returns
    -------
    str  Absolute path to the temporary file.
    """
    os.makedirs(config.TEMPORARY_FILES_DIR, exist_ok=True)
    dest = os.path.join(config.TEMPORARY_FILES_DIR, filename)
    with open(dest, "wb") as f:
        f.write(decrypted_bytes)
    return dest


def cleanup_temp_file(path: str) -> None:
    """Immediately delete a temporary audio file."""
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
