"""
config.py — CRYPTIX Configuration
───────────────────────────────────
All tunable parameters and secrets live here.
Never hard-code secrets directly in source files.

SECRET_KEY behaviour:
  1. Read from SECRET_KEY env var (or .env file) — takes priority.
  2. If absent, read from instance/secret.key (persisted across restarts).
  3. If that file doesn't exist either, generate 32 random bytes, persist
     them to instance/secret.key, and use that for the life of the instance.
"""

import os
import secrets
from dotenv import load_dotenv

load_dotenv()  # reads .env if present

# ── Instance directory ────────────────────────────────────────────────────────
_BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
_INSTANCE_DIR = os.path.join(_BASE_DIR, "instance")
os.makedirs(_INSTANCE_DIR, exist_ok=True)

# ── SECRET_KEY (persistent across restarts) ───────────────────────────────────
def _load_secret_key() -> str:
    """Return a stable SECRET_KEY, persisting it to instance/secret.key."""
    env_val = os.environ.get("SECRET_KEY", "").strip()
    if env_val:
        return env_val

    key_path = os.path.join(_INSTANCE_DIR, "secret.key")
    if os.path.isfile(key_path):
        with open(key_path, "r", encoding="utf-8") as f:
            stored = f.read().strip()
        if stored:
            return stored

    # Generate and persist a new key
    new_key = secrets.token_hex(32)
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(new_key)
    return new_key


SECRET_KEY: str = _load_secret_key()

# ── Flask ──────────────────────────────────────────────────────────────────────
DEBUG: bool = os.environ.get("DEBUG", "False").lower() == "true"
MAX_CONTENT_LENGTH: int = 64 * 1024 * 1024  # 64 MB upload limit

# ── Database ───────────────────────────────────────────────────────────────────
DATABASE_PATH: str = os.path.join(_BASE_DIR, "database", "cryptix.db")

# ── Storage ────────────────────────────────────────────────────────────────────
STORAGE_ROOT: str         = os.path.join(_BASE_DIR, "storage")
ENCRYPTED_FILES_DIR: str  = os.path.join(STORAGE_ROOT, "encrypted_files")
TEMPORARY_FILES_DIR: str  = os.path.join(STORAGE_ROOT, "temporary_files")
STEGO_IMAGES_DIR: str     = os.path.join(STORAGE_ROOT, "stego_images")
LOG_PATH: str             = os.path.join(STORAGE_ROOT, "logs", "app.log")

# ── Allowed file extensions ────────────────────────────────────────────────────
ALLOWED_EXTENSIONS: set = {
    "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "png", "jpg", "jpeg", "gif", "bmp", "webp",
    "mp3", "wav", "flac", "ogg", "m4a",
    "mp4", "avi", "mkv", "mov",
    "zip", "rar", "7z",
}

# ── Password hashing ───────────────────────────────────────────────────────────
PBKDF2_ITERATIONS: int          = int(os.environ.get("PBKDF2_ITERATIONS", 600_000))
KEK_PBKDF2_ITERATIONS: int      = int(os.environ.get("KEK_PBKDF2_ITERATIONS", 600_000))
SUPER_ENC_PBKDF2_ITERATIONS: int = int(os.environ.get("SUPER_ENC_PBKDF2_ITERATIONS", 200_000))
PBKDF2_HASH_ALGO: str           = "sha256"
SALT_LENGTH: int                = 32   # bytes

# ── Session ───────────────────────────────────────────────────────────────────
SESSION_IDLE_MINUTES: int      = int(os.environ.get("SESSION_IDLE_MINUTES", 10))
SESSION_ABSOLUTE_MINUTES: int  = int(os.environ.get("SESSION_ABSOLUTE_MINUTES", 60))
# Legacy alias used in app.py
SESSION_LIFETIME_MINUTES: int  = SESSION_ABSOLUTE_MINUTES

# ── Proof-of-Work ─────────────────────────────────────────────────────────────
POW_DIFFICULTY: int = int(os.environ.get("POW_DIFFICULTY", 3))

# ── Face Recognition ──────────────────────────────────────────────────────────
FACE_CONFIDENCE_THRESHOLD: float = float(
    os.environ.get("FACE_CONFIDENCE_THRESHOLD", 70.0)
)
FACE_SAMPLE_COUNT: int  = 30
HAAR_CASCADE_PATH: str  = ""   # leave empty to use OpenCV bundled path

# ── Biometrics policy ─────────────────────────────────────────────────────────
BIOMETRIC_POLICY: str = os.environ.get("BIOMETRIC_POLICY", "all_enrolled")

# ── Fingerprint matching ──────────────────────────────────────────────────────
FINGERPRINT_MATCH_THRESHOLD: int = 15

# ── USB Token ─────────────────────────────────────────────────────────────────
USB_REQUIRED: bool      = os.environ.get("USB_REQUIRED", "False").lower() == "true"
USB_TOKEN_FILENAME: str = ".cryptix_token"
HMAC_ALGO: str          = "sha256"

# ── Developer mode ────────────────────────────────────────────────────────────
CRYPTIX_DEV_MODE: bool = os.environ.get("CRYPTIX_DEV_MODE", "False").lower() == "true"
DEV_DONGLE_DIR: str    = os.environ.get("DEV_DONGLE_DIR", "")

# ── WebAuthn / Passkey ────────────────────────────────────────────────────────
RP_ID: str     = os.environ.get("RP_ID", "localhost")
RP_ORIGIN: str = os.environ.get("RP_ORIGIN", "http://localhost:5000")

# ── Key Derivation ────────────────────────────────────────────────────────────
HKDF_SALT_FILE_ENC: bytes  = b"cryptix-file-encryption-v1"
HKDF_SALT_DB_ENC: bytes    = b"cryptix-database-encryption-v1"
HKDF_SALT_STEGO: bytes     = b"cryptix-steganography-v1"

# ── Super Encryption key info labels ──────────────────────────────────────────
SUPER_ENC_LABELS: dict = {
    "vigenere":  b"super-enc-vigenere-v1",
    "playfair":  b"super-enc-playfair-v1",
    "chacha20":  b"super-enc-chacha20-v1",
    "blowfish":  b"super-enc-blowfish-v1",
}

# ── Winamp ────────────────────────────────────────────────────────────────────
WINAMP_PATH: str = os.environ.get(
    "WINAMP_PATH",
    r"C:\Program Files (x86)\Winamp\winamp.exe"
)

# ── CSRF ──────────────────────────────────────────────────────────────────────
WTF_CSRF_ENABLED: bool = True
