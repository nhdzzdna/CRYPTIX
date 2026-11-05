"""
CRYPTIX - Configuration File
All tunable parameters and secrets live here.
Never hard-code secrets directly in source files.
"""

import os
from dotenv import load_dotenv

load_dotenv()  # reads .env if present

# ── Flask ──────────────────────────────────────────────────────────────────────
SECRET_KEY: str = os.environ.get("SECRET_KEY", os.urandom(32).hex())
DEBUG: bool = os.environ.get("DEBUG", "False").lower() == "true"
MAX_CONTENT_LENGTH: int = 64 * 1024 * 1024  # 64 MB upload limit

# ── Database ───────────────────────────────────────────────────────────────────
DATABASE_PATH: str = os.path.join(os.path.dirname(__file__), "database", "cryptix.db")

# ── Storage ────────────────────────────────────────────────────────────────────
STORAGE_ROOT: str         = os.path.join(os.path.dirname(__file__), "storage")
ENCRYPTED_FILES_DIR: str  = os.path.join(STORAGE_ROOT, "encrypted_files")
TEMPORARY_FILES_DIR: str  = os.path.join(STORAGE_ROOT, "temporary_files")
STEGO_IMAGES_DIR: str     = os.path.join(STORAGE_ROOT, "stego_images")
FACE_DATA_DIR: str        = os.path.join(STORAGE_ROOT, "face_data")

# ── Allowed file extensions ────────────────────────────────────────────────────
ALLOWED_EXTENSIONS: set = {
    "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "png", "jpg", "jpeg", "gif", "bmp", "webp",
    "mp3", "wav", "flac", "ogg", "m4a",
    "mp4", "avi", "mkv", "mov",
    "zip", "rar", "7z",
}
ALLOWED_IMAGE_EXTENSIONS: set = {"png", "jpg", "jpeg", "bmp"}
ALLOWED_AUDIO_EXTENSIONS: set = {"mp3", "wav", "flac", "ogg", "m4a"}

# ── Password hashing ───────────────────────────────────────────────────────────
PBKDF2_ITERATIONS: int = 600_000
PBKDF2_HASH_ALGO: str  = "sha256"
SALT_LENGTH: int       = 32   # bytes

# ── Face Recognition ──────────────────────────────────────────────────────────
FACE_CONFIDENCE_THRESHOLD: float = 70.0   # LBPH confidence: lower = stricter
FACE_SAMPLE_COUNT: int = 30               # frames captured during registration
HAAR_CASCADE_PATH: str = ""               # leave empty to use OpenCV bundled path

# ── Fingerprint matching ──────────────────────────────────────────────────────
FINGERPRINT_MATCH_THRESHOLD: int = 15     # minimum ORB good matches for acceptance

# ── USB Token ─────────────────────────────────────────────────────────────────
USB_REQUIRED: bool = False                # set True in production
USB_TOKEN_FILENAME: str = ".cryptix_token"
HMAC_ALGO: str = "sha256"

# ── Key Derivation ────────────────────────────────────────────────────────────
HKDF_SALT_FILE_ENC: bytes  = b"cryptix-file-encryption-v1"
HKDF_SALT_DB_ENC: bytes    = b"cryptix-database-encryption-v1"
HKDF_SALT_STEGO: bytes     = b"cryptix-steganography-v1"

# ── Super Encryption key info labels ──────────────────────────────────────────
# Each sub-cipher uses a different HKDF label so keys are independent.
SUPER_ENC_LABELS: dict = {
    "vigenere":  b"super-enc-vigenere-v1",
    "playfair":  b"super-enc-playfair-v1",
    "chacha20":  b"super-enc-chacha20-v1",
    "blowfish":  b"super-enc-blowfish-v1",
}

# ── Blockchain ────────────────────────────────────────────────────────────────
BLOCKCHAIN_HASH_ALGO: str = "sha256"

# ── Winamp ────────────────────────────────────────────────────────────────────
WINAMP_PATH: str = os.environ.get(
    "WINAMP_PATH",
    r"C:\Program Files (x86)\Winamp\winamp.exe"
)

# ── Session ───────────────────────────────────────────────────────────────────
SESSION_LIFETIME_MINUTES: int = 60

# ── CSRF ──────────────────────────────────────────────────────────────────────
WTF_CSRF_ENABLED: bool = True
