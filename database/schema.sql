-- CRYPTIX Database Schema
-- All sensitive fields (credentials, notes content) are stored encrypted.

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    email           TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,   -- PBKDF2-HMAC-SHA256 hex
    salt            TEXT    NOT NULL,   -- hex-encoded random salt
    face_model_path TEXT,               -- path to saved LBPH .yml file
    fingerprint_path TEXT,              -- path to stored fingerprint image
    usb_token_hmac  TEXT,               -- HMAC of USB token file (hex)
    usb_volume_serial TEXT,             -- bound volume serial number
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT
);

-- ── Vault Files ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vault_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name   TEXT    NOT NULL,
    stored_name     TEXT    NOT NULL UNIQUE,   -- UUID-based safe filename
    file_type       TEXT    NOT NULL,          -- mime category: image/audio/document/other
    file_size       INTEGER NOT NULL,
    nonce           TEXT    NOT NULL,          -- hex nonce for AES-GCM
    tag             TEXT    NOT NULL,          -- hex GCM auth tag
    uploaded_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    sha256_hash     TEXT    NOT NULL           -- hash of plaintext for blockchain
);

-- ── Account Vault ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS account_vault (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site_name_enc   TEXT    NOT NULL,   -- AES-GCM encrypted, base64
    username_enc    TEXT    NOT NULL,
    password_enc    TEXT    NOT NULL,
    url_enc         TEXT,
    notes_enc       TEXT,
    nonce           TEXT    NOT NULL,
    tag             TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Secure Notes ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS secure_notes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title_enc       TEXT    NOT NULL,
    content_enc     TEXT    NOT NULL,
    nonce           TEXT    NOT NULL,
    tag             TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Schema Version ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_meta (
    version     INTEGER NOT NULL
);

-- ── Stego Images ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS stego_images (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name   TEXT    NOT NULL,
    stored_name     TEXT    NOT NULL UNIQUE,
    has_encryption  INTEGER NOT NULL DEFAULT 0,   -- 1 if message was super-encrypted
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Blockchain Log ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS blockchain_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    block_index     INTEGER NOT NULL,
    timestamp       TEXT    NOT NULL,
    user_id         INTEGER,
    action          TEXT    NOT NULL,   -- UPLOAD / DECRYPT / MODIFY / DELETE / LOGIN
    asset_hash      TEXT    NOT NULL,   -- SHA-256 of the asset at event time
    previous_hash   TEXT    NOT NULL,
    block_hash      TEXT    NOT NULL
);
