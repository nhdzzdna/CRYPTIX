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
-- Enkripsi per chunk (file_encryption.py); header berkas memuat nonce GCM,
-- sehingga kolom nonce/tag baris tidak diperlukan lagi.
CREATE TABLE IF NOT EXISTS vault_files (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name       TEXT    NOT NULL,      -- terenkripsi: "v1:<nonce>:<ct>"
    stored_name         TEXT    NOT NULL UNIQUE,   -- heksadesimal acak tanpa ekstensi asli
    file_type           TEXT    NOT NULL,          -- mime category: image/audio/video/document
    file_size           INTEGER NOT NULL,
    uploaded_at         TEXT    NOT NULL DEFAULT (datetime('now')),
    sha256_hash         TEXT    NOT NULL,      -- SHA-256 plaintext, verifikasi setelah dekripsi
    sha256_ciphertext   TEXT    NOT NULL       -- SHA-256 berkas terenkripsi, verifikasi aset
);

-- ── Account Vault ─────────────────────────────────────────────────────────────
-- Tiap field membawa nonce dan tag GCM-nya sendiri pada token "v1:...", sehingga
-- kolom nonce/tag baris hanya berisi placeholder palsu dan dihapus.
CREATE TABLE IF NOT EXISTS account_vault (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site_name_enc   TEXT    NOT NULL,   -- "v1:<nonce_hex>:<ciphertext_hex>"
    username_enc    TEXT    NOT NULL,
    password_enc    TEXT    NOT NULL,
    url_enc         TEXT,
    notes_enc       TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Secure Notes ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS secure_notes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title_enc       TEXT    NOT NULL,   -- "v1:<nonce_hex>:<ciphertext_hex>"
    content_enc     TEXT    NOT NULL,
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
    original_name   TEXT    NOT NULL,   -- terenkripsi: "v1:<nonce>:<ct>"
    stored_name     TEXT    NOT NULL UNIQUE,
    has_encryption  INTEGER NOT NULL DEFAULT 0,   -- 1 if message was super-encrypted
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Blockchain Log ────────────────────────────────────────────────────────────
-- Rantai hash ber-PoW: signature = HMAC-SHA256(kunci rantai, block_hash);
-- kunci rantai disimpan di instance/chain.key, bukan di basis data.
CREATE TABLE IF NOT EXISTS blockchain_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    block_index     INTEGER NOT NULL UNIQUE,
    timestamp       TEXT    NOT NULL,
    user_id         INTEGER,
    action          TEXT    NOT NULL,   -- lihat modules/blockchain/blockchain.py ACTIONS
    asset_ref       TEXT    NOT NULL DEFAULT '',   -- jenis:id, contoh "file:12"
    asset_hash      TEXT    NOT NULL,   -- SHA-256 ciphertext atau HMAC isi aset
    previous_hash   TEXT    NOT NULL,
    nonce           INTEGER NOT NULL DEFAULT 0,    -- proof of work
    block_hash      TEXT    NOT NULL,
    signature       TEXT    NOT NULL    -- HMAC-SHA256(kunci rantai, block_hash)
);
