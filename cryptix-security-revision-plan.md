# CRYPTIX Security Revision Plan

## Top-Level Overview

CRYPTIX is an existing local web archive application (Python 3.13, Flask, SQLite, Jinja2, vanilla JS). This plan addresses 13 confirmed security vulnerabilities found during audit and restructures the security architecture across five phases. The project is **not** rewritten from scratch — all existing modules, routes, and templates are retained and revised in place.

**Core goal:** Every item in the audit list (1–13) is resolved without removing any of the seven core capabilities (a–g). The acceptance criteria are:
- All tests pass
- Login without dongle is rejected at startup and per-request
- Login without biometrics is rejected
- No key material ever reaches cookie, flash, URL, or log
- Account passwords, note contents, files, and media are only accessible after step-up re-authentication (grant)
- Video streams with Range support in-browser for mp4 H.264
- Database contents + cookie alone cannot decrypt user data

---

## Architecture Changes Summary

### Key Hierarchy (replaces current flat master_key)

```
password + usb_secret
        │
     PBKDF2 (600k iter) + HKDF-SHA256
        │
       KEK  (never stored)
        │
   AES-GCM unwrap
        │
       DEK  (32 bytes, stored wrapped in users table)
        │
     HKDF per label
       ├── file_key
       ├── db_key
       ├── stego_key
       ├── super_enc.vigenere / playfair / chacha20 / blowfish / mac
       ├── face_template_key
       └── chain_hash_key
```

### Session Storage (replaces session["master_key_hex"])

- `session_keys.py` — in-memory dict: `{session_id → {dek, last_seen, expires}}`
- Cookie contains only: `session_id`, `user_id`, `username`, `login_stage` (stage ∈ {0, 1, done})
- DEK is wiped on logout, timeout, and server restart

### Multi-Stage Login (replaces single-step)

```
Stage 1: password + dongle (combined, atomic)  →  Stage 2: biometrics  →  Active session
         │                                              │
   DEK unlocked here,                         DEK moved from pending
   held in pending_keys                       store to active_keys
   (TTL 3 min, keyed by                       on biometric success
   pre-session token)
```

**Invariant:** Password is destroyed immediately after `unlock_dek()` returns. It never reaches `session`, `session_keys`, server-side cache, log, or blockchain.

---

## Phase 0: Preparation

**Status:** [ ] pending

### 0.1 Baseline Audit
**Intent:** Establish baseline before touching any code.
**Expected Outcomes:** pytest run recorded, all existing failures noted.
**Todo:**
1. Run `pytest` from project root and capture output to `docs/baseline_test_results.txt`.
2. Note which tests currently pass/fail.

**Relevant Context:**
- `pytest.ini` — testpaths = tests, addopts = -v --tb=short
- All 7 test files in `tests/`

---

### 0.2 Import Cleanup
**Intent:** Remove `sys.path.insert` hacks; use proper package imports from project root.
**Expected Outcomes:** All modules importable without path manipulation; `pytest` works from root with `pythonpath = .`.
**Todo:**
1. Add `pythonpath = .` to `pytest.ini`.
2. In every file under `modules/`, `routes/`, `database/`, `tests/` remove the `sys.path.insert(0, ...)` pattern.
3. Rewrite all affected imports as absolute from root (e.g. `from modules.cryptography.key_management import ...`).
4. Run `pytest` to confirm no import errors.

**Relevant Context:**
- Subagent inventory §14 shows the `sys.path.insert` pattern in all module files
- `app.py` already imports blueprints from `routes.*`

---

### 0.3 Database: Context Manager + Pragmas + schema_meta
**Intent:** Guarantee connections are always closed; enable WAL, foreign keys, busy timeout; add versioned schema table.
**Expected Outcomes:** `get_db()` used as `with get_db() as db:` everywhere; `PRAGMA busy_timeout=5000` set; `schema_meta(version INTEGER)` table exists.
**Todo:**
1. Rewrite `database/db.py`: make `get_db()` return a context-manager-compatible connection (use `contextlib.contextmanager`); add `PRAGMA busy_timeout=5000`.
2. Add `schema_meta` table to `database/schema.sql`.
3. Update all route files to use `with get_db() as db:` instead of manual `try/finally`.
4. Verify `init_db()` creates `schema_meta` and inserts `version=1`.

**Relevant Context:**
- Current pattern in routes: `db = get_db(); try: ... finally: db.close()`
- `database/db.py` already sets WAL and foreign_keys

---

### 0.4 database/reset_db.py
**Intent:** Provide a safe, interactive tool to wipe all user data when key format changes make old data irrecoverable.
**Expected Outcomes:** Running `python database/reset_db.py` prompts for "RESET", then deletes `cryptix.db`, all files in `storage/` (except `.gitkeep`), and all key files in `instance/`.
**Todo:**
1. Create `database/reset_db.py`.
2. Prompt: print warning and require exact string "RESET".
3. Delete `database/cryptix.db` if present.
4. Walk `storage/` subdirectories, delete non-.gitkeep files.
5. Delete `instance/secret.key`, `instance/chain.key`, `instance/chain_head.json` if present.
6. Print confirmation.

---

### 0.5 config.py Rewrite
**Intent:** Centralise all configuration; remove unused constants; make SECRET_KEY persistent across restarts; load from `.env`.
**Expected Outcomes:** `instance/secret.key` created on first run and reused thereafter; all sensitive defaults clearly labelled; `.env.example` updated.
**Todo:**
1. Rewrite `config.py`:
   - Load `.env` via `python-dotenv`.
   - `SECRET_KEY`: read from env; if absent, generate 32-byte random key, persist to `instance/secret.key`, read back on subsequent runs.
   - Add: `DATABASE_PATH`, `LOG_PATH`, `POW_DIFFICULTY=3`, `SESSION_IDLE_MINUTES=10`, `SESSION_ABSOLUTE_MINUTES=60`, `FACE_CONFIDENCE_THRESHOLD=70.0`, `BIOMETRIC_POLICY=all_enrolled`, `CRYPTIX_DEV_MODE=false`, `DEV_DONGLE_DIR`, `RP_ID=localhost`, `RP_ORIGIN=http://localhost:5000`, `PBKDF2_ITERATIONS=600000`, `KEK_PBKDF2_ITERATIONS=600000`, `SUPER_ENC_PBKDF2_ITERATIONS=200000`.
   - Remove constants that no longer exist after revision (nonce/tag columns, master_key, face_model_path, fingerprint_path).
2. Update `.env.example` with all new variables and safe defaults.
3. Create `instance/` directory in project root; add to `.gitignore`.

**Relevant Context:**
- Current `config.py` has `SECRET_KEY=os.urandom(32)` which changes every restart — root cause of audit item 10 (USB HMAC never matches)

---

### 0.6 Logging
**Intent:** Structured rotating log to file; never log secrets.
**Expected Outcomes:** All `print()` security-relevant outputs replaced with `logging`; `storage/logs/app.log` rotates at 5 MB, 3 backups; log entries include timestamp, level, module.
**Todo:**
1. Create `storage/logs/` directory (add `.gitkeep`).
2. Create `modules/logger.py` with `get_logger(name)` helper that configures `RotatingFileHandler` pointing to `storage/logs/app.log`.
3. Replace `print()` in all modules and routes with `logger = get_logger(__name__)`.
4. Audit all log calls: ensure no password, key, token, or message content is logged.

---

### 0.7 .gitignore
**Intent:** Prevent secrets, database, cache, and storage content from being committed.
**Expected Outcomes:** A proper `.gitignore` exists; `cryptix.db`, `__pycache__/`, `.vscode/`, `storage/face_data/`, `instance/`, `.env` are tracked as ignored.
**Todo:**
1. Create `.gitignore` with entries: `database/*.db`, `instance/`, `storage/*`, `!storage/**/.gitkeep`, `.env`, `__pycache__/`, `*.pyc`, `.vscode/`, `venv/`, `.pytest_cache/`.
2. Remove from git index: `database/cryptix.db`, all `__pycache__/` dirs, `.vscode/`, `storage/face_data/`.
3. Add `.gitkeep` to `storage/encrypted_files/`, `storage/stego_images/`, `storage/temporary_files/`, `storage/logs/`.

---

### 0.8 Language Consistency (Indonesian Formal)
**Intent:** All user-visible strings use consistent formal Indonesian.
**Expected Outcomes:** No English flash messages, error messages, labels, or JSON keys visible to users remain.
**Todo:**
1. Audit all `flash()` calls and `return jsonify({"error":...})` in all route files.
2. Audit all templates for hardcoded English UI text.
3. Create a string constants file `modules/strings.py` with all user-facing messages (flash, JSON responses, error text).
4. Replace inline strings with references to `strings.py` throughout routes and templates.

---

### 0.9 app.py Cleanup
**Intent:** Single root route; stable reloader; redirect to localhost; error handlers.
**Expected Outcomes:** `app.run(use_reloader=False)`; `GET /` redirects 127.0.0.1 → localhost; error handlers for 400, 403, 404, 413, 429, 500 render `templates/error.html`.
**Todo:**
1. In `app.py`: add `before_request` handler that redirects `request.host == "127.0.0.1:5000"` to `http://localhost:5000/`.
2. Set `app.run(use_reloader=False)`.
3. Register error handlers for 400, 403, 404, 413, 429, 500 using `templates/error.html`.
4. Create `templates/error.html` with error code, message, and back-link.
5. Keep the single `"/"` route that redirects to `/login`.

---

## Phase 1: Core Cryptography

**Status:** [ ] pending

### 1.1 Key Management Rewrite (modules/cryptography/key_management.py)
**Intent:** Replace flat `master_key = PBKDF2(password)` with a DEK/KEK hierarchy where the DEK is never derivable from password alone, and authentication hash uses a completely separate salt.
**Expected Outcomes:**
- `create_key_bundle()` returns a bundle storable in `users` table (no raw keys).
- `unlock_dek()` requires password + USB secret; returns DEK bytes.
- `purpose_key()` deterministically derives sub-keys for each label.
- A test proves `password_hash` column value cannot open any encrypted data.
- `master_key_to_hex` / `master_key_from_hex` deleted.

**Todo:**
1. **New schema additions to `users` table:** Add columns `wrapped_dek` (TEXT), `kek_salt` (TEXT), `recovery_wrapped_dek` (TEXT), `auth_salt` (TEXT, separate from kek_salt). Remove `face_model_path`, `fingerprint_path` (superseded by `biometric_templates` table).
2. Implement `create_key_bundle(password, usb_secret, user_id)`:
   - Generate `dek = os.urandom(32)`.
   - Generate `kek_salt = os.urandom(32)` (separate from auth_salt).
   - Derive `kek_material = PBKDF2-HMAC-SHA256(password, kek_salt, 600000, 32)`.
   - `kek = HKDF-SHA256(kek_material + usb_secret, salt=b"", info=b"cryptix-kek-v1", length=32)`.
   - `wrapped_dek = AES-256-GCM(kek, dek)` with AAD = `f"{user_id}:wrapped_dek:v1".encode()`.
   - Generate `recovery_key = os.urandom(32)` (displayed once, never stored).
   - `recovery_kek = HKDF-SHA256(recovery_key, info=b"cryptix-recovery-v1")`.
   - `recovery_wrapped_dek = AES-256-GCM(recovery_kek, dek)`.
   - Return bundle dict and `recovery_key` (base32 grouped for display).
3. Implement `unlock_dek(password, usb_secret, bundle)` — inverse of above; returns DEK bytes.
4. Implement `rewrap_dek(dek, new_password, usb_secret, user_id)` — for password change; returns new bundle without touching DEK.
5. Implement `recover_dek(recovery_key_b32, bundle)` — unwrap using recovery path.
6. Implement `purpose_key(dek, label)` — `HKDF-SHA256(dek, info=label.encode(), length=32)`.
7. Define label constants: `LABEL_FILE`, `LABEL_DB`, `LABEL_STEGO`, `LABEL_VIG`, `LABEL_PLAY`, `LABEL_CHA`, `LABEL_BLO`, `LABEL_MAC`, `LABEL_FACE`, `LABEL_CHAIN`.
8. Implement auth hash: `hash_password_for_auth(password, auth_salt)` → uses PBKDF2 with `auth_salt` (not `kek_salt`). Store in `password_hash`, `auth_salt` separately.
9. Delete `derive_master_key()`, `master_key_to_hex()`, `master_key_from_hex()`.
10. Update `database/schema.sql` with new `users` columns and new tables `biometric_templates`, `webauthn_credentials`.
11. Write tests: round-trip lock/unlock; prove `password_hash` value cannot decrypt `wrapped_dek`; prove changing password with `rewrap_dek` leaves DEK unchanged; prove `recover_dek` with correct key succeeds and wrong key fails.

**Relevant Context:**
- Current `key_management.py` has `derive_master_key` → PBKDF2 → stored as session hex → root of audit items 1, 2
- Current `users` table has a single `salt` used for both password hash and key derivation — audit item 1

---

### 1.2 Super Encryption Fix (super_encryption.py, classical_cipher_2.py)
**Intent:** Make Playfair actually transform data by encoding Vigenere output as hex-alpha nibbles; add per-message salt, HMAC, and versioned output format.
**Expected Outcomes:**
- Playfair output differs from Playfair input (verifiable in test).
- HMAC-SHA256 appended; single-byte MAC corruption causes rejection.
- Wrong key causes rejection.
- Round-trip for Unicode, empty string, long string, repeated characters.
- `super_encrypt_steps()` returns per-layer output for educational display.

**Todo:**
1. **Encoding bridge (in `super_encryption.py`):** After Vigenere encrypts UTF-8 plaintext to bytes, encode each nibble to a letter from `"ABCDEFGHIKLMNOPQ"` (16 chars, no J, no X). This gives a pure-alpha string that Playfair can meaningfully transform.
2. **Decoding bridge:** After Playfair decrypts, strip X fillers, map letters back to nibbles → bytes → Vigenere decrypt.
3. **Per-message salt:** `msg_salt = os.urandom(16)`. Pass to `HKDF(dek, info=b"super-enc-v2", salt=msg_salt)` to derive all four sub-keys for this message.
4. **HMAC:** After Blowfish step, compute `mac = HMAC-SHA256(mac_key, ciphertext)`. Verify with `hmac.compare_digest` before decryption.
5. **Output format:** `"CXSE2.<salt_b64>.<token_b64>.<mac_b64>"` (version prefix for future migration).
6. **Passphrase mode (Crypto Tools):** Replace `SHA256(passphrase)` slices with `PBKDF2-HMAC-SHA256(passphrase, salt, 200000, 64)`, split into 4×16-byte sub-keys; include `pbkdf2_salt` in output.
7. Implement `super_encrypt_steps(plaintext, ...)` → `dict` with keys `after_vigenere`, `after_playfair`, `after_chacha20`, `after_blowfish`, `final`.
8. Update `classical_cipher_2.py` Playfair to handle uppercase input reliably (the nibble-encoded input will be all uppercase alpha).
9. Write tests: round-trip; Playfair input ≠ Playfair output; 1-byte MAC change rejected; wrong key rejected; empty string; 10,000-char string; "AAAAAAA..." repeated chars.

**Relevant Context:**
- Current bug: Playfair receives decimal digit strings (e.g. `"65 32 72..."`) which contain no letters, so it passes through unchanged — audit item 8
- Current passphrase mode uses `hashlib.sha256(passphrase.encode()).hexdigest()` sliced — audit item 8

---

### 1.3 Crypto Tools Route Fix (routes/crypto_routes.py, templates/crypto_tools.html)
**Intent:** Fix ChaCha20 (text key → bytes) and Blowfish (PBKDF2 key derivation); add step-by-step display for Super Encryption; ensure no output reaches cookie/flash.
**Expected Outcomes:** ChaCha20 accepts text key (derived via PBKDF2 or HKDF internally); Blowfish key derived with PBKDF2+salt; Super Encryption form shows layer-by-layer output on demand; all form submissions are CSRF-protected.
**Todo:**
1. In `routes/crypto_routes.py`: ChaCha20 form — if key is text, derive `key_bytes = PBKDF2(key_text, fixed_label_salt, 200000, 32)`.
2. Blowfish key: derive `key_bytes = PBKDF2(key_text, random_salt, 200000, 16)` and include salt in output.
3. Add "Tampilkan tahapan" checkbox to Super Encryption form; if checked, call `super_encrypt_steps()` and render per-layer table.
4. Ensure all results render in template, not flash or cookie.
5. All forms in `templates/crypto_tools.html` include `{{ csrf_token() }}` hidden field.

---

### 1.4 Database Field Encryption Rewrite (database/database_encryption.py)
**Intent:** Add AAD binding each ciphertext to its owner, table, and column; remove the orphaned `nonce`/`tag` columns from `account_vault` and `secure_notes`.
**Expected Outcomes:** Format `"v1:<nonce_b64>:<ciphertext_b64>"` stored per field; ciphertext moved between columns or users fails GCM authentication; `nonce` and `tag` columns removed from schema.
**Todo:**
1. Rewrite `encrypt_field(plaintext, db_key, user_id, table, column)` — AAD = `f"{user_id}:{table}:{column}"`.
2. Rewrite `decrypt_field(token, db_key, user_id, table, column)` — must pass matching AAD.
3. Remove `nonce TEXT` and `tag TEXT` columns from `account_vault` and `secure_notes` in `database/schema.sql`.
4. Update all route files that encrypt/decrypt DB fields to pass `user_id`, `table`, `column` arguments.
5. Write tests: round-trip; cross-user AAD mismatch rejected; cross-column AAD mismatch rejected.

---

### 1.5 File Encryption Rewrite (modules/cryptography/file_encryption.py)
**Intent:** Replace single-shot AES-GCM with chunked streaming format supporting random-access decryption; rename stored files to random hex without extension.
**Expected Outcomes:** Encrypted files use magic `CRYPTIX1` header; decrypt_range decrypts only needed chunks; stored filename is `<hex>.bin` with no extension; SHA-256 of plaintext and ciphertext stored separately; tampered file detected.
**Todo:**
1. Define file format:
   - Header: magic (8 bytes `CRYPTIX1`), version (1 byte), chunk_size (4 bytes, default 1 MiB), file_salt (16 bytes), chunk_count (4 bytes).
   - Each chunk: GCM nonce (12 bytes) + ciphertext + tag (16 bytes).
   - AAD per chunk: header bytes + chunk_index (4 bytes) + is_last_chunk (1 byte).
   - Per-file key: `HKDF(file_key, info=b"file-encrypt-v1", salt=file_salt)`.
   - Nonce per chunk: 12-byte counter.
2. Implement `encrypt_stream(input_bytes, file_key)` → `(encrypted_bytes, plaintext_sha256, ciphertext_sha256)`.
3. Implement `decrypt_all(encrypted_bytes, file_key)` → plaintext bytes; verify plaintext SHA-256 after reassembly; raise on mismatch.
4. Implement `decrypt_range(encrypted_bytes, file_key, byte_start, byte_end)` → plaintext bytes for range (for streaming).
5. Change `generate_stored_name()` → `secrets.token_hex(16) + ".bin"` (no extension, no original name leaked).
6. Update `vault_files` schema: add `plaintext_sha256`, `ciphertext_sha256`; keep `sha256_hash` for backward compat then remove.
7. Write tests: round-trip; chunk boundary edge cases; tampered byte in chunk raises; range decryption returns correct slice; hex filename has no extension.

---

### 1.6 Steganography LSB Rewrite (modules/steganography/lsb.py)
**Intent:** Add magic header, position scrambling via seeded PRNG, text encryption with Super Encryption, file encryption with AES-GCM, capacity display, and passphrase extraction.
**Expected Outcomes:** Images without hidden data return clear rejection; capacity display shown before embed; round-trip for text and binary payloads; wrong key raises; positions not sequential.
**Todo:**
1. **Header:** `CRXS` (4 bytes) + version (1 byte) + payload_type (1 byte: 0=text, 1=file) + payload_length (4 bytes) + CRC32 (4 bytes) = 14 bytes.
2. **Position scrambling:** `stego_key = purpose_key(dek, LABEL_STEGO)` or PBKDF2 from passphrase. Seed `numpy.random.default_rng(int.from_bytes(stego_key[:8], 'big'))` and shuffle pixel bit indices.
3. **Payload encryption:** text → `super_encrypt(text, sub_key)`; file → `AES-256-GCM(stego_key, file_bytes)`.
4. **Output:** always save as PNG; download filename ends in `.png`.
5. **Capacity function:** `get_capacity(image_path)` → bytes available.
6. **Warning:** return a flag if input was JPEG.
7. **Limit:** reject images wider/taller than 4000 px.
8. **Passphrase extraction endpoint:** accept optional passphrase in extract form.
9. Write tests: embed+extract text round-trip; embed+extract file round-trip; no-message image rejected clearly; capacity exceeded rejected; wrong key fails; positions are not `0,1,2,...` (shuffled).

---

### 1.7 Blockchain Rewrite (modules/blockchain/blockchain.py)
**Intent:** Add PoW, HMAC-based block signature using an out-of-database chain key, per-user log visibility, asset hash verification, and atomic writes.
**Expected Outcomes:** Editing a block and recalculating hashes still fails (signature uses key not in DB); chain head anchored to `instance/chain_head.json`; `verify_assets()` returns per-asset status; cross-user blocks not visible.
**Todo:**
1. **Schema changes to `blockchain_log`:** add `nonce` (INTEGER for PoW), `signature` (TEXT HMAC), `asset_ref` (TEXT, e.g. `"file:42"`), `asset_hash` (TEXT), `content_hash` (TEXT), `user_id NOT NULL`.
2. **Chain key:** on first use, generate `chain_key = os.urandom(32)`, persist to `instance/chain.key`. Load from file at module init.
3. **PoW:** increment `nonce` until `block_hash[:POW_DIFFICULTY_HEX_DIGITS] == "0" * digits`.
4. **Signature:** `HMAC-SHA256(chain_key, block_hash)`.
5. **Head anchor:** after each `add_block`, write `{"head_hash": block_hash, "block_index": idx}` to `instance/chain_head.json`.
6. **Atomic writes:** use `BEGIN IMMEDIATE` transaction; add `UNIQUE` constraint on `block_index`.
7. **`verify_chain()`:** check hash linkage, PoW, signature, and head match. Mark chain as tampered if any check fails.
8. **`verify_assets(user_id)`:** for each `vault_files` row owned by user, read encrypted file from disk, compute SHA-256 ciphertext, compare with DB record and `UPLOAD` block. For `account_vault` and `secure_notes`, compare `content_hash` (HMAC of ciphertext) with last `MODIFY` block. Return list of `{asset_ref, status}` where status ∈ OK/DIUBAH/HILANG/TANPA_CATATAN.
9. **Action enum:** add `STREAM`, `REVEAL`, `REAUTH`, `PASSWORD_CHANGE`, `DONGLE_REGISTER`, `BIOMETRIC_ENROLL`, `TAMPER_DETECTED`, `LOGIN_FAIL`, `STEGO_EMBED`, `STEGO_EXTRACT`, `DOWNLOAD`.
10. **User filter:** `get_user_blocks(user_id, limit)` filters by `user_id`.
11. **Rate limit LOGIN_FAIL:** only add blockchain block for LOGIN_FAIL if fewer than 3 failures in the last 60 seconds for that username (prevent chain flooding).
12. Write tests: forge a block + recalculate hashes → `verify_chain()` returns tampered; modify ciphertext file on disk → `verify_assets()` returns DIUBAH; two concurrent `add_block()` calls → unique indices; cross-user block invisible.

---

## Phase 2: Authentication

**Status:** [ ] pending

### 2.1 Password Policy
**Intent:** Enforce strong passwords on registration and change; prevent username-as-password; reject common passwords.
**Expected Outcomes:** Passwords under 12 chars rejected; passwords containing username rejected; passwords in common list rejected; must have 3 of 4 character classes.
**Todo:**
1. Create `modules/authentication/password_policy.py` with `validate_password(password, username)` returning `(ok: bool, reason: str)`.
2. Bundle a small common-password list (top 1000) as `modules/authentication/common_passwords.txt`.
3. Call `validate_password` in registration and change-password routes.
4. Return generic error messages (do not distinguish which rule failed in the HTTP response; log detail server-side).

---

### 2.2 USB Authentication Rewrite (modules/authentication/usb_authentication.py)
**Intent:** Fix serial detection (replace shell=True subprocess), fix token file format (JSON with HMAC verifier), fix HMAC stability (SECRET_KEY now persistent), add DEV_DONGLE_DIR simulation.
**Expected Outcomes:** `register_usb_token()` writes JSON token file to dongle; `verify_usb_token()` returns `(verified: bool, usb_secret: bytes)`; serial obtained via ctypes without subprocess; dev mode uses directory.
**Todo:**
1. Replace `subprocess("vol ...")` with `ctypes.windll.kernel32.GetVolumeInformationW(...)`.
2. Replace `psutil` heuristic with `"removable" in opts` filter.
3. Token JSON: `{"version": 1, "token_id": "<uuid>", "secret": "<32-byte-hex>"}`.
4. Verifier stored in `users` table: `usb_verifier = HMAC-SHA256(secret_bytes, b"cryptix-usb-verifier")`.
5. `verify_usb_token(stored_verifier_hex, stored_serial, stored_token_id)` → `(bool, secret_bytes | None)`.
6. Return `usb_secret` bytes for use in KEK derivation (Phase 1.1).
7. Dev mode: if `CRYPTIX_DEV_MODE=true` and `DEV_DONGLE_DIR` is set, treat that directory as the dongle.
8. Startup gate (in `app.py` `create_app()`): if any users exist and no registered dongle is present, `sys.exit(1)` with clear message.
9. Per-request gate (`before_request` in `app.py`): for logged-in sessions, re-check dongle every 2 seconds (cache result in session with timestamp); if absent, clear session and redirect to login.
10. Write tests (dev mode): no dongle → startup rejected; wrong verifier → rejected; correct token → returns secret.

---

### 2.3 Registration Flow Rewrite (routes/auth_routes.py)
**Intent:** Enforce dongle presence at registration; generate key bundle; show recovery key once; redirect to biometric setup wizard.
**Expected Outcomes:** Registration page lists available drives; registration blocked without dongle (non-dev); recovery key shown on a no-cache page; user cannot access any other page until biometric setup complete.
**Todo:**
1. Add `GET /api/drives` endpoint returning list of removable drives (or dev dongle dir).
2. Registration form: add drive selector.
3. On POST register: validate inputs with password policy; call `create_key_bundle()`; write token to selected drive; insert user row with `wrapped_dek`, `kek_salt`, `auth_salt`, `password_hash`, `usb_verifier`, `usb_volume_serial`, `token_id`; insert genesis REGISTER block.
4. Redirect to `GET /setup/recovery-key` (no-store, no-cache headers) which renders recovery key in base32 groups, with a checkbox form that must be submitted to proceed.
5. After confirmation, redirect to `GET /setup/biometric` wizard.
6. Add `setup_complete` boolean column to `users` table; `login_required` decorator checks `setup_complete=True` for all non-setup routes.

---

### 2.4 Multi-Stage Login (routes/auth_routes.py)
**Intent:** Replace single-step login with two sequential server-enforced stages. Stages 1 (password) and 2 (dongle) are combined into a **single atomic POST** so the password is never stored anywhere between stages.
**Expected Outcomes:**
- `POST /login` (Stage 1): verifies password + dongle in one request; unlocks DEK; stores DEK in a pending key store (TTL 3 min); sets `login_stage=1` in session. Password is discarded immediately after `unlock_dek()` returns — it is never written to session, cookie, server-side cache, log, or blockchain.
- `POST /login/biometric` (Stage 2): requires `login_stage=1`; on biometric success, moves DEK from pending to active and finalises session.
- Skipping or replaying either stage is rejected with 403.
- All failures (wrong password, dongle absent, dongle mismatch, DEK unwrap failure) return the **same generic message**: "Login gagal. Periksa kredensial Anda dan pastikan dongle terpasang."
- A dongle-status indicator is available on the login page via `GET /api/dongle-status` (no username required, no session required) — returns only `{"dongle_present": true/false}` so users can see if they forgot to plug in the dongle before submitting.

**Todo:**
1. **Combined Stage 1 endpoint `POST /login`:**
   - Run PBKDF2 dummy hash first to ensure constant time even if username is absent.
   - Look up user by username; if not found, return generic error after dummy hash completes.
   - Check `locked_until` (from 2.7); if locked, return generic error.
   - Call `verify_usb_token(stored_verifier, stored_serial, stored_token_id)` → `(ok, usb_secret)`. If not ok, return generic error (same message as wrong password — do not distinguish which factor failed).
   - Call `unlock_dek(password, usb_secret, bundle)` inside a `try/except`; on any exception return generic error.
   - Immediately `del password` (and clear the local variable) after `unlock_dek()` returns DEK.
   - Generate `pending_token = secrets.token_urlsafe(32)`.
   - Store `{dek, user_id, expires_at=now+180s}` in a module-level `_pending_deks` dict (separate from `session_keys`) keyed by `pending_token`.
   - Set `session["login_stage"] = 1`, `session["pending_token"] = pending_token` (not DEK, not password).
   - Log `LOGIN_FAIL` block on failure (rate-limited, see 1.7 note); do not log password.
2. **Stage 2 endpoint `POST /login/biometric`:**
   - Require `session.get("login_stage") == 1`.
   - Retrieve and remove `pending_token` from session; look up DEK in `_pending_deks`; reject if missing or expired.
   - Biometric check: handled by WebAuthn (2.5) or face (2.6) routes that call `_advance_biometric()`.
   - `_finalize_login(pending_dek, user_id)`: `session.clear()`, new session ID, set `user_id`, `username`, `login_stage="done"`, `login_time`; call `session_keys.store_key(session.sid, dek, active_ttl)`.
3. **`GET /api/dongle-status` (public, no auth):**
   - Call `is_any_registered_dongle_present()` from `usb_authentication.py` (check all removable drives against known verifiers without revealing any user-specific info).
   - Return `{"dongle_terpasang": true/false}`.
   - Rate-limit this endpoint (10/min) to prevent enumeration loops.
4. **Login template (`templates/login.html`):**
   - Add a small status badge ("Dongle terdeteksi ✓" / "Dongle tidak terdeteksi ✗") that calls `GET /api/dongle-status` on page load and on a 5-second polling interval.
   - Badge uses colour: green for present, amber for absent — never blocks form submission (user can still attempt login; server will reject if dongle is wrong).
5. On any stage violation, expired pending DEK, or out-of-order request: clear partial session, clear pending_deks entry, return 403.
6. **`_pending_deks` cleanup**: `purge_expired_pending()` called in `before_request` (same as `session_keys.purge_expired()`).

---

### 2.5 WebAuthn / Windows Hello (modules/authentication/fingerprint.py, new static/js/webauthn.js)
**Intent:** Replace fake ORB fingerprint matching with real WebAuthn (platform authenticator, Windows Hello / Touch ID).
**Expected Outcomes:** Registration creates a credential in `webauthn_credentials` table; login assertion verifies and updates `sign_count`; `fingerprint.py` becomes a thin documentation wrapper.
**Todo:**
1. Install `webauthn` (py_webauthn) — add to `requirements.txt`.
2. Add `webauthn_credentials(id, user_id, credential_id BLOB UNIQUE, public_key BLOB, sign_count INT, name TEXT, created_at TEXT)` to schema.
3. Add a server-side challenge store: `instance/` file or in-memory dict; challenges are single-use with 5-minute TTL.
4. Implement `GET /webauthn/register/begin` (login required, wizard/settings context): generate registration options with `rp_id=RP_ID`, `authenticator_attachment=platform`, `user_verification=required`; store challenge.
5. Implement `POST /webauthn/register/complete`: verify registration response; store credential; log BIOMETRIC_ENROLL.
6. Implement `GET /webauthn/authenticate/begin` (login stage 2 required): generate authentication options.
7. Implement `POST /webauthn/authenticate/complete`: verify assertion; update `sign_count`; advance login stage.
8. Create `static/js/webauthn.js`: base64url encode/decode helpers; `startRegistration(optionsJSON)`, `startAuthentication(optionsJSON)`.
9. Rewrite `fingerprint.py` as documentation-only module (no ORB code).
10. Remove fingerprint upload field from register and login templates.

---

### 2.6 Face Recognition Rewrite (modules/authentication/face_recognition.py)
**Intent:** Store encrypted face templates in DB (not plaintext files on disk); enforce frame count, variation, and liveness (non-identical frames); return confidence for dev mode calibration.
**Expected Outcomes:** No face model files in `storage/face_data/`; template stored as encrypted BLOB in `biometric_templates`; verification rejects frozen/identical frames; DEV mode shows confidence values.
**Todo:**
1. Add `biometric_templates(id, user_id, type TEXT, encrypted_data BLOB, created_at TEXT)` to schema.
2. `enroll_face(user_id, frames: list[np.ndarray], dek)`:
   - Require ≥30 frames over ≥3 seconds.
   - Detect faces with Haar cascade; require ≥25 valid 200×200 ROI samples.
   - Compute variance across samples (reject if all identical).
   - Compress ROI array with `numpy.savez_compressed` to `BytesIO`.
   - Encrypt bytes with `AES-GCM(purpose_key(dek, LABEL_FACE))`.
   - Store in `biometric_templates`.
3. `verify_face(user_id, frames: list[np.ndarray], dek)`:
   - Reject if any two frames are pixel-identical.
   - Load and decrypt template from DB.
   - Train LBPH recognizer in memory from decrypted ROI array.
   - Accept if ≥3 of 5 frames pass threshold and median confidence < threshold.
   - In DEV mode: include confidence values in return dict.
4. `has_face_enrolled(user_id)` → bool (queries `biometric_templates`).
5. Remove `capture_and_register`, `verify_face_webcam`, and all filesystem template paths.
6. Face registration endpoint: CSRF-protected, rate-limited, only accessible during biometric setup wizard or settings (not public).
7. Write tests (monkeypatched Haar cascade and LBPH).

---

### 2.7 Login Rate Limiting and Lockout
**Intent:** Prevent brute-force attacks; detect username enumeration via timing.
**Expected Outcomes:** Flask-Limiter 5 req/min on login; account locked after 5 consecutive failures with exponential backoff up to 30 min; timing attack mitigated by constant-time dummy hash.
**Todo:**
1. Add Flask-Limiter to `requirements.txt` and initialize in `app.py` with memory storage.
2. Add `failed_attempts INT DEFAULT 0` and `locked_until TEXT` to `users` schema.
3. In Stage 1 login: check `locked_until`; if locked return generic error.
4. On failure: increment `failed_attempts`; compute `locked_until = now + min(2^(failures-4), 30) minutes` for failures ≥5.
5. On success: reset `failed_attempts = 0`, `locked_until = NULL`.
6. Apply `@limiter.limit("5/minute")` to login, face verify, reauth, reveal, and recovery routes.
7. Write tests: 6th attempt returns 429; timing with non-existent username ≈ timing with wrong password (within 20ms).

---

### 2.8 Account Recovery (routes/auth_routes.py)
**Intent:** Allow user to recover account with recovery key + new dongle + new password, without losing encrypted data.
**Expected Outcomes:** `recover_dek(recovery_key, bundle)` unwraps DEK; new bundle created from new password + new dongle; new recovery key shown once; biometric templates survive.
**Todo:**
1. Create `GET /recover` and `POST /recover` routes (rate-limited, public).
2. Form: username, recovery key (base32), new password, new password confirm.
3. On POST: load user bundle; call `recover_dek()`; call `rewrap_dek(dek, new_password, new_usb_secret)`; write new token to new dongle; update user row; generate new recovery key (display once on no-store page).
4. Write tests: correct recovery key succeeds and DEK identical; wrong key fails; data encrypted with old DEK still decryptable after recovery.

---

### 2.9 Change Password (routes/settings_routes.py)
**Intent:** Re-wrap DEK under new KEK derived from new password; invalidate other sessions; no data re-encryption needed.
**Expected Outcomes:** After password change, same DEK decrypts all existing data; other concurrent sessions are terminated; PASSWORD_CHANGE logged to blockchain.
**Todo:**
1. Change password route requires `grant settings.change` (Phase 3.5) and dongle present.
2. Verify current password; call `unlock_dek()` with current password; call `rewrap_dek(dek, new_password, usb_secret)`.
3. Update `users` row with new `wrapped_dek`, `kek_salt`.
4. Invalidate all other session IDs for this user in `session_keys` store.
5. Log `PASSWORD_CHANGE` block.
6. Write tests: data accessible after password change; wrong current password rejected.

---

## Phase 3: Session Hardening

**Status:** [ ] pending

### 3.1 Server-Side Key Store (modules/cryptography/session_keys.py)
**Intent:** Move DEK out of cookie entirely; store in server memory with locking. Also houses the `_pending_deks` store used during the login window between Stage 1 and Stage 2.
**Expected Outcomes:** Cookie contains only `session_id`, `user_id`, `username`; DEK lives in `session_keys` dict; `decode_cookie()` in test shows no key material; keys wiped on logout/timeout/restart; pending DEKs expire after 3 minutes.
**Todo:**
1. Create `modules/cryptography/session_keys.py` with two separate thread-safe stores:
   - **Active store** (`_active`): `dict[session_id → {dek, last_seen, expires_at, user_id}]` with `threading.Lock`.
     - `store_key(session_id, dek, user_id, expires_seconds)`.
     - `get_key(session_id)` → `dek | None` (checks expiry, updates `last_seen`).
     - `delete_key(session_id)` — overwrites DEK bytearray with zeros, then deletes entry.
     - `purge_expired()` — iterates and deletes expired entries.
     - `invalidate_user_sessions(user_id)` — wipes all active sessions for the given user.
   - **Pending store** (`_pending`): `dict[pending_token → {dek, user_id, expires_at}]` with separate `threading.Lock`.
     - `store_pending(pending_token, dek, user_id, ttl_seconds=180)`.
     - `consume_pending(pending_token)` → `(dek, user_id) | None` — removes entry on retrieval (single-use).
     - `purge_expired_pending()` — called in `before_request`.
2. In `_finalize_login()`: call `consume_pending(pending_token)` to get DEK, then `store_key(new_session_id, dek, user_id)`.
3. In `before_request`: call `purge_expired()` and `purge_expired_pending()`.
4. `login_required` decorator: calls `get_key(session.sid)`; if None → clear session, redirect login.
5. Write tests: confirm cookie bytes contain no DEK and no pending_token DEK data; DEK expired after timeout; DEK gone after logout; `consume_pending` is single-use; wrong pending_token returns None.

---

### 3.2 Cookie and Session Config
**Intent:** Harden cookie flags; enforce idle and absolute session limits; CSRF-protect logout.
**Expected Outcomes:** `SESSION_COOKIE_HTTPONLY=True`; `SESSION_COOKIE_SAMESITE="Lax"`; 10-min idle timeout; 60-min absolute timeout; logout is POST.
**Todo:**
1. Set in `config.py` and `app.py`: `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, `SESSION_COOKIE_SECURE` (from env).
2. `before_request`: check `session["last_seen"]` + `SESSION_IDLE_MINUTES`; check `session["login_time"]` + `SESSION_ABSOLUTE_MINUTES`; on expiry clear session and redirect.
3. Update logout route to `POST` only with CSRF token; update all "logout" buttons in templates to `<form method="post">`.

---

### 3.3 Security Headers
**Intent:** Add HTTP security headers on all responses; move all inline JS to static files.
**Expected Outcomes:** All 7 headers present on every response; zero `<script>` tags with inline code in templates; CSP passes strict validation.
**Todo:**
1. Add `after_request` handler in `app.py` that sets: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy` (as specified in requirements).
2. Audit all templates for inline `<script>` blocks; move each to `static/js/<feature>.js`.
3. Remove `'unsafe-inline'` from `script-src` in CSP after audit.
4. Write tests: check each header present in responses; no `<script>` tags with inline JS in template HTML.

---

### 3.4 CSRF Meta Tag + api.js
**Intent:** Make CSRF token available to all fetch calls without per-call boilerplate.
**Expected Outcomes:** `<meta name="csrf-token">` in all layouts; `apiFetch()` in `static/js/api.js` auto-attaches `X-CSRFToken`; face recognition fetches stop returning 400.
**Todo:**
1. Add `<meta name="csrf-token" content="{{ csrf_token() }}">` to `base.html` and new `templates/auth_base.html`.
2. Create `templates/auth_base.html` shared by login, register, recovery, and setup pages.
3. Create `static/js/api.js` with `apiFetch(url, options)` — reads meta tag, merges into headers.
4. Replace all `fetch(...)` calls in templates and JS files with `apiFetch(...)`.
5. Add Flask-WTF CSRF error handler: return JSON `{"error": "CSRF tidak valid"}` for API requests (detected by `Accept: application/json` or `X-Requested-With`).

---

### 3.5 Step-Up Re-Authentication / Grant System (new: modules/auth/grants.py, static/js/reauth.js)
**Intent:** Require fresh re-authentication before revealing secrets; grants are single-use server-side tokens with scope+resource binding.
**Expected Outcomes:** Reveal, download, stream, extract, delete all require a valid grant; grant used once; expired grant (>120s) rejected; grant belonging to different session rejected.
**Todo:**
1. Create `modules/authentication/grants.py`:
   - `_grants: dict[str, dict]` with lock.
   - `issue_grant(session_id, scope, resource_id, ttl_seconds=120)` → `grant_token`.
   - `consume_grant(grant_token, session_id, scope, resource_id)` → `bool` (single-use except `media.stream`).
   - `media.stream` grants: `ttl_seconds=900`, reusable for same `resource_id` + `session_id`.
2. Endpoint `POST /api/reauth`:
   - Accept `method` ("password" or "webauthn"), `scope`, `resource_id`.
   - Verify credential; if valid, call `issue_grant()` and return `grant_token`.
   - Rate-limited; log REAUTH block.
3. Decorator `@require_grant(scope)` for route functions.
4. Create `static/js/reauth.js`:
   - Intercept clicks on elements with `data-reauth="<scope>"` and `data-resource="<id>"`.
   - Show modal (password input or WebAuthn button).
   - POST to `/api/reauth`; on success, re-issue the original request with `X-Grant-Token` header.
5. Write tests: action without grant → 403; expired grant → 403; consumed grant reused → 403; wrong session → 403; media.stream grant reusable within TTL.

---

## Phase 4: Features and Interface

**Status:** [ ] pending

### 4.1 Account Vault (routes/account_routes.py, templates/account_vault.html)
**Intent:** List shows only site name; username/password revealed only via grant; edit and delete require grant.
**Expected Outcomes:** Account Vault HTML contains no password or username in DOM; reveal endpoint returns JSON valid for 15 seconds; clipboard cleared after 20 seconds.
**Todo:**
1. List endpoint: return only `id`, `site_name` (decrypted), `created_at` — no username/password.
2. Add `POST /account-vault/reveal/<id>` (grant `account.reveal`): decrypt and return `{username, password}` JSON.
3. Add edit endpoint requiring grant `account.reveal` (re-use for edit form pre-fill).
4. Add delete endpoint requiring grant `item.delete`.
5. Template: replace inline data attributes with reveal button → `apiFetch` → show in DOM for 15 s → remove.
6. Clipboard API: after copy, `setTimeout(() => navigator.clipboard.writeText(""), 20000)`.

---

### 4.2 Secure Notes (routes/notes_routes.py, templates/secure_notes.html)
**Intent:** Note list shows only title; content opened via grant; content encrypted with Super Encryption then field encryption.
**Expected Outcomes:** Note HTML has no content in DOM; double-encryption: Super Encrypt content → then `encrypt_field()` stores result; edit and delete require grants.
**Todo:**
1. List endpoint: return only `id`, `title` (decrypted), `created_at`.
2. Note open endpoint `POST /secure-notes/open/<id>` (grant `note.open`): decrypt field → Super Decrypt → return JSON.
3. Note edit endpoint (grant `note.edit`): Super Encrypt new content → `encrypt_field` → update DB → update `content_hash` → log MODIFY.
4. Delete endpoint (grant `item.delete`).
5. Template: title-only list; modal to view/edit content loaded via `apiFetch`.

---

### 4.3 My Vault and Documents (routes/vault_routes.py, routes/document_routes.py)
**Intent:** Upload via chunked encryption; download only with grant; verify plaintext hash after decryption; validate file type.
**Expected Outcomes:** Uploaded files use CRYPTIX1 format; download returns `Content-Disposition: attachment`; hash mismatch logs TAMPER_DETECTED; extension + magic bytes validated.
**Todo:**
1. Upload: validate extension; for images run Pillow `Image.open()` verification; call `encrypt_stream()`; store `plaintext_sha256`, `ciphertext_sha256` in DB; log UPLOAD block with `ciphertext_sha256`.
2. Download endpoint (grant `file.download`): call `decrypt_all()`; compare plaintext SHA-256; if mismatch `add_block(TAMPER_DETECTED)` and return 409.
3. Set `Content-Disposition: attachment; filename="<original_name>"` and `Cache-Control: no-store`.
4. Set `tempfile.tempdir` to `storage/temporary_files/`; clean on startup.

---

### 4.4 Media Vault (routes/media_routes.py, templates/media_vault.html)
**Intent:** In-page `<audio>`/`<video>` elements with Range streaming; Winamp with secure temp files; correct MIME map; no plaintext to disk except Winamp temp.
**Expected Outcomes:** Video seeks in browser for mp4; 206 range responses; Winamp temp file overwritten with zeros before deletion; unsupported formats show warning + download-only.
**Todo:**
1. **Stream endpoint** `GET /media-vault/stream/<id>` (grant `media.stream`, reusable):
   - Parse `Range` header; call `decrypt_range()`; return 206 with `Content-Range`, `Accept-Ranges: bytes`.
   - Return 416 for invalid range.
   - No plaintext written to disk.
2. **Media template:** Add `<video controls>` and `<audio controls>` with `src="/media-vault/stream/<id>"`.
3. **MIME map:** `{mp4: video/mp4, webm: video/webm, mp3: audio/mpeg, wav: audio/wav, ogg: audio/ogg, m4a: audio/mp4, flac: audio/flac}`.
4. **Unsupported formats** (avi, mkv, mov): render "mungkin tidak dapat diputar di browser" notice + download-only button.
5. **Winamp** (grant `media.winamp`):
   - `save_temp_audio()` writes to `storage/temporary_files/<random_hex>` (no extension).
   - Schedule deletion: `threading.Timer(60, _secure_delete)`.
   - `_secure_delete()`: overwrite bytes with zeros, then `os.remove()`.
   - Also register `atexit` handler and startup cleanup.
   - Template shows honest warning about temporary disk exposure.

---

### 4.5 Steganography Interface (routes/stego_routes.py, templates/steganography.html)
**Intent:** Show capacity before embed; extract result displayed in page (not flash); download requires grant.
**Expected Outcomes:** Capacity indicator shown in UI; extract result in JSON rendered in DOM; stego.download grant required for image download.
**Todo:**
1. Add `GET /steganography/capacity` API endpoint → returns capacity JSON for uploaded image.
2. Template: capacity progress bar; key type selector (auto vs passphrase).
3. Extract endpoint (grant `stego.extract`): return JSON with extracted content rendered in page.
4. Download endpoint (grant `stego.download`).
5. Log `STEGO_EMBED` and `STEGO_EXTRACT` blocks.

---

### 4.6 Security Center (routes/security_routes.py, templates/security_center.html)
**Intent:** Show per-asset integrity status from `verify_assets()`; only user's own blocks visible.
**Expected Outcomes:** "Verifikasi Integritas" button triggers verify_chain + verify_assets; status OK/DIUBAH/HILANG/TANPA_CATATAN displayed per asset; chain global status displayed; no other users' blocks visible.
**Todo:**
1. Verification endpoint returns `{chain_status, assets: [{ref, name, status}]}`.
2. Template: global chain badge; asset table with color-coded status.
3. Block list filtered to `user_id = session["user_id"]`.

---

### 4.7 Dashboard (templates/dashboard.html, routes/dashboard_routes.py)
**Intent:** Show dongle status, biometric enrollment, chain head, asset counts, recent activity.
**Expected Outcomes:** Dashboard shows dongle connected/disconnected; biometric methods enrolled; last chain verification time + head hash snippet; counts; recent own-blocks list.
**Todo:**
1. Add to dashboard context: dongle status, enrolled biometrics (WebAuthn credential count + face enrolled bool), last chain head hash, asset counts, recent blocks (own only).
2. Update `dashboard.html` to render new cards.

---

### 4.8 Settings (routes/settings_routes.py, templates/settings.html)
**Intent:** Manage biometrics, dongle re-registration, password change, recovery key refresh, session timeout config — all requiring step-up auth.
**Expected Outcomes:** Each action requires appropriate grant; WebAuthn credentials listed with name + add/remove; face re-enroll available; dongle re-register available.
**Todo:**
1. Add sections to `settings.html`: Dongle status + re-register button (grant `settings.change`); WebAuthn credentials table (add/remove, grant `biometric.manage`); face re-enroll (grant `biometric.manage`); change password (grant `settings.change`); new recovery key (grant `settings.change`); session timeout selector.
2. Implement corresponding route handlers.
3. Ensure all forms have CSRF tokens.

---

### 4.9 Security Assistant (routes/assistant_routes.py, modules/assistant/security_agent.py)
**Intent:** Move conversation history to server memory; password input never enters history; status queries use new schema.
**Expected Outcomes:** Cookie contains no message history; password strength check uses separate input field; history shows "[password diperiksa]" placeholder; status queries return new fields (dongle, WebAuthn, chain).
**Todo:**
1. In `routes/assistant_routes.py`: move `chat_history` from `session` to `session_keys` store (keyed by `session_id`).
2. Add separate `password_input` field to chat form (type="password"); handle in route: call `check_password_strength()`, append only "[password diperiksa]" to history, never the password.
3. Update `security_agent.py` `security_status` intent handler: query new columns (`webauthn_credentials`, `biometric_templates`, `chain_head.json`).
4. Verify no flash messages contain extracted data anywhere in assistant flow.

---

## Phase 5: Testing, Documentation, Verification

**Status:** [ ] pending

### 5.1 Comprehensive Test Suite
**Intent:** Cover all audit items and acceptance criteria with automated tests.
**Expected Outcomes:** pytest passes with ≥80% coverage of routes; each audit item has at least one failing test that was fixed.

**Test categories to add/update:**
- **Login stages (two-stage model):**
  - Combined password+dongle: wrong password → generic error; dongle absent → same generic error; wrong dongle → same generic error (no leakage of which factor failed).
  - Combined password+dongle: correct credentials → `login_stage=1` set, DEK in pending store, NO password in session/cookie/pending store.
  - Biometric stage: skipping Stage 1 → 403; expired pending_token → 403; correct biometric → finalises session.
  - Stage order: POSTing to `/login/biometric` without first completing `/login` → 403.
  - Lockout after 5 failures; rate-limit 429 on 6th attempt.
  - **Timing parity:** POST `/login` with non-existent username takes the same time (±50 ms) as POST with wrong password — dummy hash ensures this.
  - `GET /api/dongle-status` returns 200 with `{"dongle_terpasang": false}` without any session; rate-limited to 10/min.
- **Password never stored:** After a successful Stage 1 POST, inspect session cookie (decode Flask signing), `_pending_deks` store, and `session_keys` store — confirm no password string present in any of them.
- **Key isolation:** DB password_hash cannot decrypt wrapped_dek; cookie has no key material; rewrap preserves DEK; recovery works.
- **Grants:** reveal/download/stream/extract without grant → 403; expired grant → 403; reused single-use grant → 403; wrong session → 403.
- **Plaintext-free HTML:** vault and notes pages contain no password or note content in HTML.
- **IDOR:** user A cannot access user B's resources on any endpoint.
- **Blockchain:** forgery detected; asset tamper detected; cross-user visibility blocked.
- **Media:** Range 206 and 416; correct MIME; unsupported format flag.
- **Headers/CSP:** all 5+ headers present; no inline script in templates.
- **Super Encryption:** Playfair changes data; MAC corruption rejected.

**Relevant Context:**
- Add `CRYPTIX_DEV_MODE=true` and `DEV_DONGLE_DIR=tests/fixtures/fake_dongle/` to test fixture setup.
- Monkeypatch face and WebAuthn in integration tests.
- Use Flask test client with `app.test_client()`.

---

### 5.2 README.md Rewrite
**Intent:** Accurate, honest documentation in formal Indonesian. No academic assignment language.
**Expected Outcomes:** README covers all topics listed in requirements; threat model section honest about limitations; no mention of courses, lecturers, or assignments.
**Todo:**
1. Write `README.md` with sections: Deskripsi, Tabel Fitur Keamanan, Diagram Hierarki Kunci (ASCII), Instalasi, Menjalankan Aplikasi, Setup Dongle, Pendaftaran Biometrik, Mode Pengembangan, Model Ancaman, Batasan, Struktur Folder, Cara Menjalankan Test.
2. Search entire project for prohibited words: "dosen", "tugas", "mata kuliah", "semester", "UAS", "UTS", "kelas", "mahasiswa". Remove any found.

---

### 5.3 Additional Documentation
**Intent:** Change log and manual test checklist for reviewers.
**Expected Outcomes:** `docs/laporan/perubahan.md` lists changes per area; `docs/laporan/checklist_pengujian_manual.md` has step-by-step manual test scenarios.
**Todo:**
1. Create `docs/laporan/` directory.
2. Write `perubahan.md`: per-phase summary table with columns File Changed / Change Summary / Tests Added / Known Limitations.
3. Write `checklist_pengujian_manual.md`: numbered steps for dongle attach/detach, WebAuthn register, face enroll, video playback, Winamp, account recovery, with expected results column.
4. Update `requirements.txt`: add `webauthn`, `Flask-Limiter`; change `opencv-contrib-python` to `opencv-contrib-python-headless`; pin all versions.

---

### 5.4 Final Verification
**Intent:** Confirm all acceptance criteria are met before handoff.
**Expected Outcomes:** Full pytest pass; application starts without error; list of hardware-only steps provided.
**Todo:**
1. Run `pytest --tb=short -q` and capture results.
2. Start `python app.py` in dev mode; confirm no startup errors.
3. Document hardware-only verification steps: physical USB dongle, Windows Hello biometric sensor, webcam for face enrollment, video codec (H.264 mp4), physical seek test.

---

## Files Changed Per Phase (Reference)

| Phase | Files Modified | New Files |
|-------|---------------|-----------|
| 0 | `pytest.ini`, `config.py`, `app.py`, `database/db.py`, `database/schema.sql`, all modules (import cleanup) | `database/reset_db.py`, `modules/logger.py`, `modules/strings.py`, `templates/error.html`, `instance/`, `.gitignore` |
| 1 | `modules/cryptography/key_management.py`, `super_encryption.py`, `classical_cipher_2.py`, `file_encryption.py`, `database_encryption.py`, `lsb.py`, `blockchain.py`, `routes/crypto_routes.py`, `database/schema.sql` | `docs/baseline_test_results.txt` |
| 2 | `modules/authentication/auth.py`, `usb_authentication.py`, `face_recognition.py`, `fingerprint.py`, `routes/auth_routes.py`, `routes/settings_routes.py` | `modules/authentication/password_policy.py`, `modules/authentication/common_passwords.txt`, `modules/authentication/grants.py`, `static/js/webauthn.js` |
| 3 | `app.py`, `routes/*.py` (headers, grant decorators), all templates (CSRF meta, inline JS removal) | `modules/cryptography/session_keys.py`, `static/js/api.js`, `static/js/reauth.js`, `templates/auth_base.html` |
| 4 | All route files, all template files, `modules/media/winamp_integration.py`, `modules/assistant/security_agent.py` | New feature JS files |
| 5 | `tests/*.py`, `requirements.txt`, `README.md` | `docs/laporan/perubahan.md`, `docs/laporan/checklist_pengujian_manual.md` |

---

## Open Questions / Design Decisions Made

1. **DEK in memory only:** Python's garbage collector does not guarantee memory clearing. Documented in README as a known limitation.
2. **No migration of old data:** Reset tool provided. Accepted because format changes make migration non-trivial and data loss on test systems is acceptable.
3. **PoW difficulty = 3 hex zeros:** Configurable; default chosen for performance on low-spec hardware.
4. **LBPH face recognition:** Known spoofable by photos. Documented honestly in README and UI.
5. **Winamp temp file:** Brief plaintext disk exposure unavoidable with Winamp IPC. Documented with overwrite-before-delete mitigation.
6. **No real fingerprint hardware:** WebAuthn covers Windows Hello fingerprint sensor. Old ORB code removed.
7. **Challenge store for WebAuthn:** In-memory dict with TTL (not DB) — simpler, single-instance deployment, acceptable for local app.
8. **Login stages collapsed to two:** Password + dongle verification happen in a single atomic POST (`POST /login`). The password is held only in the local stack frame of the request handler; it is passed directly into `unlock_dek()` and then `del`-eted. It is never written to session, cookie, `_pending_deks`, `session_keys`, log, or blockchain. Only the DEK (and a `pending_token` that references it) survive into Stage 2. This eliminates the need for a cross-request password cache entirely.
9. **Generic error for Stage 1 failures:** All combinations of wrong password / dongle absent / dongle mismatch / DEK unwrap failure produce the same error string. This prevents an attacker from learning which factor failed, satisfying audit item 3 (biometric/USB bypass) at the authentication layer.
10. **Dongle-status endpoint is user-agnostic:** `GET /api/dongle-status` checks only whether *any* registered dongle is present on the machine, without tying to any username. This avoids username enumeration while still letting the user see a helpful status indicator. The endpoint is rate-limited.

---

## Implementation Order (Agent Mode)

Each phase is a subtask. Before advancing:
1. Run `pytest` — all tests must pass.
2. Confirm with user before continuing.

Subtask sequence:
1. Phase 0 — Preparation (0.1 → 0.9)
2. Phase 1 — Core Cryptography (1.1 → 1.7)
3. Phase 2 — Authentication (2.1 → 2.9)
4. Phase 3 — Session Hardening (3.1 → 3.5)
5. Phase 4 — Features and Interface (4.1 → 4.9)
6. Phase 5 — Testing, Documentation, Verification (5.1 → 5.4)
