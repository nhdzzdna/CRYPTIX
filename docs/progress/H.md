# Sesi H — Autentikasi ulang (butir 3.5)
## Cara pakai
- Dekorator: `@require_grant("scope")` pada rute; `resource_id` dibaca dari argumen route bernama `resource_id`.
- Elemen: `data-reauth="scope"` dan `data-reauth-resource="id"` (opsional); modal meminta kata sandi/biometrik lalu melanjutkan aksi.
- Grant dikirim lewat header `X-Reauth-Grant` atau field form `reauth_grant`; tidak pernah lewat URL.
- Respons `POST /api/reauth` sukses: `{"success":true,"grant":"…","scope":"…","resource_id":"…","expires_in":120,"reusable":false}`; gagal: `{"success":false,"error":"…","reason":"…"}`.
- Scope: account.reveal, note.open, note.edit, file.download, media.stream, media.winamp, stego.extract, stego.download, item.delete, settings.change, biometric.manage.
## Ringkasan
- Selesai: grant in-memory ber-lock terikat session id + scope + resource; sekali pakai 120 detik; media.stream berulang 15 menit; blok REAUTH dicatat saat grant terbit.
- Selesai: metode password memakai hash autentikasi; registri metode dapat ditambah; kait webauthn menolak sampai Sesi F; kata sandi tidak masuk sesi/cookie/log/blockchain.
- File diubah: `modules/authentication/reauth.py`, `routes/reauth_routes.py`, `static/js/reauth.js`, `templates/_reauth_modal.html`, `tests/test_reauth.py` (baru), serta `app.py`, `modules/strings.py`, `templates/base.html`.
- Hasil pytest penuh: 346 passed, 0 gagal (baseline Sesi H 328 + 18 test baru).
- Keputusan desain: grant tidak disimpan di cookie/sesi; penolakan JSON 401 untuk grant hilang/kedaluwarsa/sesi lain dan 403 untuk scope/resource salah; blok REAUTH hanya saat terbit agar streaming Range tidak membanjiri rantai.
- Sisa pekerjaan: pasang `@require_grant` pada route Vault/Notes/Media/Stego, implementasi WebAuthn (Sesi F), rate limit (Sesi G), dan uji manual alur modal di browser.
- DEPRECATED masih ada: derive_master_key → routes/auth_routes.py (login), tests/test_auth.py, tests/test_session_keys.py; derive_purpose_key → internal get_*, tests/test_auth.py; get_file_encryption_key/get_db_encryption_key → tests/test_auth.py; encrypt_file/decrypt_file/save_encrypted_file/load_encrypted_file → tests/test_file_encryption.py.
