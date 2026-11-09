# Sesi GL: limiter reveal, galat JSON API, RuntimeError wajah
## Perubahan
- `modules/rate_limit.py`: tambah `REVEAL_LIMIT = "20 per minute"` dan kunci
  `user_or_ip_key()` (user id sesi, jatuh ke IP bila belum masuk).
- `/account-recovery/confirm` memakai `RECOVERY_LIMIT`; `/login/biometric`
  memakai `FACE_VERIFY_LIMIT` (konstanta lama, tanpa nilai baru).
- `REVEAL_LIMIT` per pengguna pada `/account-vault/reveal`, `/account-vault/edit`,
  `/account-vault/delete`, `/secure-notes/open`, `/secure-notes/edit`,
  `/secure-notes/delete`, `/vault/decrypt`, `/vault/delete`,
  `/media-vault/play`, `/media-vault/download`. `/media-vault/stream` dikecualikan.
- `app.py`: handler 400/401/403/404/405/413/429/500 membalas JSON untuk `/api/*`,
  `request.is_json`, `Accept: application/json`, atau `X-Requested-With`;
  halaman biasa tetap `templates/error.html`. Error 500 dicatat ke logger tanpa
  detail pengecualian. Error CSRF pada jalur JSON ikut JSON.
- `routes/auth_routes.py`: `register_face` dan `verify_face` menangkap
  `RuntimeError` lalu membalas 500 JSON `MSG.FACE_DETECTOR_UNAVAILABLE`.
- `static/js/face.js`: pembacaan balasan dibuat aman agar pesan JSON tampil.
- `modules/strings.py`: tambah `MSG.RATE_LIMITED`, pesan galat JSON, dan `MSG.FACE_DETECTOR_UNAVAILABLE`.
## Bentuk JSON galat
`{"success": false, "error": "<pesan MSG>", "reason": "<kode>"}`; kode:
`bad_request`, `unauthorized`, `forbidden`, `not_found`, `method_not_allowed`,
`payload_too_large`, `rate_limit`, `internal_error`, `csrf`.
## Tes
- Baru: `tests/test_gl_limiter_error.py`, 8 tes.
- Lulus: 38 tes GL/rate-limit/auth/reauth; 123 tes terkait storage/grant/media.
