# Sesi K: Settings, asisten keamanan, dashboard

## Halaman Settings (4.8)
- templates/settings.html ditulis ulang: ganti password, USB token/dongle,
  kunci pemulihan, batas diam sesi, face recognition, WebAuthn.
- Setiap tindakan sensitif memakai grant autentikasi ulang:
  settings.change (password, dongle, kunci pemulihan, batas sesi) dan
  biometric.manage (wajah, tambah/hapus WebAuthn).
- routes/settings_routes.py: register-usb, recovery-key, session-timeout,
  webauthn/delete; /api/register_face dan pendaftaran WebAuthn dari
  Settings memakai grant.
- Kunci pemulihan baru tampil satu kali (Cache-Control: no-store) dan tidak
  disimpan di cookie sesi.
- Batas diam sesi per pengguna (pilihan menit tetap), diterapkan ke sesi
  yang sedang berjalan lewat session_keys.
- Minimal satu biometrik harus tetap terdaftar (penghapusan terakhir ditolak).
- Blockchain ACTIONS ditambah: BIOMETRIC_REMOVE, RECOVERY_ROTATE,
  SESSION_TIMEOUT.
- static/js/webauthn.js: daftar(idStatus, opsiOpsional) agar nama kredensial
  dapat dikirim dari Settings. static/js/settings.js dan face.js menangani
  tombol data-settings-action.

## Asisten keamanan, dashboard, pusat keamanan
- modules/assistant/history.py (baru): riwayat percakapan asisten.
- modules/assistant/security_agent.py dan routes/assistant_routes.py
  disesuaikan dengan data keamanan terbaru (tidak lagi membaca kolom lama
  face_model_path/fingerprint_path).
- routes/dashboard_routes.py dan routes/security_routes.py menampilkan
  kondisi keamanan akun (dongle, biometrik, kunci pemulihan, sesi).
- [PERIKSA: pastikan daftar di atas sesuai hasil kerja agent sebelum
  commit; hapus atau ubah baris yang tidak tepat.]

## Tes
- tests/test_settings.py (16 tes), tests/test_assistant_routes.py,
  tests/test_dashboard.py, tests/test_security_center.py baru;
  tests/test_webauthn.py dan tests/test_gl_limiter_error.py disesuaikan
  dengan grant.
- python -m pytest -q: 538 lulus.

## Catatan
- test_hapus_memakai_grant_biometric_manage pernah gagal 400 satu kali dan
  tidak bisa diulang (5 dari 5 lulus). Dicatat untuk sesi L.
- Pengecekan sintaks JS dengan node tidak dijalankan (node tidak terpasang);
  JS diuji manual di browser.