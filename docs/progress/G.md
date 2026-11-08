# Sesi G: biometrik, limiter, pemulihan, ganti password

Disusun dari riwayat commit dan keluaran grep; butir bertanda "belum diverifikasi" belum diperiksa pada kodenya.

Commit di cabang g-biometrik:
- 9014544 WebAuthn disambungkan ke autentikasi ulang
- 3922926 pengenalan wajah terenkripsi (butir 2.6)
- da3d819 pembatas laju dan kunci akun sementara (butir 2.7)
- f95fc4f pemulihan akun dengan kunci pemulihan (butir 2.8)
- 010b178 ganti password dengan autentikasi ulang dan pembungkusan ulang DEK (butir 2.9)
Hasil pytest penuh setelah merge main: 488 lulus.

Route dan batas laju (terverifikasi dari grep):
- POST /api/reauth dan POST /api/reauth/webauthn/options: REAUTH_LIMIT.
- POST /api/register_face (tanpa limiter), POST /api/verify_face: FACE_VERIFY_LIMIT. Template wajah di tabel biometric_templates (blok "Sesi G" di schema.sql).
- POST /login: LOGIN_LIMIT. Tahap biometrik: POST /login/biometric (tanpa limiter).
- GET/POST /account-recovery: RECOVERY_LIMIT pada POST. POST /account-recovery/confirm: tanpa limiter terlihat.
- POST /settings/change-password: @require_grant("settings.change").
- Kolom users: failed_attempts (terverifikasi). locked_until, FACE_CONFIDENCE_THRESHOLD: belum diverifikasi.

Sisa pekerjaan:
1. Pasang @limiter.limit pada reveal: /account-vault/reveal/<id> dan /secure-notes/open/<id> (butir 2.7).
2. Pasang limiter pada /account-recovery/confirm.
3. Pembersihan yang belum ter-commit (sesi M): hapus update_face_model_path dan update_fingerprint_path di auth.py, kolom lama face_model_path dan fingerprint_path di tabel users, API lama di file_encryption.py (dan test-nya). security_agent.py masih membaca kolom lama; diperbaiki di Sesi K butir 4.9.
4. /settings/register-usb dan /api/register_usb belum meminta autentikasi ulang (Sesi K butir 4.8).
5. Belum diverifikasi terhadap ketentuan: verifikasi wajah 5 frame dan penolakan gambar beku (2.6c), nilai confidence terlihat di mode pengembangan, kunci akun naik bertahap hingga 30 menit (2.7), halaman kunci pemulihan baru no-store dan tampil sekali (2.8), sesi lain dihentikan setelah ganti password (2.9).
6. Uji manual yang tidak bisa dilakukan agent: WebAuthn dengan Windows Hello, kamera untuk wajah.
   7. Perbaikan yang sudah dilakukan setelah uji manual: konversi base64url ke ArrayBuffer di static/js/webauthn.js (pendaftaran dan login WebAuthn), requirements.txt memuat dua paket OpenCV (baris lama dihapus, dikunci opencv-contrib-python-headless==4.10.0.84 karena OpenCV 5 tidak memuat berkas Haar Cascade).
   8. Belum: endpoint /api/... masih membalas halaman HTML saat terjadi error 500 (JavaScript gagal membaca JSON); RuntimeError dari modul wajah belum dibalas JSON.

Catatan: LBPH dapat dikelabui foto. Python tidak menjamin penghapusan memori.