# Sesi F — catatan progres

Butir 2.4 (commit 3d865fe): login dua tahap password+dongle lalu biometrik; DEK tertahan di pending_keys; pesan galat generik sama; tanpa bypass biometrik; fungsi turunan DEK lama dihapus.
Butir 2.5 (selesai): WebAuthn dengan paket `webauthn==3.0.1` dikunci di requirements.txt; pytest penuh 366 test lulus.
`modules/authentication/webauthn.py`: tantangan sisi server (TTL 300 detik, sekali pakai), `buat_opsi_pendaftaran`, `daftarkan_kredensial`, `buat_opsi_login`, `verifikasi_webauthn(user_id, respons, kunci)`; RP ID/origin dari config; attachment platform + user verification wajib; metode "webauthn" didaftarkan ke biometrics saat modul dimuat.
Nama pemeriksa metode biometrik terdaftar: `biometrics.metode_biometrik_terdaftar(user_id)`; verifikasi WebAuthn untuk modul autentikasi ulang (3.5): `webauthn.verifikasi_webauthn(user_id, respons, kunci)`.
`database/schema.sql`: tabel `webauthn_credentials` (credential_id unik, public_key heksadesimal, sign_count, nama, dibuat) di akhir berkas.
`routes/auth_routes.py`: POST `/api/webauthn/register/options` dan `/api/webauthn/register/complete` (gerbang penyiapan ikut mengizinkan keduanya), tahap 1 login menyertakan `webauthn_options`, `/setup` kini GET saja.
`modules/authentication/fingerprint.py` menjadi lapisan tipis: `has_fingerprint()` mendelegasikan ke `webauthn.ada_kredensial()`; pencocokan ORB dan unggahan citra dihapus; `update_fingerprint_path()` bertanda DEPRECATED (T8/T11).
`static/js/webauthn.js` (konversi base64url, `navigator.credentials.create/get`) dipakai login.html, setup.html, dan settings.html; login.js menaruh tantangan pada `window.CryptixBiometrik.opsiMasuk`.
`tests/test_webauthn.py`: 18 test dengan autentikator palsu P-256 dan attestation "none"; `tests/test_registration_flow.py` serta `tests/test_two_stage_login.py` menyesuaikan.
Belum diuji: autentikator platform sungguhan (Windows Hello / sidik jari fisik) melalui peramban.
Belum dikerjakan: metode wajah untuk tahap 2 disediakan sesi G, sehingga akun hanya-wajah belum dapat menyelesaikan tahap 2; pesan `SETUP_FP_*` dan `FINGERPRINT_INVALID_FORMAT` tidak lagi dipakai.
