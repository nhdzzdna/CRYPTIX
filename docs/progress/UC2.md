# UC2 — Vigenere Klasik, Tahapan Super Encryption, Profil & Akun, Istilah

## Ringkasan
- Bagian 1 selesai: alat Vigenere mandiri memakai kunci huruf A-Z (tidak peka huruf besar/kecil). Karakter bukan huruf pada teks dibiarkan dan tidak memajukan indeks kunci, sedangkan huruf besar/kecil dipertahankan.
- Kunci tidak valid ditolak di backend dengan status 400 dan pesan dari `modules/strings.py`. Pemanggil yang mengharapkan JSON menerima `{"error": ...}`; formulir peramban tetap menerima halaman dengan kotak galat.
- `static/js/crypto_tools.js` menyaring karakter selain A-Z pada kolom kunci saat cipher Vigenere dipilih.
- Layer Vigenere di dalam Super Encryption tidak diubah. Layer tersebut memakai fungsi printable ASCII lama dan kunci turunan yang dapat berisi non-huruf; pembatasan A-Z hanya berlaku untuk alat Vigenere mandiri agar data lama tetap dapat didekripsi.
- Bagian 2 selesai: `super_encrypt_stages` mengembalikan `final` dan daftar `stages` berisi nama, kode, jenis, input, output, keterangan, parameter aman, serta `jejak`. `super_encrypt_steps` tetap tersedia dengan bentuk lama agar pemanggil lama tidak rusak.
- Bagian 3 selesai: surel dapat diubah, data akun dapat direset tanpa menghapus akun, akun dapat dihapus dari Settings, dan akun dapat dihapus tanpa masuk dari halaman pemulihan. Semua tindakan destruktif memakai grant `account.danger` (kecuali jalur pemulihan yang tidak memiliki sesi) dan berjalan dalam satu transaksi basis data.
- Jejak layer klasik per karakter/pasangan; layer modern per byte heksadesimal. Kunci layer, kunci turunan, dan passphrase tidak pernah dimasukkan ke data tahapan. Nonce dan IV boleh ditampilkan.
- Tahapan dirender di server sebagai daftar bertahap dengan tabel jejak sederhana. Pendekatan ini dipilih agar tetap tampil tanpa JavaScript dan aman terhadap CSP ketat; JavaScript yang ada hanya mengatur formulir.

## File Berubah
### Bagian 1 dan 2
- `modules/cryptography/classical_cipher_1.py` — fungsi baru `is_valid_vigenere_key`, `vigenere_letter_encrypt`, `vigenere_letter_decrypt`; fungsi printable ASCII lama dipertahankan.
- `modules/cryptography/classical_cipher_2.py` — fungsi baru `playfair_encrypt_trace` untuk jejak pasangan dan aturan.
- `modules/cryptography/super_encryption.py` — `super_encrypt_stages`, jejak per layer, batas tampilan, dan pembungkus lama `super_encrypt_steps`.
- `routes/crypto_routes.py` — validasi kunci Vigenere, balasan JSON 400 untuk pemanggil JSON, status 400 untuk halaman, dan pengiriman data tahapan ke template.
- `modules/strings.py` — `CRYPTO_VIGENERE_KEY_INVALID` dan `CRYPTO_KEY_HINT`.
- `static/js/crypto_tools.js` — penyaringan kunci Vigenere.
- `templates/crypto_tools.html` — petunjuk kunci dan tabel jejak tahapan.
- `tests/test_vigenere_classic.py` — tes baru Bagian 1.
- `tests/test_super_encryption_stages.py` — tes baru struktur, batas, dan kerahasiaan jejak.
- `tests/test_crypto_routes.py` — tes tambahan tampilan jejak pada rute.

### Bagian 3
- `modules/authentication/account_cleanup.py` — penghapusan data pengguna terpusat dalam satu transaksi, termasuk penghapusan berkas terenkripsi dan stego.
- `modules/authentication/reauth.py` — scope baru `account.danger` (sekali pakai).
- `modules/authentication/usb_authentication.py` — `hapus_token_dongle` untuk membebaskan dongle setelah akun dihapus.
- `modules/blockchain/blockchain.py` — aksi baru `ACCOUNT_RESET` dan `ACCOUNT_DELETE`.
- `modules/strings.py` — pesan surel, reset data, hapus akun, dan hapus akun tanpa masuk.
- `routes/settings_routes.py` — `POST /settings/email`, `POST /settings/reset-data`, dan `POST /settings/delete-account`.
- `routes/auth_routes.py` — `POST /recovery/reset-account`.
- `templates/settings.html` — formulir ubah surel dan Zona Berbahaya.
- `templates/account_recovery.html` — tautan dan formulir hapus akun tanpa masuk beserta catatan batasannya.
- `templates/security_center.html` — lencana `ACCOUNT_RESET` dan `ACCOUNT_DELETE` ditampilkan sebagai tindakan berbahaya.
- `tests/test_account_management.py` — tes baru Bagian 3.
- `docs/progress/UC2.md` — dokumen ini.

## Keputusan
### Bagian 1 dan 2
- Fungsi Vigenere lama tidak diganti karena masih dipakai Super Encryption; fungsi baru ditambahkan terpisah.
- Rute `/crypto-tools` bukan rute `/api/*`, sehingga balasan JSON hanya diberikan bila pemanggil meminta JSON (`Accept: application/json`, `X-Requested-With`, atau body JSON). Formulir biasa menerima halaman berstatus 400 dengan pesan yang sama.
- Pesan galat ditulis persis `Kunci Vigenere hanya boleh huruf A-Z` tanpa titik akhir agar sesuai rumusan.
- Penyaringan JS bersifat kenyamanan; validasi server tetap menjadi penentu.
- Kunci layer Vigenere pada jejak disamarkan menjadi `***` (atau kosong untuk karakter yang tidak digeser). Contoh `{asal, kunci, hasil}` tetap dipenuhi tanpa membocorkan kunci turunan.
- Batas jejak: 200 karakter Vigenere, 100 pasangan Playfair (setara 200 huruf), dan 64 byte pertama untuk layer modern. Catatan pemotongan ditulis apa adanya, misalnya `ditampilkan 200 pertama dari 300 karakter`.
- Data tahapan memakai struktur dict/list dan dirender oleh Jinja. Ini menghindari blok skrip inline yang dilarang CSP dan menjaga tahapan tetap terlihat bila JavaScript mati.

### Bagian 3
- `account.danger` adalah grant sekali pakai karena tidak masuk `REUSABLE_TTL`. Reset data dan hapus akun sama-sama memerlukannya.
- Reset data mempertahankan akun, DEK, dongle, kredensial WebAuthn, templat wajah, dan kunci pemulihan. Hanya data pengguna (berkas, media, audio, stego, kredensial vault, catatan, koleksi, dan isi trash bila tabelnya ada) yang dihapus.
- Hapus akun menghapus baris pengguna sehingga seluruh turunannya ikut hilang, termasuk kredensial WebAuthn, templat wajah, dan kunci pemulihan. Berkas token dongle dihapus sebagai upaya terbaik agar dongle dapat didaftarkan ulang.
- Seluruh baris basis data dihapus dalam satu transaksi `BEGIN IMMEDIATE`. Berkas penyimpanan dihapus setelah transaksi berhasil; kegagalan sistem berkas dicatat di log dan tidak mengembalikan baris yang sudah terhapus.
- Rantai blockchain bersifat global. Menghapus blok akan memutus tautan hash, sehingga blok lama dipertahankan dan aksi baru `ACCOUNT_RESET` atau `ACCOUNT_DELETE` ditambahkan sebagai jejak audit.
- Jalur pemulihan tidak memiliki sesi, sehingga tidak memakai grant. Jalur ini mewajibkan dongle akun terpasang, nama pengguna yang diketik persis, dan kata sandi saat ini.
- Nama pengguna tidak dapat diubah; hanya surel yang dapat diperbarui setelah kata sandi saat ini diverifikasi.
- Bagian 4 (perubahan istilah) dibatalkan. Istilah antarmuka ditangani pada sesi terpisah.

## Keterbatasan
### Bagian 1 dan 2
- Penyaringan JS mengembalikan kursor ke akhir kolom saat ada karakter yang dibuang.
- Teks antarmuka lama di template masih banyak yang ditulis langsung; hanya teks baru pada Bagian 1 yang memakai `MSG`.
- Jejak layer modern hanya menampilkan 64 byte pertama; korelasi per huruf memang tidak bermakna pada cipher modern.
- Untuk pesan yang sangat panjang, bagian input/output tiap layer tetap ditampilkan penuh sehingga respons halaman bisa besar; hanya jejak yang dipotong.

### Bagian 3
- Tidak ada indeks sesi per pengguna. Saat akun dihapus dari Settings, hanya sesi yang sedang dipakai yang dibuang; sesi lain milik akun tersebut akan berakhir saat kunci sesi hilang atau timeout.
- Modul trash/UB belum ada pada kode gabungan saat ini. Penghapusan tabel trash ditulis defensif untuk nama `trash_items`, `trash`, dan `deleted_items`, sehingga belum dapat diuji dengan tabel trash yang sebenarnya.
- Bila kata sandi dan dongle sama-sama hilang, akun tidak dapat dihapus dari halaman pemulihan dan data terenkripsi tidak dapat dipulihkan. Batasan ini ditampilkan pada halaman pemulihan.
- Blok blockchain milik akun yang dihapus tetap tersimpan agar rantai tidak rusak. Blok tersebut tidak lagi tampil di Security Center karena pengguna tidak dapat masuk.
- Penghapusan berkas penyimpanan dan berkas token dongle bersifat upaya terbaik; kegagalan sistem berkas tidak membatalkan penghapusan akun di basis data.

## Temuan di Luar Lingkup
- Perubahan istilah "passphrase" tidak dikerjakan pada UC2 ini karena Bagian 4 dibatalkan; penyesuaian istilah dilakukan pada sesi antarmuka terpisah.
- Tidak ada route lama yang bergantung pada fungsi yang diganti pada Bagian 3, sehingga tidak ada route yang sementara tidak berfungsi.

## Hasil Uji
- Baseline sebelum Bagian 1: 690 passed.
- Setelah Bagian 1: 702 passed (12 tes baru).
- Setelah Bagian 2: 715 passed (13 tes baru Bagian 2).
- Baseline pada HEAD sebelum Bagian 3 (termasuk penggabungan `origin/main`): 747 passed.
- Setelah Bagian 3: 762 passed, 0 failed, 0 skipped (15 tes baru pada `tests/test_account_management.py`).

## Pemeriksaan Manual yang Disarankan
- Buka Settings, ubah surel dengan kata sandi benar, lalu pastikan pesan berhasil muncul dan surel baru tersimpan.
- Coba ubah surel ke surel akun lain dan pastikan pesan penolakan muncul tanpa mengubah data.
- Isi Zona Berbahaya, jalankan reset data, lalu pastikan akun masih dapat masuk dan berkas lama tidak lagi muncul.
- Hapus akun dari Settings, lalu daftarkan akun baru memakai dongle yang sama.
- Buka halaman pemulihan tanpa masuk, buka bagian hapus akun, dan pastikan catatan batasan tampil. Coba hapus dengan dongle terpasang, nama pengguna yang diketik persis, dan kata sandi benar.
- Buka Security Center setelah reset atau hapus akun dan pastikan verifikasi integritas rantai tetap berhasil.
