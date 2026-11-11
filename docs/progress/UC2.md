# UC2 — Vigenere Klasik, Tahapan Super Encryption, Profil & Akun, Istilah

## Ringkasan
- Bagian 1 selesai: alat Vigenere mandiri memakai kunci huruf A-Z (tidak peka huruf besar/kecil). Karakter bukan huruf pada teks dibiarkan dan tidak memajukan indeks kunci, sedangkan huruf besar/kecil dipertahankan.
- Kunci tidak valid ditolak di backend dengan status 400 dan pesan dari `modules/strings.py`. Pemanggil yang mengharapkan JSON menerima `{"error": ...}`; formulir peramban tetap menerima halaman dengan kotak galat.
- `static/js/crypto_tools.js` menyaring karakter selain A-Z pada kolom kunci saat cipher Vigenere dipilih.
- Layer Vigenere di dalam Super Encryption tidak diubah. Layer tersebut memakai fungsi printable ASCII lama dan kunci turunan yang dapat berisi non-huruf; pembatasan A-Z hanya berlaku untuk alat Vigenere mandiri agar data lama tetap dapat didekripsi.
- Bagian 2 selesai: `super_encrypt_stages` mengembalikan `final` dan daftar `stages` berisi nama, kode, jenis, input, output, keterangan, parameter aman, serta `jejak`. `super_encrypt_steps` tetap tersedia dengan bentuk lama agar pemanggil lama tidak rusak.
- Jejak layer klasik per karakter/pasangan; layer modern per byte heksadesimal. Kunci layer, kunci turunan, dan passphrase tidak pernah dimasukkan ke data tahapan. Nonce dan IV boleh ditampilkan.
- Tahapan dirender di server sebagai daftar bertahap dengan tabel jejak sederhana. Pendekatan ini dipilih agar tetap tampil tanpa JavaScript dan aman terhadap CSP ketat; JavaScript yang ada hanya mengatur formulir.

## File Berubah
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
- `docs/progress/UC2.md` — dokumen ini.

## Keputusan
- Fungsi Vigenere lama tidak diganti karena masih dipakai Super Encryption; fungsi baru ditambahkan terpisah.
- Rute `/crypto-tools` bukan rute `/api/*`, sehingga balasan JSON hanya diberikan bila pemanggil meminta JSON (`Accept: application/json`, `X-Requested-With`, atau body JSON). Formulir biasa menerima halaman berstatus 400 dengan pesan yang sama.
- Pesan galat ditulis persis `Kunci Vigenere hanya boleh huruf A-Z` tanpa titik akhir agar sesuai rumusan.
- Penyaringan JS bersifat kenyamanan; validasi server tetap menjadi penentu.
- Kunci layer Vigenere pada jejak disamarkan menjadi `***` (atau kosong untuk karakter yang tidak digeser). Contoh `{asal, kunci, hasil}` tetap dipenuhi tanpa membocorkan kunci turunan.
- Batas jejak: 200 karakter Vigenere, 100 pasangan Playfair (setara 200 huruf), dan 64 byte pertama untuk layer modern. Catatan pemotongan ditulis apa adanya, misalnya `ditampilkan 200 pertama dari 300 karakter`.
- Data tahapan memakai struktur dict/list dan dirender oleh Jinja. Ini menghindari blok skrip inline yang dilarang CSP dan menjaga tahapan tetap terlihat bila JavaScript mati.

## Keterbatasan
- Penyaringan JS mengembalikan kursor ke akhir kolom saat ada karakter yang dibuang.
- Teks antarmuka lama di template masih banyak yang ditulis langsung; hanya teks baru pada Bagian 1 yang memakai `MSG`.
- Jejak layer modern hanya menampilkan 64 byte pertama; korelasi per huruf memang tidak bermakna pada cipher modern.
- Untuk pesan yang sangat panjang, bagian input/output tiap layer tetap ditampilkan penuh sehingga respons halaman bisa besar; hanya jejak yang dipotong.

## Temuan di Luar Lingkup
- Belum ada. Perubahan istilah "passphrase" dikerjakan pada Bagian 4.

## Hasil Uji
- Baseline sebelum Bagian 1: 690 passed.
- Setelah Bagian 1: 702 passed (12 tes baru).
- Setelah Bagian 2: 715 passed (13 tes baru Bagian 2).
