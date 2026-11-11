# UC2 — Vigenere Klasik, Tahapan Super Encryption, Profil & Akun, Istilah

## Ringkasan
- Bagian 1 selesai: alat Vigenere mandiri memakai kunci huruf A-Z (tidak peka huruf besar/kecil). Karakter bukan huruf pada teks dibiarkan dan tidak memajukan indeks kunci, sedangkan huruf besar/kecil dipertahankan.
- Kunci tidak valid ditolak di backend dengan status 400 dan pesan dari `modules/strings.py`. Pemanggil yang mengharapkan JSON menerima `{"error": ...}`; formulir peramban tetap menerima halaman dengan kotak galat.
- `static/js/crypto_tools.js` menyaring karakter selain A-Z pada kolom kunci saat cipher Vigenere dipilih.
- Layer Vigenere di dalam Super Encryption tidak diubah. Layer tersebut memakai fungsi printable ASCII lama dan kunci turunan yang dapat berisi non-huruf; pembatasan A-Z hanya berlaku untuk alat Vigenere mandiri agar data lama tetap dapat didekripsi.

## File Berubah
- `modules/cryptography/classical_cipher_1.py` — fungsi baru `is_valid_vigenere_key`, `vigenere_letter_encrypt`, `vigenere_letter_decrypt`; fungsi printable ASCII lama dipertahankan.
- `routes/crypto_routes.py` — validasi kunci Vigenere, balasan JSON 400 untuk pemanggil JSON, status 400 untuk halaman.
- `modules/strings.py` — `CRYPTO_VIGENERE_KEY_INVALID` dan `CRYPTO_KEY_HINT`.
- `static/js/crypto_tools.js` — penyaringan kunci Vigenere.
- `templates/crypto_tools.html` — petunjuk kunci memakai `MSG.CRYPTO_KEY_HINT`.
- `tests/test_vigenere_classic.py` — tes baru.
- `docs/progress/UC2.md` — dokumen ini.

## Keputusan
- Fungsi Vigenere lama tidak diganti karena masih dipakai Super Encryption; fungsi baru ditambahkan terpisah.
- Rute `/crypto-tools` bukan rute `/api/*`, sehingga balasan JSON hanya diberikan bila pemanggil meminta JSON (`Accept: application/json`, `X-Requested-With`, atau body JSON). Formulir biasa menerima halaman berstatus 400 dengan pesan yang sama.
- Pesan galat ditulis persis `Kunci Vigenere hanya boleh huruf A-Z` tanpa titik akhir agar sesuai rumusan.
- Penyaringan JS bersifat kenyamanan; validasi server tetap menjadi penentu.

## Keterbatasan
- Penyaringan JS mengembalikan kursor ke akhir kolom saat ada karakter yang dibuang.
- Teks antarmuka lama di template masih banyak yang ditulis langsung; hanya teks baru pada Bagian 1 yang memakai `MSG`.

## Temuan di Luar Lingkup
- Belum ada. Perubahan istilah "passphrase" dikerjakan pada Bagian 4.

## Hasil Uji
- Baseline sebelum Bagian 1: 690 passed.
- Setelah Bagian 1: 702 passed (12 tes baru).
