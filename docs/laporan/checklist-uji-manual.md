# Panduan dan Lembar Periksa Uji Manual (Manual Testing Checklist)

Dokumen ini berisi panduan skenario pengujian manual ujung-ke-ujung (*end-to-end*) pada aplikasi **KOSYAK (CRYPTIX)**. Urutan pengujian disusun secara kronologis mulai dari pembuatan akun baru hingga skenario pemulihan akun.

Setiap butir uji menyediakan kolom status hasil `[ ]` yang dapat diisi dengan tanda centang `[x]` atau status `LULUS` / `GAGAL` setelah pengujian manual dilakukan.

---

## 1. Registrasi Akun Baru

| No | Skenario Pengujian | Langkah Pengujian | Hasil yang Diharapkan | Status | Catatan Penguji |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 1.1 | Pemuatan Halaman Registrasi | Buka `/register` pada peramban. | Form registrasi tampil rapi, meter kekuatan sandi 4 segmen muncul di bawah input sandi. | [ ] | |
| 1.2 | Validasi Meter Sandi | Ketik sandi lemah (misal `12345`), lalu tingkatkan ke sandi kuat (kombinasi huruf besar, kecil, angka, simbol). | Meter sandi bergerak dinamis dari merah (lemah) ke hijau (sangat kuat). | [ ] | |
| 1.3 | Pendaftaran Dongle USB Opsional | Tancapkan USB flashdisk, pilih drive dari dropdown, atau lewati jika tanpa USB. | Dropdown menampilkan drive yang terhubung dengan benar. | [ ] | |
| 1.4 | Pendaftaran Wajah Opsional | Klik tombol aktifkan kamera, hadapkan wajah dengan mata terbuka, klik ambil sampel. | Sistem mengambil sampel wajah dan menampilkan status siap disimpan. | [ ] | |
| 1.5 | Pengiriman Form Registrasi | Isi username, email, kata sandi yang cocok, lalu kirim form. | Akun berhasil dibuat, diarahkan ke halaman kunci pemulihan darurat. | [ ] | |
| 1.6 | Penyimpanan Kunci Pemulihan | Klik tombol "Salin" dan tombol "Unduh Kunci Pemulihan", centang persetujuan, lalu lanjutkan. | Berkas terunduh dengan nama `cryptix-kunci-pemulihan.txt`, tombol lanjutkan aktif setelah dicentang. | [ ] | |

---

## 2. Autentikasi & Login Dua Tahap

| No | Skenario Pengujian | Langkah Pengujian | Hasil yang Diharapkan | Status | Catatan Penguji |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 2.1 | Login Tahap 1 (Kredensial Utama) | Buka `/login`, masukkan username dan kata sandi yang baru dibuat. | Kredensial divalidasi; jika akun memiliki biometrik/dongle, diarahkan ke Tahap 2 (`/login/second-stage`). | [ ] | |
| 2.2 | Validasi Dongle Fisik USB | Jika dongle diaktifkan pada akun: coba login tanpa menancapkan flashdisk token. | Login ditolak dengan pesan bahwa USB token yang sah tidak terdeteksi. | [ ] | |
| 2.3 | Login Tahap 2: Pengenalan Wajah | Pada layar tahap 2, hadapkan wajah ke kamera web dan klik verifikasi. | Wajah dikenali dan sesi berhasil masuk ke Dashboard (`/dashboard`). | [ ] | |
| 2.4 | Pendaftaran WebAuthn / Passkey | Masuk ke **Pengaturan → Biometrik**, klik "Daftarkan Kredensial WebAuthn", ikuti prompt OS/browser. | Kredensial WebAuthn tersimpan dan muncul pada tabel daftar kredensial. | [ ] | |
| 2.5 | Login Tahap 2: WebAuthn | Logout, lakukan login Tahap 1, lalu pada Tahap 2 pilih verifikasi WebAuthn. | Prompt biometrik platform/PIN muncul; setelah diverifikasi, berhasil masuk ke Dashboard. | [ ] | |

---

## 3. Beranda & Dashboard

| No | Skenario Pengujian | Langkah Pengujian | Hasil yang Diharapkan | Status | Catatan Penguji |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 3.1 | Penampilan Kartu Statistik | Akses `/dashboard`. | Kartu ringkasan total berkas, audio, media, dan catatan tampil akurat. | [ ] | |
| 3.2 | Tautan Cepat & Navigasi | Klik masing-masing kartu atau menu sidebar. | Halaman berpindah mulus tanpa galat JavaScript di konsol (CSP bersih). | [ ] | |
| 3.3 | Log Aktivitas Terakhir | Periksa tabel aktivitas pada dashboard. | Tercatat aktivitas login dan registrasi yang terikat rantai blok integritas. | [ ] | |

---

## 4. Pengelolaan Dokumen (`/documents`)

| No | Skenario Pengujian | Langkah Pengujian | Hasil yang Diharapkan | Status | Catatan Penguji |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 4.1 | Unggah Berkas Dokumen | Tarik berkas PDF atau teks (TXT/MD) ke area dropzone. | Berkas terunggah, dienkripsi AES-256-GCM, dan muncul pada daftar dokumen. | [ ] | |
| 4.2 | Manajemen Folder Koleksi | Klik "+ Folder baru", beri nama folder, pindahkan berkas ke dalam folder tersebut. | Folder terbentuk, chip folder aktif memfilter berkas dengan benar. | [ ] | |
| 4.3 | Filter Pencarian Lokal | Ketik nama berkas pada kolom "Cari dokumen...". | Daftar tabel langsung terfilter secara instan (filter lokal di halaman). | [ ] | |
| 4.4 | Pratinjau Dokumen Teks & PDF | Klik nama berkas atau menu aksi "Pratinjau". | Modal pratinjau terbuka menampilkan isi teks atau penampil PDF dengan aman. | [ ] | |
| 4.5 | Penguncian Berkas Individual | Buka menu aksi berkas `⋯`, pilih "Kunci". | Badge berubah menjadi "Terkunci" dengan ikon gembok tertutup. | [ ] | |
| 4.6 | Akses Dokumen Terkunci | Coba buka pratinjau berkas yang terkunci. | Muncul modal verifikasi sandi; setelah sandi benar dimasukkan, pratinjau terbuka (grant 15 menit). | [ ] | |
| 4.7 | Pemindahan ke Sampah | Buka menu aksi `⋯`, pilih "Hapus". | Muncul dialog konfirmasi `KX.konfirmasiHapus`; setelah disetujui, berkas hilang dari daftar dan pindah ke Sampah. | [ ] | |

---

## 5. Perpustakaan Audio (`/audio`)

| No | Skenario Pengujian | Langkah Pengujian | Hasil yang Diharapkan | Status | Catatan Penguji |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 5.1 | Unggah Berkas Audio | Unggah berkas audio berformat MP3 atau WAV via dropzone. | Berkas dienkripsi sebelum disimpan dan tampil pada daftar trek. | [ ] | |
| 5.2 | Pemutar Audio Kustom | Klik tombol Play pada salah satu trek. | Bilah pemutar audio di bagian bawah aktif, menampilkan judul, visual progres teal, dan audio terdengar. | [ ] | |
| 5.3 | Penguncian Trek Audio | Kunci trek audio melalui menu aksi `⋯`. | Trek berstatus terkunci; klik play memunculkan modal otorisasi sandi terlebih dahulu. | [ ] | |

---

## 6. Brankas Media Visual (`/media-vault`)

| No | Skenario Pengujian | Langkah Pengujian | Hasil yang Diharapkan | Status | Catatan Penguji |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 6.1 | Unggah Foto & Video | Unggah citra (PNG/JPG) atau klip video (MP4/WEBM). | Galeri grid menampilkan kartu thumbnail terenkripsi dengan nama berkas asli. | [ ] | |
| 6.2 | Pengelompokan Album | Buat album baru, pindahkan foto ke album, lalu kunci album tersebut. | Saat album terkunci dibuka, sistem meminta otorisasi kunci album sebelum menampilkan isinya. | [ ] | |
| 6.3 | Penampil Media (Lightbox) | Klik media gambar atau video. | Modal penampil terbuka menampilkan citra resolusi penuh atau pemutar video HTML5. | [ ] | |

---

## 7. Brankas Akun & Catatan Rahasia

| No | Skenario Pengujian | Langkah Pengujian | Hasil yang Diharapkan | Status | Catatan Penguji |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 7.1 | Penyimpanan Akun (`/account-vault`) | Tambah entri akun baru (nama layanan, username, password). | Data tersimpan terenkripsi; tombol salin password berfungsi menyalin ke clipboard. | [ ] | |
| 7.2 | Catatan Rahasia (`/notes`) | Buat catatan baru, isi judul dan teks, simpan catatan. | Catatan tersimpan dengan DEK unik, daftar menampilkan cuplikan terenkripsi. | [ ] | |
| 7.3 | Hapus Catatan ke Sampah | Hapus catatan rahasia. | Catatan berpindah ke Sampah, tidak langsung terhapus permanen dari basis data. | [ ] | |

---

## 8. Alat Kriptografi & Steganografi

| No | Skenario Pengujian | Langkah Pengujian | Hasil yang Diharapkan | Status | Catatan Penguji |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 8.1 | Alat Kripto Klasik (`/crypto-tools`) | Uji enkripsi dan dekripsi teks dengan cipher klasik (Playfair / Vigenere). | Hasil ciphertext dan plaintext hasil dekripsi sesuai dengan kunci yang dimasukkan. | [ ] | |
| 8.2 | Steganografi LSB (`/steganography`) | Sisipkan pesan rahasia ke dalam citra pembawa PNG/BMP dengan kata sandi. | Citra hasil steganografi dapat diunduh tanpa perubahan visual yang mencolok. | [ ] | |
| 8.3 | Ekstraksi Pesan Stego | Unggah kembali citra stego ke tab ekstraksi dengan kata sandi yang sesuai. | Pesan rahasia asli berhasil diekstraksi secara utuh dan tepat. | [ ] | |

---

## 9. Pengelolaan Sampah 30 Hari (`/trash`)

| No | Skenario Pengujian | Langkah Pengujian | Hasil yang Diharapkan | Status | Catatan Penguji |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 9.1 | Penampilan Item Sampah | Buka rute `/trash`. | Menampilkan seluruh dokumen, audio, media, dan catatan yang dihapus beserta sisa hari kedaluwarsa. | [ ] | |
| 9.2 | Pemulihan Item (*Restore*) | Klik tombol "Pulihkan" pada salah satu item di Sampah. | Item hilang dari Sampah dan kembali muncul di halaman asalnya dengan data yang utuh. | [ ] | |
| 9.3 | Hapus Permanen Tunggal | Klik tombol "Hapus Permanen" pada item. | Muncul dialog konfirmasi merah; setelah disetujui, item dan berkas fisiknya musnah sepenuhnya. | [ ] | |
| 9.4 | Kosongkan Seluruh Sampah | Klik tombol "Kosongkan Sampah". | Seluruh item di sampah dibersihkan secara permanen; tampilan berubah menjadi kondisi kosong (*empty state*). | [ ] | |

---

## 10. Pengaturan, Kunci Pemulihan, & Skenario Reset Akun

| No | Skenario Pengujian | Langkah Pengujian | Hasil yang Diharapkan | Status | Catatan Penguji |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 10.1 | Ganti Kata Sandi | Di `/settings` tab Profil, masukkan kata sandi lama dan tetapkan sandi baru. | Sandi berhasil diganti; KEK pengguna diturunkan ulang dan DEK dienkripsi ulang secara transparan. | [ ] | |
| 10.2 | Terbitkan Kunci Pemulihan Baru | Di tab Keamanan, klik "Terbitkan kunci pemulihan baru". | Muncul modal konfirmasi peringatan kuning; kunci baru tampil dalam blok kode mono untuk disalin/diunduh. | [ ] | |
| 10.3 | Pemulihan Akun via Kunci | Logout, buka `/account-recovery`, masukkan username dan kunci pemulihan darurat. | Kunci diverifikasi; pengguna diizinkan mengatur kata sandi baru untuk akunnya. | [ ] | |
| 10.4 | Reset Akun Penuh (Darurat) | Pada `/account-recovery`, buka bagian reset akun, isi konfirmasi username dan kata sandi. | Akun dibersihkan total dan direset ke keadaan awal sesuai prosedur yang ditentukan. | [ ] | |

