# Ringkasan Perubahan Revisi (Changelog) — KOSYAK (CRYPTIX)

Dokumen ini merangkum seluruh perubahan arsitektur, keamanan, backend, dan perombakan antarmuka pengguna (UI/UX) pada platform KOSYAK (repositori CRYPTIX). Setiap kelompok perubahan merujuk pada catatan progres teknis terkait di `docs/progress/`.

---

## 1. Perombakan Antarmuka Pengguna & Sistem Desain (UI/UX Redesign)
*Rujukan: `docs/progress/U0.md`, `U1.md`, `U1b.md`, `U2.md`, `U3.md`, `U4.md`*

- **Fondasi Sistem Desain & Tokenisasi**:
  - Dibuat sistem token CSS terpusat (`static/css/tokens.css`) mencakup palet warna teal-dark, tipografi lokal (`Plus Jakarta Sans` dan `JetBrains Mono`), skala spasi, elevasi, dan radius.
  - Komponen UI modular terstandarisasi (`static/css/components.css` dan `static/js/ui/*.js`): Toast (`KX.toast`), Dialog Modal (`KX.modal`), Konfirmasi Hapus (`KX.konfirmasiHapus`), Dropzone drag-and-drop (`KX.dropzone`), Bar Aksi Mengambang (`KX.aksiMengambang`), Utilitas Salin (`KX.salin`), dan Pengukur Kekuatan Kata Sandi (`KX.meterSandi`).
  - Integrasi pustaka ikon SVG Sprite lokal lewat makro Jinja `ikon(nama, ukuran)`.
- **Penataan Ulang Halaman**:
  - **Autentikasi & Dashboard** (`U1.md`): Form login dua tahap, registrasi dengan meter sandi interaktif, dan dashboard ikhtisar tanpa subjudul serta tanpa tombol pencarian global yang menyesatkan.
  - **Pusat Keamanan & Pengaturan** (`U1b.md`): Kartu audit keamanan, verifikasi dongle USB, manajemen kredensial WebAuthn, pendaftaran ulang wajah, dan penerbitan kunci pemulihan darurat.
  - **Halaman Koleksi & Media** (`U2.md`, `U2b.md`): Redesain Dokumen (`/documents`), Audio (`/audio`), dan Galeri Media (`/media-vault`) dengan navigasi chip folder/album, indikator status gembok terkunci, dan pemutar audio kustom.
  - **Brankas Akun, Catatan, & Alat Kripto** (`U3.md`): Redesain brankas kredensial akun, editor catatan terenkripsi, alat cipher klasik, dan steganografi gambar.
- **Konsistensi Bahasa & Tanpa Inline Script**:
  - Seluruh teks antarmuka disentralisasi menggunakan Bahasa Indonesia baku lewat `modules/strings.py`.
  - Penghapusan seluruh JavaScript inline pada templat HTML demi kepatuhan terhadap Content Security Policy (CSP) ketat (`script-src 'self'`).

---

## 2. Pengelolaan Siklus Hidup Berkas & Fitur Sampah 30 Hari (*Trash Vault*)
*Rujukan: `docs/progress/UB.md`*

- **Penyimpanan Sementara Sebelum Dihapus Permanen**:
  - Dihapuskannya mekanisme penghapusan langsung berkas/catatan. Setiap operasi hapus kini memindahkan item ke tabel `trash` dengan penanda waktu kadaluwarsa 30 hari (`deleted_at` dan `expires_at`).
  - Rute `/trash` menyediakan daftar item sampah dengan hitungan sisa hari, pemulihan item (*restore*) ke koleksi/folder semula, serta opsi pengosongan sampah permanen.
- **Isolasi Akses & Integritas**:
  - Berkas yang berada di dalam Sampah diblokir secara otomatis dari rute pratinjau, unduh, dan *streaming* dengan kode status HTTP 404.
  - Pembersihan otomatis berkas kadaluwarsa terintegrasi dalam modul `modules/trash.py`.

---

## 3. Pengunci Item & Koleksi Fleksibel (*Fine-Grained Item & Album Locks*)
*Rujukan: `docs/progress/UB.md`, `U2.md`, `U2b.md`*

- **Status Terkunci Granular**:
  - Kolom `is_locked` disematkan pada berkas, catatan, dan koleksi.
  - Membuka, memutar, atau melihat pratinjau berkas terkunci mewajibkan verifikasi kata sandi pengguna untuk menerbitkan hak akses sementara (*reauth grant token* dengan cakupan `item.view` atau `album.unlock`) yang berlaku selama 15 menit.
- **Dialog Kunci Generik**:
  - Modul `static/js/item_lock.js` mengelola pembukaan item terkunci dengan integrasi modal dialog `KX.modal` dan penanganan galat terpadu.
  - Isi album atau folder yang terkunci tidak dimunculkan pada tampilan ringkasan "Semua" untuk mencegah kebocoran metadata.

---

## 4. Pratinjau Dokumen & Media Aman (*In-App Preview*)
*Rujukan: `docs/progress/UB.md`*

- **Dukungan Format Terkendali**:
  - Pratinjau berkas teks (TXT, MD, CSV, JSON) disajikan secara aman via JSON endpoint dengan batas ukuran 1 MB untuk mencegah kehabisan memori.
  - Berkas PDF dan gambar didukung untuk pratinjau *inline* menggunakan header respons `Content-Disposition: inline`.
  - Format Microsoft Office (DOCX, PPTX) tidak dipaksakan didekode langsung di browser demi keamanan dan kestabilan, melainkan disajikan opsi unduh terdekripsi.
- **Perlindungan Integritas & Otorisasi**:
  - Pratinjau mewajibkan grant token `@require_grant("doc.preview", ...)` jika berkas berstatus terkunci.
  - Verifikasi hash ciphertext sebelum dekripsi; jika ditemukan modifikasi di luar alur aplikasi, sistem mencatat peringatan manipulasi (*tamper detected*).

---

## 5. Token Perangkat Keras USB Dongle yang Atomik
*Rujukan: `docs/progress/UC1.md`, `F.md`*

- **Pendaftaran & Pengecekan Aman**:
  - Pendaftaran token USB dongle pada `/settings/register-usb` menuliskan token kriptografis `.cryptix_token` yang terikat pada volume serial number removable drive.
  - Penulisan token dilakukan secara atomik (penulisan ke berkas sementara `.tmp` lalu diganti namanya) untuk mencegah korupsi token fisik.
  - Pemeriksaan keberadaan dongle fisik terintegrasi pada langkah login tahap pertama.

---

## 6. Pembersihan Akhir & Penguatan Lingkungan (Hardening)
*Rujukan: `docs/progress/M1.md`, `U4.md`*

- **Pencabutan Kode Mati**:
  - Menghapus konstanta tak terpakai `MAGIC_PDF` dan `MAGIC_IMAGES` pada `routes/media_routes.py`.
  - Menghapus fungsi dan tabel usang yang telah ditandai *DEPRECATED* pada tahap refaktorisasi sebelumnya.
- **Pembersihan CSP & Sumber Font Lokal**:
  - Seluruh font web dialihkan ke berkas lokal di `static/fonts/`.
  - Host eksternal `fonts.googleapis.com` dan `fonts.gstatic.com` dicabut dari direktif `style-src` dan `font-src` pada `app.py`.
- **Konsistensi Nama Internal**:
  - Nama berkas unduhan kunci darurat pemulihan tetap dipertahankan sebagai `cryptix-kunci-pemulihan.txt`. Hal ini sengaja dipertahankan agar kompatibel dengan sistem lama dan tidak merusak skrip atau kebiasaan operasional pengguna.
  - Nama basis data internal (`cryptix.db`) dan token rahasia (`.cryptix_token`) dipertahankan secara utuh.

