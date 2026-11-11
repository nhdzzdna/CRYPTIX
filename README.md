# KOSYAK — Platform Arsip Digital Terenkripsi

## Deskripsi
**KOSYAK** adalah aplikasi web arsip digital pribadi berbasis Python/Flask dan SQLite yang mengamankan berkas, dokumen, audio, media visual, catatan rahasia, serta kredensial akun menggunakan kombinasi teknik kriptografi modern, steganografi, dan rantai blok integritas data.

Aplikasi ini dirancang dengan model keamanan berlapis: autentikasi multi-faktor fisik (USB dongle token), login dua tahap dengan biometrik (WebAuthn dan pengenalan wajah), hierarki kunci kriptografi (DEK/KEK), serta isolasi hak akses sementara (*reauth grant token*).

---

## Fitur Utama

1. **Hierarki Kunci Kriptografi (DEK & KEK)**
   - Setiap pengguna memiliki *Key Encryption Key* (KEK) unik yang diturunkan melalui PBKDF2-HMAC-SHA256 dari kata sandi akun dan *salt* unik.
   - Entitas rahasia memiliki *Data Encryption Key* (DEK) acak 256-bit masing-masing yang dienkripsi dengan KEK pengguna sebelum disimpan di basis data.
   - Basis data SQLite terenkripsi pada kolom-kolom sensitif dan tidak menyimpan kunci mentah.

2. **Penyimpanan Berkas Terenkripsi (AES-256-GCM)**
   - Berkas dienkripsi secara simetris menggunakan AES-256 dalam mode Galois/Counter Mode (GCM) yang memberikan kerahasiaan sekaligus jaminan integritas (*authenticated encryption*).
   - Dilengkapi *super encryption* bertahap dan kompresi zlib opsional untuk efisiensi penyimpanan.

3. **Steganografi Citra (LSB)**
   - Penyembunyian pesan dan berkas rahasia di dalam saluran piksel citra pembawa (*carrier image*) menggunakan metode *Least Significant Bit* (LSB).
   - Dilengkapi proteksi kata sandi dan verifikasi integritas pesan ekstraksi.

4. **Buku Besar Audit Rantai Blok (Hash Chain)**
   - Setiap mutasi data penting (unggah, unduh, hapus, pemindahan ke Sampah, modifikasi) dicatat dalam blok audit lokal yang saling mengikat menggunakan hash kriptografis SHA-256.
   - Deteksi otomatis terhadap perubahan atau pemalsuan data (*tamper detection*).

5. **Token Perangkat Keras (Dongle USB)**
   - Autentikasi faktor kepemilikan fisik menggunakan volume USB removable.
   - Pendaftaran dongle menulis berkas token rahasia `.cryptix_token` yang ditandatangani HMAC-SHA256 dan terikat dengan nomor seri volume drive secara atomik.

6. **Login Dua Tahap & Biometrik**
   - **Tahap 1**: Verifikasi nama pengguna dan kata sandi.
   - **Tahap 2**: Verifikasi faktor kedua melalui biometrik:
     - **WebAuthn (FIDO2/Passkey)**: Autentikasi biometrik platform bawaan perangkat (sensor sidik jari/Windows Hello/Touch ID).
     - **Pengenalan Wajah**: Deteksi wajah lokal berbasis OpenCV (LBPH Face Recognizer) dengan bimbingan posisi mata terbuka.

7. **Sistem Sampah 30 Hari (*Trash Vault*)**
   - Berkas dan catatan yang dihapus dipindahkan terlebih dahulu ke Sampah selama retensi 30 hari sebelum dapat dihapus permanen atau dibersihkan otomatis.
   - Berkas di dalam Sampah dapat dipulihkan kembali ke lokasi asalnya.

8. **Pengunci Item & Album (*Fine-Grained Item Locks*)**
   - Berkas individual maupun folder/album koleksi dapat diberi status terkunci (*locked*).
   - Mengakses atau memutar media terkunci membutuhkan otorisasi ulang kata sandi dengan penerbitan *grant token* berbasis waktu (15 menit).

---

## Arsitektur Sistem

- **Backend**: Python 3.13, Flask, SQLite3, Cryptography, PyCryptodome.
- **Frontend**: Server-Side Rendering (Jinja2) dengan CSS murni berbasis *design tokens* (`tokens.css`, `components.css`), JavaScript modular tanpa pustaka eksternal, SVG sprite icons, serta bebas skrip inline dengan kebijakan Content Security Policy (CSP) ketat (`default-src 'self'`).
- **Keamanan Sesi & Otorisasi**:
  - `Flask-Limiter` untuk mitigasi *brute-force* pada rute sensitif.
  - `@require_grant` untuk perlindungan akses aksi kritikal tanpa menyimpan kata sandi di memori sesi.
  - Seluruh aset font (`Plus Jakarta Sans` dan `JetBrains Mono`) dimuat secara lokal tanpa ketergantungan koneksi internet.

---

## Struktur Folder

```text
CRYPTIX/
├── app.py                      # Titik masuk utama aplikasi Flask & konfigurasi CSP
├── config.py                   # Konfigurasi sistem, direktori storage, dan parameter kripto
├── requirements.txt            # Daftar pustaka dependensi terpasang
├── database/                   # Skrip inisialisasi dan skema basis data SQLite
├── modules/                    # Modul logika bisnis inti
│   ├── authentication/         # Autentikasi, USB dongle, WebAuthn, wajah, & reauth
│   ├── blockchain/             # Audit ledger rantai blok hash
│   ├── cryptography/           # Primitif kripto: AES-GCM, KEK/DEK, cipher klasik
│   ├── steganography/          # Enkripsi & ekstraksi LSB citra
│   ├── strings.py              # Sentralisasi teks antarmuka Bahasa Indonesia formal
│   └── trash.py                # Manajemen siklus hidup Sampah 30 hari
├── routes/                     # Definisi rute Blueprint Flask
│   ├── auth_routes.py          # Alur login dua tahap, registrasi, logout
│   ├── collection_routes.py    # Manajemen folder dan album berkas
│   ├── document_routes.py      # Pengelolaan & pratinjau dokumen
│   ├── media_routes.py         # Streaming audio dan galeri media
│   ├── settings_routes.py      # Pengaturan profil, dongle, dan kunci pemulihan
│   └── trash_routes.py         # Halaman dan aksi Sampah
├── static/                     # Aset statis (CSS, JS, Fonts lokal, SVG sprites)
├── templates/                  # Templat HTML Jinja2
├── tests/                      # Rangkaian uji otomatis pytest
└── docs/                       # Dokumentasi arsitektur, progres, dan panduan uji
```

---

## Panduan Instalasi dan Menjalankan di Windows

### 1. Prasyarat
- Sistem Operasi: Windows 10/11
- Python: Versi 3.11 atau lebih baru (direkomendasikan Python 3.13)
- Port: `5000` tersedia di localhost

### 2. Pemasangan Virtual Environment
Buka terminal PowerShell atau Command Prompt pada direktori proyek:

```powershell
# Buat virtual environment
python -m venv venv

# Aktifkan virtual environment
.\venv\Scripts\Activate.ps1
# Atau pada CMD:
# .\venv\Scripts\activate.bat
```

### 3. Pemasangan Dependensi
Pasang paket yang telah dikunci pada `requirements.txt`:

```powershell
pip install -r requirements.txt
```

### 4. Konfigurasi Lingkungan
Buat berkas `.env` dari contoh yang tersedia jika diperlukan:

```powershell
copy .env.example .env
```

### 5. Menjalankan Aplikasi
Mulai server pengembangan lokal:

```powershell
python app.py
```
Akses aplikasi melalui peramban di alamat: `http://127.0.0.1:5000`.

---

## Menjalankan Rangkaian Uji

Seluruh pengujian unit dan integrasi dijalankan menggunakan `pytest`:

```powershell
# Menjalankan seluruh rangkaian tes (suite penuh)
python -m pytest -q

# Menjalankan pengujian spesifik per modul
python -m pytest tests/test_headers_csp.py -v
python -m pytest tests/test_ub_sampah.py -v
```

---

## Keterbatasan Sistem

Pengguna dan penguji diharapkan memahami beberapa batasan fungsional aplikasi saat ini:
1. **WebAuthn**: Pada peramban atau perangkat tertentu, autentikator platform WebAuthn dapat meminta pembuatan atau verifikasi PIN perangkat keras selain sentuhan biometrik fisik.
2. **Pengenalan Wajah**: Algoritma deteksi mata terbuka pada proses pendaftaran wajah bertujuan membantu kesiapan posisi wajah pengguna, namun **bukan merupakan perlindungan anti-spoofing tingkat lanjut** (seperti *liveness detection* 3D atau inframerah).
3. **Pratinjau Dokumen**: Fitur pratinjau langsung di dalam aplikasi saat ini hanya mendukung berkas teks biasa (TXT, MD, CSV, JSON) serta PDF. Format dokumen Microsoft Office (DOCX, PPTX, XLSX) **tidak didukung untuk pratinjau langsung** dan hanya dapat diunduh dalam bentuk terenkripsi/didekripsi utuh.
4. **Pencarian Data**: Fitur pencarian pada halaman berkas, audio, dan media bekerja sebagai filter visual pada daftar yang sedang aktif di halaman tersebut, **bukan mesin pencari indeks global**.
5. **Ekspor Data**: Tidak tersedia fitur ekspor data massal ke format CSV atau format tabular lainnya.
6. **Pemulihan Akun**: Apabila pengguna kehilangan kata sandi akun sekaligus dongle USB token fisiknya, **seluruh data terenkripsi tidak dapat dipulihkan kembali** karena tidak ada pintu belakang (*backdoor*) kriptografis.
7. **Tujuan Pengembangan**: Aplikasi ini dikembangkan sebagai purwarupa proyek pembelajaran keamanan aplikasi dan kriptografi, **bukan produk komersial siap produksi massal**.
