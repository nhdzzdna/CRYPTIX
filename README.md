
# CRYPTIX — Digital Archive Security Platform

## Deskripsi
CRYPTIX adalah aplikasi web arsip digital pribadi berbasis Python/Flask yang mengamankan file, teks, gambar, kredensial akun, dan log aktivitas dengan berbagai teknik kriptografi modern dan klasik.

Dikembangkan sebagai proyek akhir mata kuliah Kriptografi oleh Kelompok 3.

---

## Cara Instalasi

```bash
# 1. Clone / ekstrak proyek
cd CRYPTIX

# 2. Buat virtual environment (disarankan)
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # Linux/macOS

# 3. Install dependensi
pip install -r requirements.txt

# 4. Salin template konfigurasi
copy .env.example .env      # Windows
# cp .env.example .env      # Linux/macOS

# 5. Edit .env sesuai kebutuhan (opsional untuk development)

# 6. Jalankan aplikasi
python app.py
```

Buka browser di `http://127.0.0.1:5000`.

---

## Cara Menyiapkan USB Token

1. Colokkan flashdisk yang akan dijadikan token.
2. Login ke CRYPTIX, buka **Settings → Security → USB Token**.
3. Klik **"Register USB Token"** — aplikasi membaca serial number volume dan menulis file `.cryptix_token` yang ditandatangani HMAC ke root flashdisk.
4. Set `USB_REQUIRED = True` di `config.py` untuk mengaktifkan wajib USB saat login.
5. Setiap kali login, flashdisk yang sama harus tercolok.

> **Catatan:** Pada komputer tanpa drive removable, pastikan `USB_REQUIRED = False` (default) agar bisa diuji.

---

## Cara Mendaftarkan Biometrik

### Face Recognition
1. Buka halaman **Register** dan isi data akun.
2. Di bagian **Face Registration**, klik **"Start Camera"** — webcam akan aktif.
3. Posisikan wajah di depan kamera lalu klik **"Capture"**. Sistem mengambil 30 sampel wajah.
4. Klik **"Save Face Data"** untuk menyimpan model LBPH.
5. Saat login, klik **"Verify Face"** dan hadapkan kamera ke wajah Anda.

### Fingerprint (Simulasi Akademik)
1. Di halaman **Register**, unggah citra sidik jari (PNG/JPG) pada bagian **Fingerprint Registration**.
2. Saat login, unggah citra sidik jari yang sama (atau citra yang sangat mirip) pada bagian **Fingerprint Login**.
3. Sistem menggunakan ORB feature matching dari OpenCV untuk membandingkan citra.

> ⚠️ **Catatan Penting:** Fitur fingerprint adalah **simulasi akademik menggunakan pencocokan citra**. Ini BUKAN pengenalan sidik jari dari sensor perangkat keras. Dalam kondisi nyata, citra harus berasal dari scanner sidik jari terdedikasi. Akurasi sangat bergantung pada kualitas dan konsistensi citra yang diunggah.

---

## Tabel Pemetaan Ketentuan Dosen → Implementasi

| No | Ketentuan Dosen | Implementasi |
|----|----------------|-------------|
| 1a | Face Recognition (OpenCV LBPH) | `modules/authentication/face_recognition.py` |
| 1b | Fingerprint (ORB matching simulasi) | `modules/authentication/fingerprint.py` |
| 2  | Password PBKDF2-HMAC-SHA256, 600 000 iterasi | `modules/authentication/password_hash.py` |
| 3  | USB Token (HMAC + serial number) | `modules/authentication/usb_authentication.py` |
| 4  | Super Encryption (Vigenere→Playfair→ChaCha20→Blowfish) | `modules/cryptography/super_encryption.py` |
| 5  | Crypto Tools (uji tiap cipher) | `routes/crypto_routes.py` + `templates/crypto_tools.html` |
| 6  | Enkripsi file AES-256-GCM | `modules/cryptography/file_encryption.py` |
| 7  | Enkripsi database AES-256-GCM (HKDF) | `modules/cryptography/database_encryption.py` |
| 8  | Steganografi LSB pada PNG | `modules/steganography/lsb.py` |
| 9  | Blockchain hash chain di SQLite | `modules/blockchain/blockchain.py` |
| 10 | Winamp integration + HTML5 fallback | `modules/media/winamp_integration.py` |
| 11 | Key management (PBKDF2, session-only) | `modules/cryptography/key_management.py` |
| 12 | Semua menu & halaman | `routes/` + `templates/` |

---

## Batasan yang Jujur

| Batasan | Keterangan |
|---------|-----------|
| Fingerprint adalah simulasi | Menggunakan pencocokan citra ORB, bukan sensor hardware. Tidak cocok untuk produksi. |
| USB token bergantung pada psutil | Deteksi drive removable; volume serial number mungkin berbeda di VM atau WSL. |
| Face Recognition offline & sederhana | Menggunakan LBPH OpenCV, akurasi lebih rendah dibanding model deep learning. |
| Winamp hanya Windows | `subprocess` memanggil winamp.exe; fallback HTML5 tersedia untuk platform lain. |
| SQLite single-file | Tidak disarankan untuk deployment multi-user skala besar. |
| Kunci hanya di session | Jika session habis, user harus login ulang; tidak ada key recovery. |

---

## Struktur Folder

```
CRYPTIX/
├── app.py                    # Entry point Flask
├── config.py                 # Semua konfigurasi & konstanta
├── requirements.txt
├── README.md
├── database/
│   ├── db.py                 # Koneksi & helper SQLite
│   ├── schema.sql
│   └── cryptix.db            # Dibuat otomatis saat pertama dijalankan
├── modules/
│   ├── authentication/       # auth, password, face, fingerprint, usb
│   ├── cryptography/         # key management, 4 cipher, super enc, file enc, db enc
│   ├── steganography/        # LSB
│   ├── blockchain/           # hash chain
│   └── media/                # winamp integration
├── routes/                   # Blueprint Flask per fitur
├── templates/                # Jinja2 HTML
├── static/                   # CSS, JS, images
├── storage/
│   ├── encrypted_files/
│   ├── temporary_files/
│   └── stego_images/
└── tests/                    # pytest
```
