"""
modules/strings.py
───────────────────
Centralised user-facing string constants for CRYPTIX.
All messages are written in formal Indonesian (Bahasa Indonesia formal).

Usage::

    from modules.strings import MSG
    flash(MSG.LOGIN_REQUIRED, "warning")
    return jsonify({"error": MSG.EMPTY_MESSAGE}), 400
"""

from __future__ import annotations


class MSG:
    """Static string constants — do NOT add f-strings here."""

    # ── Authentication ────────────────────────────────────────────────────────
    LOGIN_REQUIRED          = "Silakan masuk terlebih dahulu untuk mengakses halaman ini."
    REGISTER_FIELDS_REQUIRED = "Semua kolom harus diisi."
    REGISTER_PASSWORD_MISMATCH = "Kata sandi tidak cocok."
    REGISTER_USERNAME_INVALID = "Nama pengguna harus 3–32 karakter dan hanya boleh memuat huruf, angka, garis bawah, atau titik."
    REGISTER_EMAIL_INVALID  = "Format surel tidak valid."
    REGISTER_PASSWORD_TOO_SHORT = "Kata sandi minimal 12 karakter."
    REGISTER_PASSWORD_USERNAME = "Kata sandi tidak boleh memuat nama pengguna."
    REGISTER_PASSWORD_COMMON = "Kata sandi termasuk daftar kata sandi umum. Gunakan kata sandi lain."
    REGISTER_PASSWORD_COMPLEX = "Kata sandi harus memuat setidaknya 3 dari 4 jenis karakter: huruf kecil, huruf besar, angka, dan simbol."
    REGISTER_USB_REQUIRED   = "Pilih dongle yang terpasang untuk mendaftarkan akun."
    REGISTER_USB_INVALID    = "Dongle terpilih tidak terdeteksi. Colokkan kembali lalu muat ulang halaman."
    RECOVERY_CHECK_REQUIRED = "Centang konfirmasi bahwa kunci pemulihan sudah disimpan untuk melanjutkan."
    RECOVERY_ONLY_ONCE      = "Kunci pemulihan hanya ditampilkan satu kali dan tidak dapat dilihat kembali."
    SETUP_BIOMETRIC_REQUIRED = "Daftarkan setidaknya satu biometrik (wajah atau sidik jari) untuk menyelesaikan penyiapan."
    SETUP_COMPLETE          = "Penyiapan keamanan selesai. Anda dapat mulai menggunakan CRYPTIX."

    LOGIN_FAILED            = "{error}"   # error string comes from auth module
    LOGIN_SUCCESS           = "Selamat datang, {username}!"
    LOGOUT_SUCCESS          = "Anda telah keluar dari sistem."
    SESSION_EXPIRED         = "Sesi Anda telah berakhir. Silakan masuk kembali."
    CSRF_INVALID            = "Token keamanan tidak valid atau telah kedaluwarsa. Muat ulang halaman lalu coba kembali."

    # ── Authentication module errors ──────────────────────────────────────────
    AUTH_INVALID_CREDENTIALS = "Nama pengguna atau kata sandi tidak valid."
    AUTH_USB_NOT_REGISTERED  = "Akun ini belum memiliki token USB yang terdaftar."
    AUTH_USB_INVALID         = "Token USB tidak terdeteksi atau tidak valid."
    AUTH_FACE_FAILED         = "Verifikasi wajah gagal."
    AUTH_FINGERPRINT_FAILED  = "Verifikasi sidik jari gagal."
    AUTH_REGISTER_CONFLICT   = "Nama pengguna atau surel sudah digunakan."
    AUTH_REGISTER_ERROR      = "Pendaftaran gagal karena kesalahan sistem."

    # ── Biometrics ────────────────────────────────────────────────────────────
    FACE_NO_FRAMES               = "Tidak ada bingkai yang diterima."
    FACE_MODEL_SAVED             = "Model wajah berhasil disimpan."
    FACE_NOT_ENOUGH_SAMPLES      = "Tidak cukup sampel wajah yang terdeteksi."
    FACE_VERIFIED                = None   # returned as JSON boolean; no message
    USB_NO_DRIVE                 = "Tidak ada media penyimpanan lepas yang terdeteksi."
    USB_REGISTERED               = "Token USB berhasil didaftarkan."
    USB_NOT_ATTACHED             = "Colokkan dongle terdaftar lalu masuk kembali."
    USB_STARTUP_BLOCKED          = "Aplikasi berhenti karena dongle terdaftar tidak terpasang. Colokkan dongle lalu jalankan ulang aplikasi."
    USB_STARTUP_UNREGISTERED     = "Aplikasi berhenti karena belum ada dongle terdaftar bagi akun yang ada. Colokkan dongle lalu daftarkan ulang akun, atau reset basis data dengan perintah python -m database.reset_db."


    # ── Vault (file) ──────────────────────────────────────────────────────────
    VAULT_NO_FILE_SELECTED   = "Tidak ada file yang dipilih."
    VAULT_FILE_TYPE_DENIED   = "Jenis file tidak diizinkan."
    VAULT_FILE_TOO_LARGE     = "Ukuran file melebihi batas maksimum."
    VAULT_UPLOAD_SUCCESS     = 'File "{filename}" berhasil dienkripsi dan diunggah.'
    VAULT_DECRYPT_FAILED     = "Dekripsi gagal — file mungkin rusak atau kunci tidak valid."
    VAULT_FILE_DELETED       = "File berhasil dihapus."

    # ── Secure Notes ──────────────────────────────────────────────────────────
    NOTES_FIELDS_REQUIRED    = "Judul dan isi catatan harus diisi."
    NOTES_SAVED              = "Catatan berhasil disimpan."
    NOTES_UPDATED            = "Catatan berhasil diperbarui."
    NOTES_DELETED            = "Catatan berhasil dihapus."

    # ── Account Vault (credentials) ───────────────────────────────────────────
    ACCOUNT_FIELDS_REQUIRED  = "Nama situs, nama pengguna, dan kata sandi harus diisi."
    ACCOUNT_ADDED            = "Kredensial berhasil ditambahkan."
    ACCOUNT_DELETED          = "Kredensial berhasil dihapus."

    # ── Steganography ─────────────────────────────────────────────────────────
    STEGO_NO_CARRIER         = "Silakan unggah gambar pembawa (carrier image)."
    STEGO_EMPTY_MESSAGE      = "Pesan tidak boleh kosong."
    STEGO_INVALID_CARRIER    = "Format gambar pembawa harus PNG/JPG/BMP."
    STEGO_EMBED_FAILED       = "Penyembunyian pesan gagal: {error}"
    STEGO_EMBED_SUCCESS      = "Pesan berhasil disembunyikan ke dalam gambar."
    STEGO_EXTRACT_FAILED     = "Ekstraksi pesan gagal: {error}"
    STEGO_EXTRACT_SUCCESS    = "Pesan berhasil diekstrak: {message}"
    STEGO_DELETED            = "Gambar stego berhasil dihapus."
    STEGO_NO_MESSAGE         = "Tidak ditemukan pesan yang valid; gambar bukan gambar stego."
    STEGO_DECODE_FAILED      = "Muatan hasil ekstraksi tidak dapat dibaca sebagai teks UTF-8."
    STEGO_DECRYPT_FAILED     = "Dekripsi pesan gagal; kunci mungkin salah."
    STEGO_NO_PAYLOAD_FILE     = "Silakan pilih berkas yang akan disisipkan."
    STEGO_KEY_REQUIRED       = "Kunci steganografi wajib disediakan untuk menyisipkan atau mengekstrak muatan."
    STEGO_IMAGE_TOO_LARGE    = "Dimensi gambar pembawa melebihi batas {max}x{max} piksel."
    STEGO_TOO_LARGE          = "Muatan terlalu besar: {used} byte melebihi kapasitas {capacity} byte."
    STEGO_TAMPERED           = "Muatan tidak cocok: kunci salah atau isi gambar telah berubah."
    STEGO_VERSION_UNSUPPORTED = "Versi muatan steganografi tidak didukung."
    STEGO_NOT_TEXT           = "Muatan dalam gambar berupa berkas, bukan teks."
    STEGO_NOT_FILE           = "Muatan dalam gambar berupa teks, bukan berkas."
    STEGO_PNG_WARNING        = "Gambar hasil disimpan sebagai PNG; menyimpan ulang sebagai JPEG akan merusak muatan."
    STEGO_FILE_EXTRACTED     = "Berkas berhasil diekstrak dari gambar."

    # ── Crypto Tools ───────────────────────────────────────────────────────────
    CRYPTO_PASSPHRASE_REQUIRED = "Isi frasa sandi untuk Super Encryption."
    CRYPTO_UNKNOWN_CIPHER      = "Algoritma tidak dikenal."
    CRYPTO_OPERATION_FAILED    = "Operasi kriptografi gagal; periksa kembali input Anda."

    # ── Media Vault ───────────────────────────────────────────────────────────
    MEDIA_DECRYPT_FAILED     = "Dekripsi file media gagal."
    MEDIA_WINAMP_OPENED      = "File dibuka di Winamp. Berkas sementara akan dihapus otomatis."
    MEDIA_WINAMP_ERROR       = "Kesalahan Winamp: {error}"
    WINAMP_NOT_FOUND         = "Winamp tidak ditemukan pada lokasi yang dikonfigurasi."
    WINAMP_START_FAILED      = "Winamp tidak dapat dijalankan."

    # ── Settings ──────────────────────────────────────────────────────────────
    SETTINGS_WRONG_PASSWORD  = "Kata sandi lama tidak valid."
    SETTINGS_PASSWORD_MISMATCH = "Kata sandi baru tidak cocok."
    SETTINGS_PASSWORD_CHANGED  = "Kata sandi berhasil diubah. Silakan masuk kembali."
    SETTINGS_PASSWORD_SAME     = "Kata sandi baru harus berbeda dari kata sandi saat ini."
    SETTINGS_PASSWORD_REWRAP_FAILED = "Kata sandi gagal diubah karena kunci tidak dapat dibungkus ulang."
    SETTINGS_USB_MISSING       = "Dongle terdaftar tidak terpasang atau tidak cocok."
    SETTINGS_USB_NO_DRIVE      = "Tidak ada media penyimpanan lepas yang terdeteksi."
    SETTINGS_USB_REGISTERED    = "Token USB berhasil didaftarkan."
    SETTINGS_BIOMETRIC_DELETED = "Kredensial WebAuthn berhasil dihapus."
    SETTINGS_BIOMETRIC_NOT_FOUND = "Kredensial WebAuthn tidak ditemukan untuk akun ini."
    SETTINGS_BIOMETRIC_LAST    = "Tidak dapat menghapus satu-satunya biometrik. Daftarkan wajah atau kredensial lain terlebih dahulu."
    SETTINGS_SESSION_TIMEOUT_INVALID = "Pilihan batas sesi tidak valid."
    SETTINGS_SESSION_TIMEOUT_SAVED = "Batas diam sesi diperbarui."
    SETTINGS_RECOVERY_FAILED   = "Kunci pemulihan baru tidak dapat dibuat karena sesi atau dongle tidak tersedia."

    # ── Assistant ────────────────────────────────────────────────────────────
    ASSISTANT_EMPTY_MESSAGE  = "Pesan tidak boleh kosong."

    # ── Sesi F: login dua tahap (butir 2.4) ──────────────────────────────────
    LOGIN_STAGE1_FAILED   = "Login gagal. Periksa kredensial Anda dan pastikan dongle terpasang"
    LOGIN_STAGE_ORDER     = "Permintaan tidak sesuai urutan tahap login. Muat ulang halaman lalu coba kembali."
    LOGIN_PENDING_EXPIRED = "Proses masuk kedaluwarsa. Silakan mulai kembali dari awal."
    LOGIN_BIOMETRIC_NONE  = "Belum ada metode biometrik terdaftar untuk akun ini. Selesaikan penyiapan keamanan terlebih dahulu."
    LOGIN_BIOMETRIC_FAILED = "Verifikasi biometrik gagal. Coba sekali lagi."
    WEBAUTHN_REGISTER_FAILED = "Pendaftaran WebAuthn gagal. Gunakan perangkat platform lalu coba lagi."
    WEBAUTHN_DUPLICATE    = "Kredensial WebAuthn tersebut sudah terdaftar."
    WEBAUTHN_CHALLENGE_EXPIRED = "Tantangan WebAuthn kedaluwarsa. Muat ulang halaman lalu coba lagi."
    WEBAUTHN_NO_CREDENTIAL = "Kredensial WebAuthn tidak ditemukan untuk akun ini."
    WEBAUTHN_FAILED       = "Verifikasi WebAuthn gagal. Coba sekali lagi."
    # ── Sesi H: autentikasi ulang / step-up ───────────────────────────────────
    REAUTH_REQUIRED           = "Autentikasi ulang diperlukan untuk melanjutkan."
    REAUTH_INVALID            = "Grant autentikasi ulang tidak valid atau sudah kedaluwarsa."
    REAUTH_SESSION_MISMATCH   = "Grant autentikasi ulang ini milik sesi lain."
    REAUTH_SCOPE_MISMATCH     = "Grant tidak berlaku untuk tindakan ini."
    REAUTH_RESOURCE_MISMATCH  = "Grant tidak berlaku untuk sumber daya ini."
    REAUTH_METHOD_UNSUPPORTED = "Metode autentikasi ulang tidak didukung."
    REAUTH_WEBAUTHN_PENDING   = "WebAuthn belum tersedia pada versi ini."
    REAUTH_PASSWORD_REQUIRED  = "Kata sandi wajib diisi."
    REAUTH_FAILED             = "Kata sandi tidak valid."
    REAUTH_SCOPE_UNKNOWN      = "Scope autentikasi ulang tidak dikenal."
    # ── Sesi J1: Media Vault dan Steganography ────────────────────────────────
    MEDIA_STREAM_UNSUPPORTED = "Format ini hanya tersedia untuk unduhan dan tidak diputar di browser."
    MEDIA_DOWNLOAD_ONLY      = "Hanya unduh — format ini mungkin tidak dapat diputar di browser."
    MEDIA_TEMP_WARNING       = "Winamp memerlukan berkas plaintext sementara di disk. Berkas dihapus otomatis setelah 60 detik dengan penimpaan nol sebagai upaya terbaik; penghapusan permanen tidak dapat dijamin pada SSD atau media penyimpanan modern."
    MEDIA_RANGE_INVALID      = "Rentang byte tidak valid."
    STEGO_PASSPHRASE_REQUIRED = "Passphrase wajib diisi bila memilih kunci passphrase."
    STEGO_EXTRACT_TEXT_SUCCESS = "Pesan berhasil diekstrak."
    STEGO_EXTRACT_FILE_SUCCESS = "Berkas berhasil diekstrak."
    # ── Sesi G: autentikasi ulang WebAuthn ────────────────────────────────────
    REAUTH_WEBAUTHN_FAILED    = "Verifikasi WebAuthn gagal. Coba sekali lagi."
    REAUTH_WEBAUTHN_NONE      = "Belum ada kredensial WebAuthn terdaftar untuk akun ini."
    FACE_NO_SESSION_KEY       = "Kunci sesi tidak tersedia. Muat ulang halaman lalu coba kembali."
    FACE_CAPTURE_TOO_SHORT    = "Pendaftaran wajah memerlukan minimal 30 frame selama sedikitnya 3 detik."
    ACCOUNT_RECOVERY_FAILED   = "Nama pengguna atau kunci pemulihan tidak valid."
    ACCOUNT_RECOVERY_USB_REQUIRED = "Pilih dongle baru yang terpasang untuk memulihkan akun."
    ACCOUNT_RECOVERY_DONE     = "Pemulihan akun berhasil. Simpan kunci pemulihan baru, lalu masuk kembali."
    # ── Sesi I: Account Vault, Secure Notes, My Vault ─────────────────────────
    ACCOUNT_UPDATED           = "Kredensial berhasil diperbarui."
    VAULT_FILE_CONTENT_INVALID = "Isi file tidak sesuai dengan jenisnya."
    # ── GL: pembatas laju, galat JSON, dan detektor wajah ─────────────────────
    RATE_LIMITED              = "Anda terlalu sering mengirim permintaan. Silakan tunggu beberapa saat lalu coba kembali."
    ERROR_BAD_REQUEST         = "Permintaan Anda tidak dapat diproses. Periksa kembali input yang dikirim."
    ERROR_UNAUTHORIZED        = "Silakan masuk terlebih dahulu untuk mengakses sumber daya ini."
    ERROR_FORBIDDEN           = "Anda tidak memiliki izin untuk mengakses sumber daya ini."
    ERROR_NOT_FOUND           = "Halaman atau sumber daya yang Anda minta tidak ditemukan."
    ERROR_METHOD_NOT_ALLOWED  = "Metode permintaan tidak diizinkan untuk sumber daya ini."
    ERROR_TOO_LARGE           = "Ukuran berkas melebihi batas maksimum yang diizinkan."
    ERROR_INTERNAL            = "Terjadi kesalahan internal. Silakan coba kembali beberapa saat lagi."
    FACE_DETECTOR_UNAVAILABLE = "Detektor wajah tidak tersedia. Periksa pemasangan OpenCV."
    # ── N1: kunci pemulihan, pendaftaran wajah, username tersamar ─────────────
    RECOVERY_PAGE_TITLE       = "Simpan Kunci Pemulihan"
    RECOVERY_KEY_EXPLAIN      = "Kunci ini membuka akun bila password atau dongle hilang. Tidak dapat ditampilkan lagi."
    RECOVERY_ONCE_HINT        = "Kunci ditampilkan satu kali saja. Simpan di tempat aman sebelum melanjutkan."
    RECOVERY_COPY_LABEL       = "Salin"
    RECOVERY_DOWNLOAD_LABEL   = "Unduh .txt"
    RECOVERY_CONFIRM_LABEL    = "Saya sudah menyimpan kunci ini"
    RECOVERY_CONTINUE_LABEL   = "Lanjut ke Penyiapan Keamanan"
    RECOVERY_BACK_LABEL       = "Kembali ke Halaman Masuk"
    RECOVERY_COPY_OK          = "Kunci disalin ke clipboard."
    RECOVERY_COPY_FAILED      = "Gagal menyalin. Pilih teks kunci lalu salin secara manual."
    RECOVERY_DOWNLOAD_OK      = "Berkas kunci pemulihan diunduh."
    RECOVERY_FILENAME         = "cryptix-kunci-pemulihan.txt"
    RECOVERY_FILE_HEADER      = "CRYPTIX - Kunci Pemulihan"
    RECOVERY_FILE_HINT        = "Simpan berkas ini di tempat aman. Kunci tidak dapat ditampilkan lagi."
    SETUP_FACE_BUTTON         = "Daftarkan Wajah (30 frame / 3 detik)"
    SETUP_FACE_GUIDE          = "Hadapkan wajah ke kamera, lalu gerakkan kepala pelan selama pengambilan gambar."
    SETUP_FACE_PRIVACY        = "Sistem mengambil sekitar 30 gambar dalam beberapa detik untuk membuat templat wajah. Foto tidak disimpan; hanya templat terenkripsi yang disimpan."
    SETUP_FACE_DETECTED       = "Wajah terdeteksi."
    SETUP_FACE_NOT_DETECTED   = "Wajah tidak terdeteksi. Hadapkan wajah ke kamera."
    SETUP_FACE_DETECT_OFF     = "Peramban ini tidak mendukung pemeriksaan wajah langsung. Ikuti petunjuk posisi di layar."
    SETUP_FACE_PREPARING      = "Menyiapkan kamera..."
    SETUP_FACE_CAPTURING      = "Mengambil gambar: {n} dari 30"
    SETUP_FACE_SENDING        = "Mengirim sampel..."
    SETUP_FACE_CAMERA_FAILED  = "Kamera tidak dapat dibuka. Periksa izin kamera lalu coba lagi."
    SETUP_FACE_FAILED         = "Pendaftaran wajah gagal."
    FACE_MULTIPLE_FACES       = "Pendaftaran ditolak: terdeteksi lebih dari satu wajah. Pastikan hanya satu wajah di kamera."
    FACE_LOW_DETECTION_RATE   = "Pendaftaran ditolak: wajah terdeteksi di kurang dari 80% frame. Hadapkan wajah ke kamera dan coba lagi."
    SETUP_FACE_MULTIPLE       = "Lebih dari satu wajah terdeteksi. Sisakan satu wajah di kamera."
