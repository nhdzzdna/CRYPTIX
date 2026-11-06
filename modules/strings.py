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
    REGISTER_FAILED         = "Pendaftaran gagal: {error}"
    REGISTER_SUCCESS        = "Akun berhasil dibuat! Silakan masuk."
    LOGIN_FAILED            = "{error}"   # error string comes from auth module
    LOGIN_SUCCESS           = "Selamat datang, {username}!"
    LOGOUT_SUCCESS          = "Anda telah keluar dari sistem."

    # ── Authentication module errors ──────────────────────────────────────────
    AUTH_INVALID_CREDENTIALS = "Nama pengguna atau kata sandi tidak valid."
    AUTH_USB_NOT_REGISTERED  = "Akun ini belum memiliki token USB yang terdaftar."
    AUTH_USB_INVALID         = "Token USB tidak terdeteksi atau tidak valid."
    AUTH_FACE_FAILED         = "Verifikasi wajah gagal."
    AUTH_FINGERPRINT_FAILED  = "Verifikasi sidik jari gagal."
    AUTH_REGISTER_CONFLICT   = "Nama pengguna atau surel sudah digunakan."
    AUTH_REGISTER_ERROR      = "Pendaftaran gagal karena kesalahan sistem."

    # ── Biometrics ────────────────────────────────────────────────────────────
    FINGERPRINT_INVALID_FORMAT   = "Gambar sidik jari harus berformat PNG/JPG/BMP."
    FINGERPRINT_REGISTERED       = "Sidik jari berhasil didaftarkan."
    FACE_NO_FRAMES               = "Tidak ada bingkai yang diterima."
    FACE_MODEL_SAVED             = "Model wajah berhasil disimpan."
    FACE_NOT_ENOUGH_SAMPLES      = "Tidak cukup sampel wajah yang terdeteksi."
    FACE_VERIFIED                = None   # returned as JSON boolean; no message
    USB_NO_DRIVE                 = "Tidak ada media penyimpanan lepas yang terdeteksi."
    USB_REGISTERED               = "Token USB berhasil didaftarkan."

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
    SETTINGS_USB_NO_DRIVE      = "Tidak ada media penyimpanan lepas yang terdeteksi."
    SETTINGS_USB_REGISTERED    = "Token USB berhasil didaftarkan."

    # ── Assistant ────────────────────────────────────────────────────────────
    ASSISTANT_EMPTY_MESSAGE  = "Pesan tidak boleh kosong."
