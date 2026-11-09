"""
modules/assistant/knowledge.py
──────────────────────────────
Basis pengetahuan Security Assistant untuk fitur dan cara pakai CRYPTIX.

Asisten tetap berbasis aturan: tidak ada model bahasa dan tidak ada panggilan
keluar. Setiap topik memuat kata kunci, sinonim, dan rujukan ke teks jawaban di
``modules.strings.MSG``. Pencocokan memakai frasa utuh agar kata umum seperti
"akun" atau "file" tidak memicu topik yang salah.

Topik disusun dari perilaku kode yang benar-benar ada. Fitur yang tidak
diimplementasikan (misalnya liveness, enkripsi end-to-end, atau login sidik
jari) tidak diklaim tersedia.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from modules.strings import MSG


@dataclass(frozen=True)
class TopikPengetahuan:
    """Satu topik panduan beserta frasa pemicu dan kunci teks jawabannya."""

    id: str
    judul: str
    kata_kunci: tuple[str, ...]
    sinonim: tuple[str, ...]
    kunci_msg: str

    @property
    def jawaban(self) -> str:
        """Teks jawaban diambil dari ``MSG`` agar terpusat."""
        return getattr(MSG, self.kunci_msg)


DAFTAR_TOPIK: tuple[TopikPengetahuan, ...] = (
    TopikPengetahuan(
        id="daftar_akun",
        judul="Daftar Akun",
        kata_kunci=(
            "daftar akun", "buat akun", "registrasi akun", "sign up",
        ),
        sinonim=(
            "registrasi", "mendaftar akun", "membuat akun", "cara daftar",
            "buat akun baru",
        ),
        kunci_msg="ASSISTANT_KB_DAFTAR_AKUN",
    ),
    TopikPengetahuan(
        id="login_dua_tahap",
        judul="Login Dua Tahap",
        kata_kunci=(
            "login dua tahap", "masuk dua tahap", "tahap login",
            "login tahap 2",
        ),
        sinonim=(
            "cara login", "cara masuk", "proses login", "masuk akun",
            "verifikasi login",
        ),
        kunci_msg="ASSISTANT_KB_LOGIN_DUA_TAHAP",
    ),
    TopikPengetahuan(
        id="dongle_usb",
        judul="Dongle USB",
        kata_kunci=(
            "dongle", "usb token", "token usb", "flashdisk",
        ),
        sinonim=(
            "daftar ulang dongle", "mendaftarkan dongle", "dongle terpasang",
            "usb dongle", "hardware token",
        ),
        kunci_msg="ASSISTANT_KB_DONGLE_USB",
    ),
    TopikPengetahuan(
        id="setup_awal",
        judul="Penyiapan Awal",
        kata_kunci=(
            "setup awal", "penyiapan awal", "halaman setup",
            "wajib biometrik",
        ),
        sinonim=(
            "lewati setup", "setup akun", "penyiapan akun",
        ),
        kunci_msg="ASSISTANT_KB_SETUP_AWAL",
    ),
    TopikPengetahuan(
        id="wajah",
        judul="Pendaftaran Wajah",
        kata_kunci=(
            "pendaftaran wajah", "daftar wajah", "daftar ulang wajah",
            "templat wajah",
        ),
        sinonim=(
            "wajah", "mendaftar wajah", "mendaftarkan wajah",
            "face recognition", "pengenalan wajah", "kamera wajah",
        ),
        kunci_msg="ASSISTANT_KB_WAJAH",
    ),
    TopikPengetahuan(
        id="verifikasi_wajah",
        judul="Verifikasi Wajah",
        kata_kunci=(
            "verifikasi wajah", "scan wajah", "login wajah", "cek wajah",
        ),
        sinonim=(
            "wajah saat login", "verifikasi kamera", "face verification",
        ),
        kunci_msg="ASSISTANT_KB_VERIFIKASI_WAJAH",
    ),
    TopikPengetahuan(
        id="webauthn",
        judul="WebAuthn",
        kata_kunci=(
            "webauthn", "passkey", "windows hello", "kunci keamanan",
        ),
        sinonim=(
            "authenticator platform", "kredensial webauthn",
            "tambah webauthn", "mendaftarkan webauthn",
        ),
        kunci_msg="ASSISTANT_KB_WEBAUTHN",
    ),
    TopikPengetahuan(
        id="biometrik",
        judul="Metode Biometrik",
        kata_kunci=(
            "biometrik", "biometrics", "metode biometrik",
        ),
        sinonim=(
            "autentikasi biometrik", "biometrik terdaftar",
            "hapus biometrik",
        ),
        kunci_msg="ASSISTANT_KB_BIOMETRIK",
    ),
    TopikPengetahuan(
        id="kunci_pemulihan",
        judul="Kunci Pemulihan",
        kata_kunci=(
            "kunci pemulihan", "recovery key", "kode pemulihan",
        ),
        sinonim=(
            "simpan kunci pemulihan", "menyimpan kunci pemulihan",
            "kunci cadangan", "recovery code",
        ),
        kunci_msg="ASSISTANT_KB_KUNCI_PEMULIHAN",
    ),
    TopikPengetahuan(
        id="pemulihan_akun",
        judul="Pemulihan Akun",
        kata_kunci=(
            "pemulihan akun", "account recovery", "pulihkan akun",
            "lupa password",
        ),
        sinonim=(
            "akun hilang", "tidak bisa login", "reset akun",
            "pulihkan akses", "memulihkan akun",
        ),
        kunci_msg="ASSISTANT_KB_PEMULIHAN_AKUN",
    ),
    TopikPengetahuan(
        id="ganti_password",
        judul="Ganti Password",
        kata_kunci=(
            "ganti password", "ubah password", "ganti kata sandi",
            "ubah kata sandi",
        ),
        sinonim=(
            "change password", "mengganti password", "mengubah password",
            "mengganti kata sandi", "mengubah kata sandi", "ganti sandi",
            "password baru",
        ),
        kunci_msg="ASSISTANT_KB_GANTI_PASSWORD",
    ),
    TopikPengetahuan(
        id="reveal_akun",
        judul="Reveal Kredensial",
        kata_kunci=(
            "reveal akun", "tampilkan kredensial", "lihat password",
            "buka password",
        ),
        sinonim=(
            "menampilkan kredensial", "tampilkan username",
            "menampilkan username", "lihat kredensial", "melihat password",
            "membuka password", "reveal password", "ikon mata",
        ),
        kunci_msg="ASSISTANT_KB_REVEAL_AKUN",
    ),
    TopikPengetahuan(
        id="account_vault",
        judul="Account Vault",
        kata_kunci=(
            "account vault", "akun vault", "kredensial situs",
            "tambah kredensial",
        ),
        sinonim=(
            "simpan kredensial", "menambah kredensial",
            "menyimpan kredensial", "password situs", "manajer password",
        ),
        kunci_msg="ASSISTANT_KB_ACCOUNT_VAULT",
    ),
    TopikPengetahuan(
        id="catatan_aman",
        judul="Secure Notes",
        kata_kunci=(
            "secure notes", "catatan aman", "catatan rahasia",
            "catatan terenkripsi",
        ),
        sinonim=(
            "tambah catatan", "menambah catatan", "simpan catatan",
            "menyimpan catatan", "buka catatan", "membuka catatan", "notes",
        ),
        kunci_msg="ASSISTANT_KB_CATATAN_AMAN",
    ),
    TopikPengetahuan(
        id="unggah_berkas",
        judul="My Vault",
        kata_kunci=(
            "my vault", "unggah berkas", "upload file", "unggah file",
        ),
        sinonim=(
            "upload berkas", "mengunggah berkas", "mengunggah file",
            "simpan berkas", "unduh berkas", "mengunduh berkas",
            "documents",
        ),
        kunci_msg="ASSISTANT_KB_UNGGAH_BERKAS",
    ),
    TopikPengetahuan(
        id="media_vault",
        judul="Media Vault",
        kata_kunci=(
            "media vault", "putar media", "streaming media",
            "unggah media",
        ),
        sinonim=(
            "upload media", "mengunggah media", "memutar media",
            "audio video", "winamp", "putar audio", "memutar audio",
            "putar video", "memutar video",
        ),
        kunci_msg="ASSISTANT_KB_MEDIA_VAULT",
    ),
    TopikPengetahuan(
        id="steganografi",
        judul="Steganografi",
        kata_kunci=(
            "steganografi", "steganography", "lsb", "sisipkan pesan",
        ),
        sinonim=(
            "sembunyikan pesan", "menyembunyikan pesan", "ekstrak pesan",
            "mengekstrak pesan", "menyisipkan pesan", "gambar carrier",
            "pesan di gambar",
        ),
        kunci_msg="ASSISTANT_KB_STEGANOGRAFI",
    ),
    TopikPengetahuan(
        id="verifikasi_integritas",
        judul="Verifikasi Integritas",
        kata_kunci=(
            "verifikasi integritas", "integritas blockchain", "hash chain",
            "blok rusak",
        ),
        sinonim=(
            "cek blockchain", "memeriksa blockchain", "verifikasi rantai",
            "memverifikasi integritas", "tamper", "head hash",
        ),
        kunci_msg="ASSISTANT_KB_VERIFIKASI_INTEGRITAS",
    ),
    TopikPengetahuan(
        id="security_center",
        judul="Security Center",
        kata_kunci=(
            "security center", "pusat keamanan", "log blockchain",
            "audit log",
        ),
        sinonim=(
            "blok aktivitas", "riwayat blockchain", "verifikasi aset",
            "membuka security center",
        ),
        kunci_msg="ASSISTANT_KB_SECURITY_CENTER",
    ),
    TopikPengetahuan(
        id="batas_sesi",
        judul="Batas Sesi",
        kata_kunci=(
            "batas sesi", "batas diam sesi", "session timeout",
            "sesi kedaluwarsa",
        ),
        sinonim=(
            "batas waktu sesi", "mengatur batas sesi", "sesi habis",
            "durasi sesi", "timeout sesi",
        ),
        kunci_msg="ASSISTANT_KB_BATAS_SESI",
    ),
    TopikPengetahuan(
        id="akun_terkunci",
        judul="Akun Terkunci",
        kata_kunci=(
            "akun terkunci", "akun diblokir", "terkunci sementara",
            "locked out",
        ),
        sinonim=(
            "terlalu banyak percobaan", "gagal login berulang",
            "akun saya terkunci", "kunci akun", "lockout",
        ),
        kunci_msg="ASSISTANT_KB_AKUN_TERKUNCI",
    ),
    TopikPengetahuan(
        id="super_encryption",
        judul="Super Encryption",
        kata_kunci=(
            "super encryption", "super enkripsi", "cxse2",
            "empat lapisan",
        ),
        sinonim=(
            "empat cipher", "encrypt then mac", "super encrypt",
            "menggunakan super encryption",
        ),
        kunci_msg="ASSISTANT_KB_SUPER_ENCRYPTION",
    ),
    TopikPengetahuan(
        id="aes_gcm",
        judul="AES-256-GCM",
        kata_kunci=(
            "aes gcm", "aes-256-gcm", "aes 256 gcm", "cryptix1",
        ),
        sinonim=(
            "authenticated encryption", "tag gcm", "enkripsi file aes",
        ),
        kunci_msg="ASSISTANT_KB_AES_GCM",
    ),
    TopikPengetahuan(
        id="enkripsi_database",
        judul="Enkripsi Database",
        kata_kunci=(
            "enkripsi database", "database encryption", "field sensitif",
            "v1 nonce ciphertext",
        ),
        sinonim=(
            "enkripsi kolom", "mengenkripsi database", "plaintext database",
            "kunci database", "database terenkripsi",
        ),
        kunci_msg="ASSISTANT_KB_ENKRIPSI_DATABASE",
    ),
    TopikPengetahuan(
        id="mode_pengembangan",
        judul="Mode Pengembangan",
        kata_kunci=(
            "mode pengembangan", "development mode", "cryptix_dev_mode",
            "dev mode",
        ),
        sinonim=(
            "mode developer", "mengaktifkan mode pengembangan",
            "dongle simulasi", "folder simulasi", "debug mode",
        ),
        kunci_msg="ASSISTANT_KB_MODE_PENGEMBANGAN",
    ),
    TopikPengetahuan(
        id="crypto_tools",
        judul="Crypto Tools",
        kata_kunci=(
            "crypto tools", "alat kriptografi", "vigenere", "playfair",
            "chacha20", "blowfish",
        ),
        sinonim=(
            "cipher klasik", "cipher modern", "enkripsi teks manual",
            "menggunakan crypto tools", "algoritma cipher",
        ),
        kunci_msg="ASSISTANT_KB_CRYPTO_TOOLS",
    ),
    TopikPengetahuan(
        id="dashboard",
        judul="Dashboard",
        kata_kunci=(
            "dashboard", "ringkasan akun", "halaman utama",
            "statistik akun",
        ),
        sinonim=(
            "beranda", "ringkasan keamanan",
        ),
        kunci_msg="ASSISTANT_KB_DASHBOARD",
    ),
    TopikPengetahuan(
        id="reauth",
        judul="Autentikasi Ulang",
        kata_kunci=(
            "autentikasi ulang", "reauth", "step up", "verifikasi ulang",
        ),
        sinonim=(
            "grant reauth", "x-reauth-grant", "reauth grant",
            "meminta autentikasi ulang", "modal verifikasi",
        ),
        kunci_msg="ASSISTANT_KB_REAUTH",
    ),
    TopikPengetahuan(
        id="csrf",
        judul="Token CSRF",
        kata_kunci=(
            "csrf", "token csrf", "x-csrftoken", "csrf-token",
        ),
        sinonim=(
            "csrf token", "proteksi csrf", "token form",
        ),
        kunci_msg="ASSISTANT_KB_CSRF",
    ),
    TopikPengetahuan(
        id="rate_limit",
        judul="Pembatasan Laju",
        kata_kunci=(
            "rate limit", "pembatasan laju", "batas permintaan",
            "terlalu sering",
        ),
        sinonim=(
            "rate limiting", "kena rate limit", "limit request", "429",
            "terlalu banyak permintaan",
        ),
        kunci_msg="ASSISTANT_KB_RATE_LIMIT",
    ),
    TopikPengetahuan(
        id="logout",
        judul="Logout",
        kata_kunci=(
            "logout", "keluar akun", "log out", "akhiri sesi",
        ),
        sinonim=(
            "keluar dari akun", "hapus sesi", "session key", "kunci sesi",
        ),
        kunci_msg="ASSISTANT_KB_LOGOUT",
    ),
    TopikPengetahuan(
        id="assistant",
        judul="Security Assistant",
        kata_kunci=(
            "security assistant", "asisten keamanan", "asisten", "chatbot",
        ),
        sinonim=(
            "rule based", "riwayat percakapan", "password diperiksa",
            "asisten cryptix", "membuka asisten",
        ),
        kunci_msg="ASSISTANT_KB_ASSISTANT",
    ),
)

# Skor minimum agar sebuah pesan dianggap cocok dengan topik. Frasa pendek
# seperti "lsb" atau "429" tetap lolos, sedangkan kata umum tunggal tidak.
_AMBANG_SKOR = 12


def _normalisasi(teks: str) -> str:
    """Huruf kecil, tanda baca menjadi spasi, spasi dirapatkan."""
    teks = (teks or "").casefold()
    teks = re.sub(r"[^a-z0-9]+", " ", teks)
    return " ".join(teks.split())


def _frasa_cocok(pesan: str, frasa: str) -> bool:
    """True bila *frasa* muncul sebagai rangkaian kata utuh di *pesan*."""
    frasa = _normalisasi(frasa)
    if not frasa:
        return False
    return f" {frasa} " in f" {pesan} "


def cari_topik(pesan: str) -> TopikPengetahuan | None:
    """
    Kembalikan topik paling relevan untuk *pesan*, atau ``None``.

    Skor dihitung dari frasa yang cocok: frasa lebih panjang dan terdiri atas
    lebih banyak kata mendapat bobot lebih besar. Bila skor tertinggi di bawah
    ambang, pesan dianggap tidak dikenal agar jatuh ke fallback.
    """
    pesan_bersih = _normalisasi(pesan)
    if not pesan_bersih:
        return None

    terbaik: TopikPengetahuan | None = None
    skor_terbaik = 0

    for topik in DAFTAR_TOPIK:
        skor = 0
        jumlah_cocok = 0
        for frasa in topik.kata_kunci + topik.sinonim:
            if _frasa_cocok(pesan_bersih, frasa):
                jumlah_cocok += 1
                skor += 10 * len(_normalisasi(frasa).split()) + len(
                    _normalisasi(frasa)
                )
        if jumlah_cocok > 1:
            skor += (jumlah_cocok - 1) * 5

        if skor > skor_terbaik:
            skor_terbaik = skor
            terbaik = topik

    if skor_terbaik < _AMBANG_SKOR:
        return None
    return terbaik
