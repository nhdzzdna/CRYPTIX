"""
modules/assistant/knowledge.py
──────────────────────────────
Basis pengetahuan Security Assistant untuk fitur dan cara pakai CRYPTIX.

Struktur wajib modul ini adalah ``TOPIK``: daftar kamus dengan kunci ``id``,
``judul``, ``kata_kunci``, ``sinonim``, dan ``jawaban``. Setiap jawaban ditulis
ringkas dalam dua sampai lima kalimat dan diverifikasi terhadap perilaku kode
yang benar-benar ada. Fitur yang tidak tersedia, seperti liveness atau enkripsi
end-to-end, tidak diklaim ada.

Untuk kompatibilitas dengan penyambungan lama, ``DAFTAR_TOPIK`` dan
``cari_topik`` tetap disediakan. Keduanya membaca teks panjang dari
``modules.strings.MSG``; penyambungan baru dapat memakai ``TOPIK`` langsung.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from modules.strings import MSG


TOPIK: list[dict] = [
    {
        "id": "daftar-akun",
        "judul": "Daftar Akun",
        "kata_kunci": [
            "daftar akun", "buat akun", "registrasi akun", "sign up",
        ],
        "sinonim": [
            "registrasi", "mendaftar akun", "membuat akun", "cara daftar",
            "buat akun baru",
        ],
        "jawaban": (
            "Buka halaman Daftar, isi nama pengguna, email, dan kata sandi, lalu "
            "pilih Dongle USB yang terpasang sebelum menekan tombol Daftar. Kata "
            "sandi minimal 12 karakter dan harus memuat minimal tiga dari empat "
            "jenis karakter, yaitu huruf kecil, huruf besar, angka, dan simbol. "
            "Setelah pendaftaran, kunci pemulihan ditampilkan satu kali dan harus "
            "Anda simpan di tempat aman. Pendaftaran memerlukan dongle, kecuali "
            "mode pengembangan memakai folder dongle simulasi."
        ),
    },
    {
        "id": "login-dua-tahap",
        "judul": "Login Dua Tahap",
        "kata_kunci": [
            "login dua tahap", "masuk dua tahap", "tahap login", "login tahap 2",
        ],
        "sinonim": [
            "cara login", "cara masuk", "proses login", "masuk akun",
            "verifikasi login",
        ],
        "jawaban": (
            "Login berlangsung dalam dua tahap. Pada tahap pertama, isi nama "
            "pengguna dan kata sandi, pastikan dongle terpasang, lalu klik Masuk. "
            "Pada tahap kedua, selesaikan verifikasi biometrik memakai WebAuthn "
            "atau wajah melalui tombol Verifikasi. Kunci sesi sementara di server "
            "hanya berlaku sekitar tiga menit, jadi bila kedaluwarsa Anda perlu "
            "memulai lagi dari tahap pertama."
        ),
    },
    {
        "id": "dongle-usb",
        "judul": "Dongle USB",
        "kata_kunci": [
            "dongle", "usb token", "token usb", "flashdisk",
        ],
        "sinonim": [
            "daftar ulang dongle", "mendaftarkan dongle", "dongle terpasang",
            "usb dongle", "hardware token",
        ],
        "jawaban": (
            "Dongle adalah lapisan autentikasi tambahan berupa flashdisk yang "
            "menyimpan berkas token khusus. Server hanya menyimpan ID token, "
            "verifier HMAC SHA256, dan serial volume, bukan rahasia dongle dalam "
            "bentuk asli. Setiap permintaan sesi memeriksa keberadaan dan "
            "kecocokan dongle, lalu sesi diakhiri bila dongle dicabut. Untuk "
            "mendaftarkan ulang, buka Settings, bagian Perangkat dan Sesi, lalu "
            "pilih Daftar Ulang Dongle."
        ),
    },
    {
        "id": "setup-awal",
        "judul": "Penyiapan Awal",
        "kata_kunci": [
            "setup awal", "penyiapan awal", "halaman setup", "wajib biometrik",
        ],
        "sinonim": [
            "lewati setup", "setup akun", "penyiapan akun",
        ],
        "jawaban": (
            "Setelah akun dibuat, halaman setup meminta Anda mendaftarkan minimal "
            "satu metode biometrik sebelum menu lain dapat dibuka. Anda dapat "
            "memilih pendaftaran wajah dengan 30 frame dalam sekitar tiga detik "
            "atau pendaftaran WebAuthn. Tidak ada tombol lewati, sehingga "
            "penyiapan ini wajib agar login dua tahap dapat diselesaikan. "
            "Pendaftaran wajah memerlukan kamera dan detektor wajah OpenCV yang "
            "tersedia."
        ),
    },
    {
        "id": "wajah",
        "judul": "Pendaftaran Wajah",
        "kata_kunci": [
            "pendaftaran wajah", "daftar wajah", "daftar ulang wajah",
            "templat wajah",
        ],
        "sinonim": [
            "wajah", "mendaftar wajah", "mendaftarkan wajah", "face recognition",
            "pengenalan wajah", "kamera wajah",
        ],
        "jawaban": (
            "Buka pengaturan autentikasi biometrik di Settings atau halaman "
            "setup, lalu pilih pendaftaran wajah. Pendaftaran memerlukan minimal "
            "30 frame dan sekitar tiga detik, kemudian sistem menyimpan 25 sampai "
            "60 sampel area wajah dan menolak bila kurang dari lima sampel "
            "berbeda. Yang disimpan hanya templat area wajah terenkripsi "
            "AES-256-GCM dengan format FG1, bukan foto wajah. Pendaftaran gagal "
            "bila detektor wajah OpenCV tidak tersedia."
        ),
    },
    {
        "id": "verifikasi-wajah",
        "judul": "Verifikasi Wajah",
        "kata_kunci": [
            "verifikasi wajah", "scan wajah", "login wajah", "cek wajah",
        ],
        "sinonim": [
            "wajah saat login", "verifikasi kamera", "face verification",
        ],
        "jawaban": (
            "Saat login tahap kedua, pilih verifikasi wajah dan hadapkan wajah "
            "Anda ke kamera. Sistem memerlukan minimal lima frame, menolak "
            "rangkaian frame yang identik, dan menerima bila minimal tiga frame "
            "lolos. Median keyakinan harus mencapai ambang yang ditetapkan, "
            "dengan nilai default 70. CRYPTIX belum memiliki deteksi liveness "
            "atau anti spoof, jadi pastikan hanya Anda yang berada di depan "
            "kamera."
        ),
    },
    {
        "id": "webauthn",
        "judul": "WebAuthn",
        "kata_kunci": [
            "webauthn", "passkey", "windows hello", "kunci keamanan",
        ],
        "sinonim": [
            "authenticator platform", "kredensial webauthn", "tambah webauthn",
            "mendaftarkan webauthn",
        ],
        "jawaban": (
            "WebAuthn memakai authenticator platform seperti Windows Hello, "
            "sidik jari perangkat, atau kunci keamanan dengan verifikasi pengguna "
            "yang wajib. Daftarkan lewat Settings pada bagian Autentikasi "
            "Biometrik, subbagian WebAuthn, atau melalui halaman setup. Tantangan "
            "verifikasi berlaku 300 detik dan hanya dapat dipakai sekali. "
            "Kredensial disimpan di database dan dapat dihapus dari halaman yang "
            "sama."
        ),
    },
    {
        "id": "biometrik",
        "judul": "Metode Biometrik",
        "kata_kunci": [
            "biometrik", "biometrics", "metode biometrik",
        ],
        "sinonim": [
            "autentikasi biometrik", "biometrik terdaftar", "hapus biometrik",
        ],
        "jawaban": (
            "CRYPTIX mendukung dua metode biometrik, yaitu WebAuthn dan wajah. "
            "WebAuthn memakai authenticator platform atau kunci keamanan, "
            "sedangkan wajah diverifikasi melalui kamera dengan templat "
            "terenkripsi. Kebijakan default all enrolled mewajibkan semua metode "
            "yang terdaftar lolos saat login tahap kedua. Anda tidak dapat "
            "menghapus satu satunya metode biometrik, jadi daftarkan metode lain "
            "terlebih dahulu."
        ),
    },
    {
        "id": "kunci-pemulihan",
        "judul": "Kunci Pemulihan",
        "kata_kunci": [
            "kunci pemulihan", "recovery key", "kode pemulihan",
        ],
        "sinonim": [
            "simpan kunci pemulihan", "menyimpan kunci pemulihan",
            "kunci cadangan", "recovery code",
        ],
        "jawaban": (
            "Kunci pemulihan dibuat saat pendaftaran dan ditampilkan satu kali. "
            "Kunci ini membungkus kunci enkripsi data secara terpisah dari kata "
            "sandi dan dongle, sehingga akses dapat dipulihkan bila kata sandi "
            "atau dongle hilang. Simpan kunci di tempat aman dan jangan "
            "membagikannya kepada siapa pun. Tidak ada escrow di server, sehingga "
            "data terenkripsi tidak dapat dipulihkan bila kunci ini hilang."
        ),
    },
    {
        "id": "pemulihan-akun",
        "judul": "Pemulihan Akun",
        "kata_kunci": [
            "pemulihan akun", "account recovery", "pulihkan akun",
            "lupa password",
        ],
        "sinonim": [
            "akun hilang", "tidak bisa login", "reset akun", "pulihkan akses",
            "memulihkan akun",
        ],
        "jawaban": (
            "Buka halaman pemulihan akun, lalu isi nama pengguna, kunci "
            "pemulihan, kata sandi baru, dan pilih dongle baru yang terpasang. "
            "Klik Pulihkan Akun untuk membuka kunci enkripsi data lama dengan "
            "kunci pemulihan, lalu membungkusnya ulang dengan kata sandi dan "
            "dongle baru. Kunci enkripsi data tidak berubah, sehingga berkas dan "
            "templat wajah lama tetap valid. Tanpa kunci pemulihan, pemulihan "
            "tidak mungkin dilakukan."
        ),
    },
    {
        "id": "ganti-password",
        "judul": "Ganti Password",
        "kata_kunci": [
            "ganti password", "ubah password", "ganti kata sandi",
            "ubah kata sandi",
        ],
        "sinonim": [
            "change password", "mengganti password", "mengubah password",
            "mengganti kata sandi", "mengubah kata sandi", "ganti sandi",
            "password baru",
        ],
        "jawaban": (
            "Buka Settings, pilih Ganti Password, lalu isi kata sandi lama, kata "
            "sandi baru, dan konfirmasi sebelum menekan tombol Ganti Password. "
            "Kata sandi baru harus minimal 12 karakter, memuat minimal tiga dari "
            "empat jenis karakter, bukan kata sandi umum, dan tidak memuat nama "
            "pengguna. CRYPTIX membungkus ulang kunci enkripsi data dengan kata "
            "sandi baru, mereset hitungan gagal login, lalu mengakhiri sesi. "
            "Pastikan dongle terpasang selama proses ini."
        ),
    },
    {
        "id": "reveal-akun",
        "judul": "Reveal Kredensial",
        "kata_kunci": [
            "reveal akun", "tampilkan kredensial", "lihat password",
            "buka password",
        ],
        "sinonim": [
            "menampilkan kredensial", "tampilkan username",
            "menampilkan username", "lihat kredensial", "melihat password",
            "membuka password", "reveal password", "ikon mata",
        ],
        "jawaban": (
            "Di Account Vault, klik tombol Tampilkan pada kredensial yang ingin "
            "dilihat. CRYPTIX meminta autentikasi ulang melalui modal Verifikasi "
            "atau Biometrik. Setelah berhasil, grant sekali pakai berlaku 120 "
            "detik untuk scope account reveal. Setiap reveal baru memerlukan "
            "grant baru, dan aksi ini dibatasi 20 permintaan per menit."
        ),
    },
    {
        "id": "account-vault",
        "judul": "Account Vault",
        "kata_kunci": [
            "account vault", "akun vault", "kredensial situs",
            "tambah kredensial",
        ],
        "sinonim": [
            "simpan kredensial", "menambah kredensial", "menyimpan kredensial",
            "password situs", "manajer password",
        ],
        "jawaban": (
            "Account Vault menyimpan kredensial situs berupa nama situs, "
            "username, kata sandi, URL, dan catatan. Setiap field dienkripsi "
            "terpisah dengan AES-256-GCM dalam format v1 dengan nonce dan "
            "ciphertext. Data pengikat tambahan mengikat user id, nama tabel, dan "
            "nama kolom. Tambah kredensial lewat tombol Tambah Kredensial, lalu "
            "Simpan Terenkripsi, dan username akan tampil tersamar sampai grant "
            "reveal dipakai."
        ),
    },
    {
        "id": "catatan-aman",
        "judul": "Secure Notes",
        "kata_kunci": [
            "secure notes", "catatan aman", "catatan rahasia",
            "catatan terenkripsi",
        ],
        "sinonim": [
            "tambah catatan", "menambah catatan", "simpan catatan",
            "menyimpan catatan", "buka catatan", "membuka catatan", "notes",
        ],
        "jawaban": (
            "Secure Notes menyimpan judul dan isi catatan rahasia. Isi catatan "
            "dienkripsi dengan Super Encryption lebih dahulu, lalu seluruh field "
            "dienkripsi AES-256-GCM sebelum masuk database. Tambah catatan lewat "
            "tombol Tambah Catatan dan Simpan Terenkripsi, lalu buka dengan tombol "
            "Buka. Membuka, mengedit, dan menghapus catatan memerlukan grant "
            "autentikasi ulang serta dibatasi 20 permintaan per menit."
        ),
    },
    {
        "id": "unggah-berkas",
        "judul": "My Vault",
        "kata_kunci": [
            "my vault", "unggah berkas", "upload file", "unggah file",
        ],
        "sinonim": [
            "upload berkas", "mengunggah berkas", "mengunggah file",
            "simpan berkas", "unduh berkas", "mengunduh berkas", "documents",
        ],
        "jawaban": (
            "Buka My Vault, pilih berkas lewat Upload File Baru, lalu klik "
            "Enkripsi dan Upload. Berkas dienkripsi AES-256-GCM per potongan 1 "
            "MiB dengan header CRYPTIX1, salt acak, dan data pengikat pengguna "
            "serta metadata. Unduh lewat tombol Unduh, yang memerlukan grant file "
            "download dan memeriksa SHA-256 plaintext setelah dekripsi. Batas "
            "unggah 64 MB dan hanya ekstensi yang diizinkan, sedangkan halaman "
            "Documents hanya menampilkan berkas bertipe dokumen dari My Vault."
        ),
    },
    {
        "id": "media-vault",
        "judul": "Media Vault",
        "kata_kunci": [
            "media vault", "putar media", "streaming media", "unggah media",
        ],
        "sinonim": [
            "upload media", "mengunggah media", "memutar media", "audio video",
            "winamp", "putar audio", "memutar audio", "putar video",
            "memutar video",
        ],
        "jawaban": (
            "Media Vault menyimpan audio dan video terenkripsi. Unggah lewat "
            "tombol Upload Media dan Enkripsi Upload, lalu putar dengan tombol "
            "Putar. Streaming memakai HTTP Range sehingga plaintext tidak ditulis "
            "ke disk. Format yang dapat diputar adalah mp4, webm, mp3, wav, ogg, "
            "m4a, dan flac, sedangkan AVI, MKV, dan MOV hanya dapat diunduh, dan "
            "tombol Winamp memakai berkas sementara yang dihapus setelah 60 detik."
        ),
    },
    {
        "id": "steganografi",
        "judul": "Steganografi",
        "kata_kunci": [
            "steganografi", "steganography", "lsb", "sisipkan pesan",
        ],
        "sinonim": [
            "sembunyikan pesan", "menyembunyikan pesan", "ekstrak pesan",
            "mengekstrak pesan", "menyisipkan pesan", "gambar carrier",
            "pesan di gambar",
        ],
        "jawaban": (
            "Buka Steganography, pilih gambar carrier PNG, JPG, atau BMP dengan "
            "ukuran maksimal 4000 kali 4000, lalu tentukan muatan teks atau "
            "berkas. Muatan teks dienkripsi dengan Super Encryption secara "
            "default, sedangkan muatan berkas selalu dienkripsi AES-256-GCM. "
            "Kapasitas sekitar lebar kali tinggi kali tiga dikurangi 112, lalu "
            "dibagi delapan byte. Hasil selalu PNG karena menyimpan ulang sebagai "
            "JPEG akan merusak muatan, dan ekstraksi dilakukan lewat tombol "
            "Ekstrak."
        ),
    },
    {
        "id": "verifikasi-integritas",
        "judul": "Verifikasi Integritas",
        "kata_kunci": [
            "verifikasi integritas", "integritas blockchain", "hash chain",
            "blok rusak",
        ],
        "sinonim": [
            "cek blockchain", "memeriksa blockchain", "verifikasi rantai",
            "memverifikasi integritas", "tamper", "head hash",
        ],
        "jawaban": (
            "Buka Security Center, lalu klik Verifikasi Integritas. CRYPTIX "
            "menghitung ulang hash setiap blok, proof of work ringan, dan tanda "
            "tangan HMAC-SHA256. Head hash dibandingkan dengan jangkar di berkas "
            "chain head dan berkas dongle bila tersedia. Status aset Anda dapat "
            "berupa OK, DIUBAH, HILANG, atau TANPA CATATAN, dan rantai lokal ini "
            "bersifat tamper evident, bukan tamper proof."
        ),
    },
    {
        "id": "security-center",
        "judul": "Security Center",
        "kata_kunci": [
            "security center", "pusat keamanan", "log blockchain", "audit log",
        ],
        "sinonim": [
            "blok aktivitas", "riwayat blockchain", "verifikasi aset",
            "membuka security center",
        ],
        "jawaban": (
            "Security Center menampilkan statistik rantai, blok aktivitas milik "
            "Anda, dan status aset. Tombol Verifikasi Integritas memeriksa "
            "seluruh rantai dan aset Anda. Status aset yang ditampilkan adalah OK, "
            "DIUBAH, HILANG, atau TANPA CATATAN. Ringkasan verifikasi terakhir "
            "disimpan di memori proses dan hilang saat server restart."
        ),
    },
    {
        "id": "batas-sesi",
        "judul": "Batas Sesi",
        "kata_kunci": [
            "batas sesi", "batas diam sesi", "session timeout",
            "sesi kedaluwarsa",
        ],
        "sinonim": [
            "batas waktu sesi", "mengatur batas sesi", "sesi habis",
            "durasi sesi", "timeout sesi",
        ],
        "jawaban": (
            "Batas diam sesi default adalah 10 menit dan batas absolut 60 menit. "
            "Ubah batas diam lewat Settings, bagian Perangkat dan Sesi, lalu "
            "Simpan Batas Sesi. Cookie hanya memuat ID sesi acak, sedangkan kunci "
            "enkripsi sesi disimpan di memori server. Saat batas tercapai atau "
            "server restart, sesi berakhir dan Anda harus login ulang."
        ),
    },
    {
        "id": "akun-terkunci",
        "judul": "Akun Terkunci",
        "kata_kunci": [
            "akun terkunci", "akun diblokir", "terkunci sementara", "locked out",
        ],
        "sinonim": [
            "terlalu banyak percobaan", "gagal login berulang",
            "akun saya terkunci", "kunci akun", "lockout",
        ],
        "jawaban": (
            "Akun terkunci sementara setelah percobaan login gagal berulang. "
            "Lima kali gagal mengunci 60 detik, sepuluh kali gagal mengunci 5 "
            "menit, lima belas kali gagal mengunci 15 menit, dan dua puluh kali "
            "atau lebih mengunci 30 menit. Hitungan mencakup kata sandi salah, "
            "dongle tidak cocok atau tidak terpasang, dan kegagalan membuka kunci. "
            "Tidak ada pembukaan manual, jadi tunggu hingga masa kunci berakhir "
            "lalu coba lagi."
        ),
    },
    {
        "id": "super-encryption",
        "judul": "Super Encryption",
        "kata_kunci": [
            "super encryption", "super enkripsi", "cxse2", "empat lapisan",
        ],
        "sinonim": [
            "empat cipher", "encrypt then mac", "super encrypt",
            "menggunakan super encryption",
        ],
        "jawaban": (
            "Super Encryption menggabungkan empat lapisan secara berurutan, yaitu "
            "Vigenere, Playfair, ChaCha20, dan Blowfish CBC. Setiap pesan memakai "
            "salt acak 16 byte dan kunci turunan HKDF. Hasil diakhiri HMAC-SHA256 "
            "dengan pola encrypt then mac dan format CXSE2 dengan salt, token, dan "
            "mac. Gunakan di Crypto Tools dengan memilih Super Encryption Semua "
            "Layer dan mengisi passphrase, dan ingat bahwa ini komposisi edukatif, "
            "bukan skema AEAD standar."
        ),
    },
    {
        "id": "aes-gcm",
        "judul": "AES-256-GCM",
        "kata_kunci": [
            "aes gcm", "aes 256 gcm", "cryptix1",
        ],
        "sinonim": [
            "authenticated encryption", "tag gcm", "enkripsi file aes",
        ],
        "jawaban": (
            "CRYPTIX memakai AES-256-GCM untuk berkas, kredensial, catatan, "
            "templat wajah, dan muatan steganografi. Berkas memakai format CRYPTIX1 "
            "dengan salt acak 16 byte, nonce per potongan, dan data pengikat "
            "pengguna serta metadata. Kunci diturunkan dari kunci enkripsi data "
            "sesi melalui HKDF dengan label berbeda per tujuan. GCM memberi "
            "kerahasiaan sekaligus deteksi perubahan melalui tag autentikasi."
        ),
    },
    {
        "id": "enkripsi-database",
        "judul": "Enkripsi Database",
        "kata_kunci": [
            "enkripsi database", "database encryption", "field sensitif",
            "v1 nonce ciphertext",
        ],
        "sinonim": [
            "enkripsi kolom", "mengenkripsi database", "plaintext database",
            "kunci database", "database terenkripsi",
        ],
        "jawaban": (
            "Berkas SQLite tidak dienkripsi seluruhnya, karena yang dienkripsi "
            "adalah field sensitif. Kredensial dan catatan disimpan dalam format "
            "v1 dengan nonce dan ciphertext memakai AES-256-GCM. Data pengikat "
            "mengikat user id, nama tabel, dan nama kolom. Kunci berasal dari kunci "
            "enkripsi data sesi melalui HKDF dengan label khusus database, sehingga "
            "salinan berkas database tetap memuat metadata tetapi bukan plaintext "
            "field sensitif."
        ),
    },
    {
        "id": "mode-pengembangan",
        "judul": "Mode Pengembangan",
        "kata_kunci": [
            "mode pengembangan", "development mode", "cryptix dev mode",
            "dev mode",
        ],
        "sinonim": [
            "mode developer", "mengaktifkan mode pengembangan", "dongle simulasi",
            "folder simulasi", "debug mode",
        ],
        "jawaban": (
            "Mode pengembangan diaktifkan dengan variabel lingkungan "
            "CRYPTIX_DEV_MODE bernilai True. CRYPTIX memakai folder simulasi "
            "sebagai dongle bila tidak ada flashdisk. Endpoint verifikasi wajah "
            "ikut mengembalikan keyakinan per frame dan nilai median. Mode ini "
            "melemahkan asumsi keamanan perangkat keras, sehingga hanya untuk "
            "pengembangan dan bukan penggunaan sehari hari."
        ),
    },
    {
        "id": "crypto-tools",
        "judul": "Crypto Tools",
        "kata_kunci": [
            "crypto tools", "alat kriptografi", "vigenere", "playfair",
            "chacha20", "blowfish",
        ],
        "sinonim": [
            "cipher klasik", "cipher modern", "enkripsi teks manual",
            "menggunakan crypto tools", "algoritma cipher",
        ],
        "jawaban": (
            "Crypto Tools menguji algoritma secara mandiri. Vigenere bekerja "
            "sebagai substitusi klasik pada ASCII 32 sampai 126, Playfair memakai "
            "digram 5 kali 5 dengan J digabung ke I, ChaCha20 memakai nonce acak "
            "16 byte, dan Blowfish CBC memakai PKCS7 serta IV acak 8 byte. Super "
            "Encryption menambahkan empat lapisan dan HMAC-SHA256. Pilih algoritma "
            "dan operasi Enkripsi atau Dekripsi, lalu klik Proses, dan hasilnya "
            "tidak disimpan."
        ),
    },
    {
        "id": "dashboard",
        "judul": "Dashboard",
        "kata_kunci": [
            "dashboard", "ringkasan akun", "halaman utama", "statistik akun",
        ],
        "sinonim": [
            "beranda", "ringkasan keamanan",
        ],
        "jawaban": (
            "Dashboard merangkum kondisi akun Anda. Halaman ini menampilkan jumlah "
            "berkas, kredensial, catatan, dan gambar stego, kapasitas penyimpanan "
            "terpakai, status dongle terpasang, serta metode biometrik terdaftar. "
            "Dashboard juga menampilkan hasil verifikasi rantai terakhir beserta "
            "jangkar kepala. Lima aktivitas terbaru milik Anda dari log audit ikut "
            "ditampilkan."
        ),
    },
    {
        "id": "reauth",
        "judul": "Autentikasi Ulang",
        "kata_kunci": [
            "autentikasi ulang", "reauth", "step up", "verifikasi ulang",
        ],
        "sinonim": [
            "grant reauth", "x reauth grant", "reauth grant",
            "meminta autentikasi ulang", "modal verifikasi",
        ],
        "jawaban": (
            "Autentikasi ulang atau step up diminta saat membuka data sensitif "
            "atau mengubah pengaturan. CRYPTIX menampilkan modal Verifikasi untuk "
            "kata sandi atau Biometrik untuk WebAuthn dan wajah. Grant umumnya "
            "berlaku sekali pakai selama 120 detik dan terikat pada sesi, scope, "
            "serta resource, tetapi khusus media stream grant dapat dipakai ulang "
            "selama 15 menit. Grant dikirim lewat header X-Reauth-Grant atau field "
            "reauth grant, tidak lewat URL, dan disimpan di memori sehingga hilang "
            "saat server restart."
        ),
    },
    {
        "id": "csrf",
        "judul": "Token CSRF",
        "kata_kunci": [
            "csrf", "token csrf", "x csrftoken", "csrf token",
        ],
        "sinonim": [
            "csrf token", "proteksi csrf", "token form",
        ],
        "jawaban": (
            "Semua permintaan pengubah data wajib menyertakan token CSRF. Halaman "
            "menyediakan token pada meta csrf token, sedangkan form menyertakan "
            "token sebagai field tersembunyi dan JavaScript mengirimnya lewat "
            "header X-CSRFToken. Tanpa token yang cocok, server menolak "
            "permintaan. Jangan membuka CRYPTIX lewat situs lain atau membagikan "
            "token Anda."
        ),
    },
    {
        "id": "rate-limit",
        "judul": "Pembatasan Laju",
        "kata_kunci": [
            "rate limit", "pembatasan laju", "batas permintaan", "terlalu sering",
        ],
        "sinonim": [
            "rate limiting", "kena rate limit", "limit request", "429",
            "terlalu banyak permintaan",
        ],
        "jawaban": (
            "CRYPTIX membatasi laju permintaan untuk mencegah penyalahgunaan. "
            "Login dibatasi 15 permintaan per menit, verifikasi wajah 20 per "
            "menit, autentikasi ulang 20 per menit, dan pemulihan akun 10 per "
            "menit. Reveal, edit, dan hapus data sensitif juga dibatasi 20 "
            "permintaan per menit. Batas dihitung per sesi pengguna dengan "
            "cadangan alamat IP, jadi tunggu sebentar bila terkena batas."
        ),
    },
    {
        "id": "logout",
        "judul": "Logout",
        "kata_kunci": [
            "logout", "keluar akun", "log out", "akhiri sesi",
        ],
        "sinonim": [
            "keluar dari akun", "hapus sesi", "session key", "kunci sesi",
        ],
        "jawaban": (
            "Sesi login memakai cookie yang hanya berisi ID sesi acak, sedangkan "
            "kunci enkripsi data dan turunannya disimpan di memori server. Logout "
            "tersedia lewat tombol POST di sidebar. CRYPTIX menulis blok LOGOUT, "
            "menghapus kunci sesi server, dan membersihkan cookie. Tidak ada fitur "
            "logout semua perangkat, dan restart server juga mengakhiri semua "
            "sesi."
        ),
    },
    {
        "id": "assistant",
        "judul": "Security Assistant",
        "kata_kunci": [
            "security assistant", "asisten keamanan", "asisten", "chatbot",
        ],
        "sinonim": [
            "rule based", "riwayat percakapan", "password diperiksa",
            "asisten cryptix", "membuka asisten",
        ],
        "jawaban": (
            "Security Assistant berbasis aturan, tanpa model bahasa dan tanpa "
            "panggilan jaringan. Ia dapat menjelaskan status keamanan akun, "
            "merekomendasikan enkripsi, memeriksa kekuatan kata sandi, merangkum "
            "log aktivitas, dan menjawab panduan fitur. Riwayat disimpan di server "
            "dengan maksimal 40 entri per sesi dan tidak masuk cookie. Kolom "
            "password terpisah hanya diproses di memori, dan riwayat mencatat "
            "penanda password diperiksa."
        ),
    },
]


# ── Kompatibilitas dengan penyambungan lama ──────────────────────────────────

@dataclass(frozen=True)
class _TopikLama:
    """Tampilan objek untuk pemanggil lama; bukan struktur data utama."""

    id: str
    judul: str
    kata_kunci: tuple[str, ...]
    sinonim: tuple[str, ...]
    kunci_msg: str

    @property
    def jawaban(self) -> str:
        return getattr(MSG, self.kunci_msg)


DAFTAR_TOPIK: tuple[_TopikLama, ...] = tuple(
    _TopikLama(
        id=topik["id"].replace("-", "_"),
        judul=topik["judul"],
        kata_kunci=tuple(topik["kata_kunci"]),
        sinonim=tuple(topik["sinonim"]),
        kunci_msg="ASSISTANT_KB_" + topik["id"].replace("-", "_").upper(),
    )
    for topik in TOPIK
)

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


def cari_topik(pesan: str) -> _TopikLama | None:
    """
    Kembalikan topik paling relevan untuk *pesan*, atau ``None``.

    Fungsi ini melayani penyambungan lama dan memakai frasa dari ``TOPIK``.
    Skor dihitung dari frasa yang cocok: frasa lebih panjang dan terdiri atas
    lebih banyak kata mendapat bobot lebih besar.
    """
    pesan_bersih = _normalisasi(pesan)
    if not pesan_bersih:
        return None

    terbaik: _TopikLama | None = None
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
