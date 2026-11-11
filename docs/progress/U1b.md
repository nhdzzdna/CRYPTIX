# U1b — Security Center, Settings & Pemulihan Reset Akun

## Bagian 1: Security Center (P1)

### Ringkasan

Sesi U1b menyelesaikan modernisasi antarmuka Security Center (`templates/security_center.html`, rute `GET /security-center` dan `POST /security-center/verify`) sesuai panduan `docs/desain/spesifikasi-ui.txt` §117–120, katalog fondasi U0 (`docs/progress/U0.md`), serta instruksi kerja:

1. **Kartu Blockchain Integrity**: Memuat 4 stat (Total blok, Indeks terakhir, Jangkar head, Verifikasi terakhir) dan tombol "Verifikasi integritas" di kanan atas header kartu (`kx-card-head`). Di dalamnya terdapat visual rantai horizontal (`#n`) dengan diferensiasi warna per blok (hijau valid, merah rusak, teal terbaru, abu belum diverifikasi), serta hash jangkar lengkap di dalam blok kode mono dengan tombol Salin (`data-kx-salin`). Hasil verifikasi ditampilkan lewat banner kartu (hijau utuh, merah menunjukkan kerusakan) dan notifikasi `KX.toast`.
2. **Kartu Log Aktivitas Blockchain**: Chip filter dinamis mencakup tipe blok yang ada sesuai daftar `ACTIONS` pada `modules/blockchain/blockchain.py` (termasuk `TRASH_MOVE`, `DELETE`, `ACCOUNT_DELETE`, dan lainnya). Tabel mencakup kolom Nomor, Waktu (`mono`), Aksi (badge warna per kategori tindakan), Asset hash, dan Block hash (sel hash dipotong 16 karakter dengan tombol Salin via `data-kx-hash`). Tombol "Ekspor CSV" ditiadakan karena belum tersedia pada backend.
3. **Kartu Keutuhan Aset Milik Anda**: Ditampilkan secara kondisional saat data aset tersedia (`assets is not none`), dimodernisasi menggunakan tabel `kx-table` dengan badge status tanpa emoji.
4. **Gaya dan Skrip**: Gaya tampilan diisolasi pada `static/css/halaman/security_center.css` lewat `{% block styles %}` tanpa memodifikasi `static/css/style.css`. Logika interaktif (filter chip dan toast hasil verifikasi) ditempatkan pada `static/js/security_center.js` tanpa JavaScript inline untuk mematuhi CSP. Seluruh teks antarmuka menggunakan bahasa Indonesia formal dari `modules/strings.py` tanpa emoji.

---

### Audit Elemen Lama (Sebelum → Sesudah) — Security Center

| Elemen / Fitur | Sebelum | Sesudah | Status | Alasan |
|---|---|---|---|---|
| Subjudul halaman | Paragraf di `page_subtitle` | Dihapus | Dibuang | Keputusan yang mengalahkan spesifikasi: tanpa subjudul/deskripsi umum. |
| Tombol verifikasi di topbar | Form di `page_actions` topbar | Dipindah ke kanan atas kartu Integritas Blockchain (`kx-card-head`) | Diubah | Spesifikasi §118 dan instruksi prompt: tombol di kanan atas kartu. |
| Banner hasil verifikasi | Komponen `.security-result` lama di bawah header | `.kx-sc-banner` terintegrasi di dalam kartu Integritas | Diubah | Desain terpadu dengan status valid, invalid, atau info sesuai spesifikasi. |
| Notifikasi hasil verifikasi | Hanya perubahan visual pada halaman | Banner kartu + notifikasi `KX.toast` saat halaman termuat dengan hasil verifikasi | Diubah | Spesifikasi §119: hasil verifikasi tampil sebagai toast dan banner di kartu. |
| 4 Kotak statistik | Blok `.security-stat` terpisah di atas kartu | Grid 4 kolom `.kx-sc-stats` di dalam kartu Integritas (Total blok, Indeks terakhir, Jangkar head, Verifikasi terakhir) | Diubah | Spesifikasi §118: 4 stat di dalam kartu Integritas Blockchain. |
| Visual rantai horizontal | Belum tersedia pada halaman lama | Rantai horizontal scrollable `.kx-sc-chain-track` berisi nomor blok `#n` dengan indikator warna (hijau valid, merah rusak, teal terbaru, abu belum diverifikasi) dan panah alur | Diubah | Spesifikasi §118 dan instruksi: visual rantai horizontal dengan warna per status. |
| Jangkar kepala (head anchor) | Elemen `.security-anchor` dengan kode inline biasa | Blok kode `.kx-code` di dalam `.kx-code-wrap` dengan tombol Salin `.kx-copy-btn` | Diubah | Spesifikasi §118: hash jangkar lengkap di blok kode dengan fitur Copy. |
| Keutuhan aset | Panel `.security-panel` dengan daftar aset lama | Kartu `.kx-sc-card-assets` berbasis `kx-table`, badge status tanpa emoji | Dipertahankan & Diubah | Menjaga pengujian verifikasi aset dan keutuhan fungsionalitas akun. |
| Chip filter log aktivitas | Belum ada chip filter | Baris chip `.kx-sc-chips` (Semua + aksi yang ada dalam data blok) | Diubah | Spesifikasi §120: chip filter dinamis sesuai tipe aksi blockchain. |
| Tombol Ekspor CSV | Tidak ada / diminta pada spesifikasi | Tidak disediakan | Ditiadakan | Backend tidak menyediakan endpoint ekspor CSV; dicatat sebagai keterbatasan. |
| Tabel log aktivitas | Kartu list artikel dengan layout custom | Tabel `.kx-table` terstruktur dengan kolom Nomor, Waktu, Aksi, Asset hash, Block hash | Diubah | Spesifikasi §120: format tabel terstandarisasi. |
| Pemotongan hash dan salin | Teks hash panjang tanpa tombol salin otomatis | Komponen `.kx-hash` dengan pemotongan 16 karakter dan tombol Salin otomatis | Diubah | Standar U0 untuk seluruh sel hash di aplikasi. |
| Emoji status dan badge | Menggunakan emoji | Badge teks bersih (`kx-badge-ok`, `kx-badge-danger`, `kx-badge-warn`, `kx-badge-info`) dengan ikon SVG sprite | Diubah | Aturan bebas emoji di seluruh antarmuka. |

---

### Tabel Kepatuhan Spesifikasi (P1)

| Kebutuhan Spesifikasi / Prompt | Realisasi pada Sesi U1b | Status |
|---|---|---|
| Kartu Blockchain Integrity dengan 4 stat (Total blok, Indeks terakhir, Jangkar head, Verifikasi terakhir) | Grid `.kx-sc-stats` memuat 4 metrik dengan ikon dan keterangan | sesuai |
| Tombol "Verifikasi integritas" di kanan atas kartu | Form POST dengan tombol `.kx-btn-primary.kx-btn-sm` di `.kx-card-head` | sesuai |
| Visual rantai horizontal (`#n`) dengan warna per blok | Kontainer horizontal `.kx-sc-chain-track`: hijau (valid), merah (rusak), teal (terbaru), abu (belum diverifikasi) | sesuai |
| Hash jangkar lengkap di blok kode dengan fitur Copy | `.kx-code-wrap` dengan `<pre class="kx-code"><code>` dan tombol Salin `[data-kx-salin]` | sesuai |
| Hasil verifikasi: toast + banner di kartu | Banner `.kx-sc-banner` (hijau valid, merah rusak) + panggilan `KX.toast` via `security_center.js` | sesuai |
| Kartu Log aktivitas dengan chip filter sesuai tipe blok yang ada | Chip `.kx-chip` di `.kx-sc-chips` memfilter baris tabel secara instan di sisi klien | sesuai |
| Penanganan tipe blok dari ACTIONS (termasuk TRASH_MOVE, DELETE, ACCOUNT_DELETE) | Macro badge warna dan filter chip mendukung seluruh aksi yang terdaftar | sesuai |
| Tabel Nomor, Waktu (mono), Aksi (badge), Asset hash, Block hash | Tabel `.kx-sc-table` dengan kolom yang ditentukan dan sel hash 16 karakter + Copy | sesuai |
| Tanpa tombol Ekspor CSV | Ditiadakan karena rute backend ekspor CSV tidak tersedia | sesuai |
| Tanpa subjudul/deskripsi umum dan tanpa tombol topbar | Subjudul dan tombol topbar dihapus | sesuai |
| Tanpa inline JavaScript (CSP ketat) | Logika UI dipisah ke `static/js/security_center.js` | sesuai |
| Gaya halaman khusus di `static/css/halaman/security_center.css` | Seluruh style diisolasi di file halaman; `style.css` tidak diubah | sesuai |
| Teks UI bahasa Indonesia formal via `modules/strings.py`, tanpa emoji | Ditambahkan konstanta `SC_*` di `modules/strings.py`; tanpa emoji | sesuai |
| Responsif tiga lebar (desktop, tablet, mobile) | Media query breakpoint 900px dan 640px di `security_center.css` | sesuai |
| Pengujian markup lama diperbarui | `tests/test_security_center.py` diperbarui dan tes kontrak UI ditambahkan | sesuai |

---

## Bagian 2: Settings (P2)

### Ringkasan

Sesi U1b menyelesaikan redesain antarmuka Settings (`templates/settings.html`, `static/js/settings.js`, `static/css/halaman/settings.css`, dan rute terkait di `routes/settings_routes.py`) sesuai panduan spesifikasi dan aturan proyek:

1. **Struktur 5 Tab Pill**:
   - Tab pill di bagian atas: **Profil**, **Keamanan**, **Biometrik**, **Sesi**, dan **Akun**.
   - Navigasi tab berjalan di sisi klien tanpa muat ulang halaman (`no reload`).
   - Tab aktif tersinkronisasi dua arah dengan hash URL (`#profil`, `#keamanan`, `#biometrik`, `#sesi`, `#akun`). Jika terdapat respons pembuatan kunci pemulihan baru (`recovery_key_baru`), tab aktif secara otomatis diarahkan ke tab `keamanan`.
2. **Tab Profil**:
   - Kolom kiri memuat kartu Profil dengan avatar inisial (kapital nama pengguna), Username read-only (JetBrains Mono), Email (JetBrains Mono) beserta tombol "Ubah email" yang membuka modal ubah surel, serta tanggal Bergabung dan Login Terakhir rata kanan dalam format mono.
   - Kartu Ganti Password memuat kolom password saat ini (toggle satu mata), password baru (meter kekuatan 4 segmen + petunjuk 12 karakter), dan konfirmasi password dengan tombol teal `Ganti Password` (`POST /settings/change-password` ber-grant `settings.change`).
   - Kolom kanan memuat kartu ringkasan Perangkat & Biometrik (status USB token Terdaftar/Belum terdaftar & Terpasang/Tidak terpasang, jumlah kredensial WebAuthn, status template Face Recognition) dengan tautan "Kelola" yang mengalihkan tab ke Biometrik.
3. **Tab Keamanan**:
   - Kartu USB Token / Dongle: status badge, dropdown drive tujuan (`<select name="mountpoint">`) dari data drive yang dikirim backend, kolom password saat ini, petunjuk pendaftaran ulang, dan tombol "Daftar Ulang Dongle" (`POST /settings/register-usb`).
   - Kartu Kunci Pemulihan: kotak peringatan kuning (`.kx-infobox.kx-infobox-warn`) yang menegaskan kunci lama langsung tidak berlaku dan kunci baru hanya tampil sekali. Tombol "Terbitkan kunci pemulihan baru" membuka modal konfirmasi. Saat kunci baru terbit (`recovery_key_baru`), ditampilkan dalam blok kode mono dengan tombol Salin (`data-kx-salin`), tombol Unduh berkas `.txt`, dan kotak centang "Sudah saya simpan".
4. **Tab Biometrik**:
   - Kartu Face Recognition: badge status, bimbingan posisi wajah ("Hadap kamera dengan mata terbuka"), tampilan kamera video dan canvas, serta tombol "Daftar Ulang Wajah" (`data-settings-action="face-enroll"` ber-grant `biometric.manage`). Alur `face.js` dipertahankan utuh.
   - Kartu WebAuthn: badge status, tabel kredensial (kolom Nama, Ditambahkan, tombol Hapus outline merah), input nama kredensial baru, tombol "Tambah WebAuthn" (`data-settings-action="webauthn-add"` ber-grant `biometric.manage`), dan catatan minimal satu biometrik harus tetap terdaftar. Penghapusan kredensial meminta konfirmasi via `KX.konfirmasiHapus`.
5. **Tab Sesi**:
   - Kartu Batas Diam Sesi: dropdown pilihan menit (`<select id="session-timeout" name="session_timeout_minutes">`), tombol "Simpan Batas Sesi" (`POST /settings/session-timeout`), dan keterangan berlakunya batas waktu.
6. **Tab Akun (Zona Bahaya)**:
   - Dua kartu bahaya dengan outline merah (`.kx-card-danger`): "Reset data" (`POST /settings/reset-data`) dan "Hapus akun" (`POST /settings/delete-account`).
   - Modal konfirmasi masing-masing kartu memuat penjelasan konsekuensi jujur, kolom kata sandi saat ini, dan kolom ketik ulang nama pengguna persis (`data-target-username`). Tombol merah solid hanya aktif jika nama pengguna yang diketik cocok persis. Alur form tetap memakai grant `account.danger`.
7. **Gaya dan Skrip**:
   - Gaya diisolasi di `static/css/halaman/settings.css` tanpa mengubah `style.css`.
   - Logika tab, modal, konfirmasi username bahaya, unduh kunci pemulihan, dan biometrik diisolasi di `static/js/settings.js` tanpa JavaScript inline (CSP compliant).
   - Seluruh teks antarmuka berbahasa Indonesia formal dari `modules/strings.py` tanpa emoji.

---

### Audit Elemen Lama (Sebelum → Sesudah) — Settings

| Elemen / Fitur | Sebelum | Sesudah | Status | Alasan |
|---|---|---|---|---|
| Navigasi halaman | Sidebar vertikal 4 link scrollspy | 5 Tab pill horizontal (Profil, Keamanan, Biometrik, Sesi, Akun) di atas konten | Diubah | Spesifikasi UI §128–134 dan instruksi prompt redesain 5 tab pill. |
| Subjudul halaman | Paragraf di `page_subtitle` | Dihapus | Dibuang | Keputusan yang mengalahkan spesifikasi: tanpa subjudul/deskripsi umum. |
| Ubah Email | Form inline terbuka di tab profil | Tombol "Ubah email" di samping surel yang membuka modal dialog `#modal-ubah-email` | Diubah | Merapikan layout kartu profil sesuai spesifikasi §130. |
| Avatar pengguna | Belum ada elemen avatar | Avatar inisial huruf kapital di samping username/email dengan font display | Diubah | Spesifikasi §130: avatar inisial pengguna. |
| Ringkasan Perangkat & Biometrik | Belum ada kartu ringkasan terpadu | Kartu terpisah di kolom kanan dengan status token, WebAuthn, wajah, dan tombol "Kelola" ke tab Biometrik | Diubah | Spesifikasi §130: kolom kanan ringkasan perangkat dan biometrik. |
| Kunci Pemulihan Baru | Section alert di atas seluruh panel halaman | Terintegrasi di kartu Kunci Pemulihan pada tab Keamanan dengan tombol Salin, Unduh .txt, dan centang "Sudah saya simpan" | Diubah | Spesifikasi §131: alur terpadu di dalam kartu kunci pemulihan. |
| Modal Konfirmasi Kunci Pemulihan | Form tombol submit langsung | Tombol membuka modal konfirmasi sebelum POST ke `/settings/recovery-key` | Diubah | Spesifikasi §131: modal konfirmasi sebelum menerbitkan kunci baru. |
| Hapus Kredensial WebAuthn | Submit form langsung dengan data-reauth | Konfirmasi melalui `KX.konfirmasiHapus` menyebut nama kredensial sebelum langkah reauth | Diubah | Spesifikasi §132 dan standar dialog hapus aplikasi. |
| Zona Bahaya (Reset & Hapus) | Form inline dengan tombol outline merah biasa | Dua kartu zona bahaya ber-outline merah di tab Akun, masing-masing membuka modal dengan proteksi ketik username persis | Diubah | Spesifikasi zona bahaya dan instruksi prompt untuk mencegah tindakan tidak sengaja. |
| Teks UI dan Emoji | Campuran teks dan ikon SVG inline | Menggunakan makro `ikon()` dari sprite SVG dan teks Indonesia formal via `modules/strings.py` | Diubah | Standar U0 dan aturan ketat anti-emoji. |

---

### Tabel Kepatuhan Spesifikasi (P2)

| Kebutuhan Spesifikasi / Prompt | Realisasi pada Sesi U1b | Status |
|---|---|---|
| Lima tab pill: Profil, Keamanan, Biometrik, Sesi, Akun | Elemen `.kx-tabs.kx-settings-tabs` dengan 5 tombol tab dan 5 panel terkait | sesuai |
| Pindah tab tanpa reload, tersimpan di hash URL | Logika tab di `settings.js` sinkron dengan `window.location.hash` dan event `hashchange` | sesuai |
| Profil: avatar inisial, Username read-only mono, Email mono + tombol Ubah Email | Kartu profil memuat avatar, nilai dalam font mono JetBrains, dan modal ubah email | sesuai |
| Profil: Bergabung dan Login Terakhir mono rata kanan | Timestamp dalam kelas mono dan format tanggal yang rapi | sesuai |
| Profil: kartu Ganti Password (password saat ini, baru + meter 4 segmen, konfirmasi) | Form `POST /settings/change-password` dengan meter kekuatan 4 segmen dan toggle mata | sesuai |
| Profil: ringkasan Perangkat & Biometrik dengan tautan "Kelola" ke tab Biometrik | Kartu ringkasan memuat status USB, WebAuthn, wajah, dan tautan `data-goto-tab="biometrik"` | sesuai |
| Keamanan: kartu USB token (status, mountpoint drives, password, daftar ulang, petunjuk) | Kartu USB lengkap dengan dropdown drives backend dan teks petunjuk `USB_REREGISTER_HINT` | sesuai |
| Keamanan: kartu Kunci Pemulihan (peringatan kuning, modal konfirmasi, blok kode mono + Copy + Unduh + kotak "Sudah saya simpan") | Kartu kunci pemulihan dengan infobox peringatan, modal konfirmasi, blok kode, tombol salin, unduh .txt, dan checkbox | sesuai |
| Biometrik: kartu Face Recognition (badge status, daftar ulang wajah, bimbingan hadap kamera) | Kartu memuat elemen video, canvas, bimbingan, status text, dan tombol pendaftaran ulang | sesuai |
| Biometrik: kartu WebAuthn (tabel Nama/Ditambahkan/Hapus via KX.konfirmasiHapus, input nama + Tambah) | Tabel kredensial terstruktur dengan konfirmasi hapus KX dan form penambahan kredensial baru | sesuai |
| Sesi: dropdown batas diam sesi + tombol Simpan batas sesi | Dropdown batas waktu sesi dengan nilai bawaan dari backend dan form simpan | sesuai |
| Akun: dua kartu zona bahaya (merah outline) Reset data dan Hapus akun | Dua kartu `.kx-card-danger` bergaris tepi merah untuk Reset Data dan Hapus Akun | sesuai |
| Akun: modal tiap kartu dengan akibat jujur, password, ketik username persis, tombol submit aktif hanya jika cocok | Modal `#modal-reset-data` dan `#modal-hapus-akun` dengan validasi ketik username persis | sesuai |
| Tanpa inline JavaScript (CSP ketat) | Seluruh logika UI diisolasi di `static/js/settings.js` | sesuai |
| Gaya halaman khusus di `static/css/halaman/settings.css` | Seluruh style halaman diisolasi; `static/css/style.css` tidak diubah | sesuai |
| Teks UI bahasa Indonesia formal via `modules/strings.py`, tanpa emoji | Ditambahkan konstanta `SETTINGS_*` di `modules/strings.py`; tanpa kata terlarang dan tanpa emoji | sesuai |
| Responsif tiga lebar (desktop, tablet, mobile) | Media query breakpoint 900px dan 640px di `settings.css` | sesuai |
| Rute backend, nama field form, dan scope grant tidak diubah | Form tetap memakai `settings.change`, `biometric.manage`, dan `account.danger` sesuai backend | sesuai |

---

## Bagian 3: Pemulihan Reset Akun (P3)

### Ringkasan

Sesi P3 memodernisasi bagian reset akun tanpa masuk pada `templates/account_recovery.html` (elemen `<details id="recovery-reset">` dari UC2):

1. **Restyle dengan Komponen `kx-*`**:
   - Kontainer accordion `<details id="recovery-reset">` dikemas dalam infobox peringatan kuning `.kx-infobox.kx-infobox-warn` (`.authx-recovery-box`).
   - Teks ringkasan memuat label tautan resmi `MSG.RECOVERY_RESET_LINK` ("Hapus akun tanpa masuk") dan deskripsi keterbatasan `MSG.RECOVERY_RESET_LIMITATION`.
   - Tombol pembuka modal merah outline `.kx-btn.kx-btn-danger.kx-btn-sm` berlabel `MSG.RECOVERY_RESET_TITLE` ("Hapus Akun Tanpa Masuk") dengan pemicu `data-buka-modal="#modal-reset-account"`.
2. **Modal Dialog Konfirmasi**:
   - Menggunakan markup modal standar `.kx-modal-overlay` dan `.kx-modal` dengan id `#modal-reset-account`.
   - Memuat peringatan keterbatasan yang jelas: *"Bila kata sandi dan dongle sama-sama hilang, akun tidak dapat dihapus dari halaman ini dan data terenkripsi tidak dapat dipulihkan. Jika kata sandi dan dongle hilang, tidak ada jalur dari aplikasi."*
   - Form mengarah ke rute asli `POST /recovery/reset-account` (`action="{{ url_for('auth.recovery_reset_account') }}"`) dengan token CSRF.
   - Kolom isian mencakup: Username (`#reset-username`), Ketik Ulang Username (`#reset-confirm-username`), Kata Sandi Saat Ini (`#reset-password`) dengan toggle mata tunggal `data-kx-sandi`, dan penanda Dongle Akun (`#reset-dongle`).
   - Tombol kirim bahaya solid `.kx-btn.kx-btn-danger-solid` dan tombol pembatalan `.kx-btn.kx-btn-secondary`.
3. **Skrip dan Aksesibilitas**:
   - Pemicu modal dialog dikelola oleh `static/js/account_recovery.js` dan pustaka `static/js/ui/modal.js` tanpa JavaScript inline (mematuhi CSP).
   - Inisialisasi komponen sandi terpasang rapi.
4. **Pembaruan Dokumen U1**:
   - Catatan historis pada `docs/progress/U1.md` yang sebelumnya menyatakan tautan reset akun dilewati telah diperbarui untuk merefleksikan keberadaan dan integrasi rute `POST /recovery/reset-account`.

---

### Audit Elemen Lama (Sebelum → Sesudah) — Pemulihan Reset Akun

| Elemen / Fitur | Sebelum | Sesudah | Status | Alasan |
|---|---|---|---|---|
| Kontainer Details | `<div class="auth-note auth-note-warning">` dengan kelas CSS Bootstrap lama | `.kx-infobox.kx-infobox-warn.authx-recovery-box` dengan token kx-* | Diubah | Selaras dengan desain token U0 dan konsistensi warna peringatan. |
| Form Reset Akun | Form inline panjang di dalam `<details>` | Tombol pembuka modal di dalam details, form lengkap ditempatkan di modal `#modal-reset-account` | Diubah | Mencegah penyerahan tidak sengaja dan memberikan dialog konfirmasi terfokus. |
| Peringatan Keterbatasan | Paragraf biasa di bawah summary | Box peringatan `.kx-infobox.kx-infobox-warn` di dalam modal dengan penegasan keterbatasan aplikasi | Diubah | Memenuhi persyaratan instruksi agar konsekuensi kehilangan dongle/sandi jelas terlihat. |
| Kolom Input | `.form-control` dan `.form-group` Bootstrap lama | `.kx-field`, `.kx-label`, dan `.kx-input` dengan toggle satu mata `.kx-sandi` | Diubah | Standardisasi komponen form KOSYAK. |
| Tombol Submit | `.btn.btn-outline-danger.btn-full` | `.kx-btn.kx-btn-danger-solid` di kaki modal dialog | Diubah | Standar tombol aksi destruktif aplikasi. |
| Skrip Pemicu | Tanpa skrip modal di halaman auth | `static/js/ui/modal.js` dan `static/js/account_recovery.js` via `{% block scripts %}` | Diubah | Mematuhi CSP tanpa inline JS dan mendukung interaksi modal dialog. |

---

### Tabel Kepatuhan Spesifikasi (P3)

| Kebutuhan Spesifikasi / Prompt | Realisasi pada Sesi U1b | Status |
|---|---|---|
| Restyle `<details id="recovery-reset">` dengan komponen kx-* | Menggunakan `.kx-infobox-warn`, tombol `.kx-btn-danger`, dan summary bersih | sesuai |
| Modal konfirmasi berisi username, konfirmasi username, kata sandi | Modal `#modal-reset-account` memuat seluruh kolom isian yang disyaratkan | sesuai |
| Peringatan keterbatasan (jika kata sandi dan dongle hilang, tidak ada jalur dari aplikasi) | Box peringatan kuning di dalam modal memuat teks peringatan eksplisit | sesuai |
| Form tetap mengarah ke `POST /recovery/reset-account` | Rute target, metode POST, dan seluruh nama parameter form dipertahankan utuh | sesuai |
| Perbarui catatan di `docs/progress/U1.md` | Catatan pada tabel dan butir keputusan di `docs/progress/U1.md` diperbarui | sesuai |
| Tanpa inline JavaScript (CSP ketat) | Logika modal ditangani oleh `static/js/account_recovery.js` | sesuai |
| Bebas kata terlarang dan tanpa emoji | Seluruh teks berbahasa Indonesia formal tanpa emoji dan bebas kata terlarang | sesuai |

---

### Keputusan Desain

1. **Struktur Pembukaan Dua Tahap**: Pengguna yang membuka `<details id="recovery-reset">` terlebih dahulu membaca penjelasan keterbatasan sebelum menekan tombol merah untuk membuka dialog modal konfirmasi. Hal ini mencegah formulir destruktif terisi atau terkirim tanpa kesadaran penuh.
2. **Penggunaan Toggle Sandi pada Modal Pemulihan**: Input kata sandi di dalam modal dilengkapi komponen `data-kx-sandi` agar pengguna dapat memverifikasi ketikan kata sandi saat ini sebelum mengirim permohonan reset permanen.

---

### Keterbatasan

1. **Verifikasi Fisik Dongle**: Rute `/recovery/reset-account` tetap mewajibkan dongle fisik terpasang di server/perangkat lokal untuk membuktikan kepemilikan token sebelum penghapusan data diizinkan.
2. **Keterbatasan Aplikasi**: Sesuai prinsip kriptografi KOSYAK, jika kata sandi akun dan dongle USB sama-sama hilang, tidak ada *backdoor* maupun jalur pemulihan apa pun dari dalam aplikasi.

---

## Hasil Pengujian Keseluruhan

Rangkaian pengujian lengkap dijalankan menggunakan `pytest` di dalam lingkungan virtual Python:
- `tests/test_settings.py`: 22 passed.
- `tests/test_account_management.py`: 17 passed.
- `tests/test_password_change.py`: 6 passed.
- `tests/test_webauthn.py`: 18 passed.
- `tests/test_account_recovery.py`: 5 passed.
- `tests/test_security_center.py`: 5 passed.
- **Suite Penuh Keseluruhan (`python -m pytest -q`)**: **750 passed** (100% lulus tanpa kegagalan).
