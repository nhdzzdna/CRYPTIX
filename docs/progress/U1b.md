# U1b — Security Center

## Ringkasan

Sesi U1b menyelesaikan modernisasi antarmuka Security Center (`templates/security_center.html`, rute `GET /security-center` dan `POST /security-center/verify`) sesuai panduan `docs/desain/spesifikasi-ui.txt` §117–120, katalog fondasi U0 (`docs/progress/U0.md`), serta instruksi kerja:

1. **Kartu Blockchain Integrity**: Memuat 4 stat (Total blok, Indeks terakhir, Jangkar head, Verifikasi terakhir) dan tombol "Verifikasi integritas" di kanan atas header kartu (`kx-card-head`). Di dalamnya terdapat visual rantai horizontal (`#n`) dengan diferensiasi warna per blok (hijau valid, merah rusak, teal terbaru, abu belum diverifikasi), serta hash jangkar lengkap di dalam blok kode mono dengan tombol Salin (`data-kx-salin`). Hasil verifikasi ditampilkan lewat banner kartu (hijau utuh, merah menunjukkan kerusakan) dan notifikasi `KX.toast`.
2. **Kartu Log Aktivitas Blockchain**: Chip filter dinamis mencakup tipe blok yang ada sesuai daftar `ACTIONS` pada `modules/blockchain/blockchain.py` (termasuk `TRASH_MOVE`, `DELETE`, `ACCOUNT_DELETE`, dan lainnya). Tabel mencakup kolom Nomor, Waktu (`mono`), Aksi (badge warna per kategori tindakan), Asset hash, dan Block hash (sel hash dipotong 16 karakter dengan tombol Salin via `data-kx-hash`). Tombol "Ekspor CSV" ditiadakan karena belum tersedia pada backend.
3. **Kartu Keutuhan Aset Milik Anda**: Ditampilkan secara kondisional saat data aset tersedia (`assets is not none`), dimodernisasi menggunakan tabel `kx-table` dengan badge status tanpa emoji.
4. **Gaya dan Skrip**: Gaya tampilan diisolasi pada `static/css/halaman/security_center.css` lewat `{% block styles %}` tanpa memodifikasi `static/css/style.css`. Logika interaktif (filter chip dan toast hasil verifikasi) ditempatkan pada `static/js/security_center.js` tanpa JavaScript inline untuk mematuhi CSP. Seluruh teks antarmuka menggunakan bahasa Indonesia formal dari `modules/strings.py` tanpa emoji.

---

## Audit Elemen Lama (Sebelum → Sesudah)

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
| Emoji status dan badge | Menggunakan emoji `✅`, `⚠`, `🗂`, `❔` | Badge teks bersih (`kx-badge-ok`, `kx-badge-danger`, `kx-badge-warn`, `kx-badge-info`) dengan ikon SVG sprite | Diubah | Aturan bebas emoji di seluruh antarmuka. |

---

## Tabel Kepatuhan Spesifikasi

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

## Keputusan Desain

1. **Penempatan Tombol Verifikasi**: Tombol "Verifikasi integritas" dipindahkan dari topbar ke header kartu Integritas Blockchain (`kx-card-head`), merapikan topbar dan memusatkan kontrol langsung pada kartu yang relevan.
2. **Penyaringan Chip Dinamis**: Filter chip dihasilkan dari kumpulan aksi yang benar-benar ada pada data blok pengguna, sehingga tidak membingungkan pengguna dengan filter kosong yang tidak memiliki catatan.
3. **Penyelarasan Warna Visual Rantai**: Warna blok visual rantai memprioritaskan indikator kerusakan (merah jika tampered), kemudian kebaruan (teal jika indeks terakhir), keabsahan (hijau jika terverifikasi valid), dan abu-abu jika belum diperiksa.
4. **Pembaruan Pengujian Tanpa Emoji**: String pencocokan emoji pada pengujian lama (`✅ OK`, `⚠ DIUBAH`, `🗂 HILANG`, `❔ TANPA CATATAN`) diselaraskan dengan teks lencana murni (`OK`, `DIUBAH`, `HILANG`, `TANPA CATATAN`) untuk menegakkan aturan anti-emoji tanpa melemahkan pengujian.

---

## Keterbatasan

1. **Ekspor CSV**: Tombol "Ekspor CSV" tidak diimplementasikan pada antarmuka karena backend rute `/security-center` saat ini tidak menyediakan endpoint maupun handler untuk pembuatan berkas CSV log aktivitas blockchain.

---

## Hasil Pengujian

Pengujian terarah dan penuh dijalankan menggunakan `pytest` di dalam lingkungan virtual Python:
- `tests/test_security_center.py`: 5 passed.
- `tests/test_u0_shell.py`, `tests/test_dashboard.py`, `tests/test_u3_ui.py`: 28 passed.
- Suite pengujian lengkap (`pytest -q`): seluruh item lulus tanpa galat.
