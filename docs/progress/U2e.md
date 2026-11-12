# U2e — Perbaikan UI Lanjutan

## Ringkasan

Pekerjaan ini menutup kejanggalan antarmuka yang tersisa setelah redesain
halaman: elemen ber-atribut `hidden` yang tetap tampil, menu aksi yang
terpotong, keadaan kosong yang keliru, petunjuk formulir yang tidak sesuai
pilihan, token CSS yang tidak terdefinisi, serta jarak antarelemen aksi.
Backend, route, grant, dan alur kriptografi tidak diubah.

## Akar Masalah

1. **Tidak ada aturan `[hidden]` global.** Sebelumnya hanya kelas
   `.kx-hidden` yang memaksa `display: none`. Komponen `kx-*` yang memberi
   `display: flex`/`grid` menimpa efek atribut `hidden` sehingga elemen yang
   seharusnya tersembunyi tetap tampil.
2. **Komponen `kx-*` memberi `display` yang menimpa `hidden`.** Kartu, baris,
   grid, dan tabel tetap dirender karena deklarasi `display` pada komponen
   lebih kuat daripada perilaku bawaan atribut `hidden`.
3. **Token CSS tidak terdefinisi.** Beberapa berkas halaman memakai nama token
   yang tidak ada di `tokens.css` (`--kx-sp-*`, `--kx-surface-card`,
   `--kx-text-muted`, `--kx-teal`, `--kx-rose`, `--kx-r-full`, `--kx-fs-xs`,
   `--kx-fs-2xl`, `--kx-border-strong`). Akibatnya jarak menjadi nol dan warna
   atau latar tertentu hilang.

## Riwayat Commit

| Commit | Judul | Berkas | Perubahan |
|---|---|---|---|
| `e483b73` | `[U2e] hidden global dan dropzone` | 3 | +37 / −2 |
| `e3ba6cf` | `[U2e] menu aksi dan keadaan kosong` | 13 | +130 / −39 |
| `f36ae20` | `[U2e] crypto tools dan folder` | 6 | +80 / −16 |
| `51c656d` | `[U2e] perbaikan crypto tools dan folder` | 11 | +124 / −22 |
| `6518dac` | `[U2e] jarak dan sapuan` | 7 | +125 / −35 |
| penutup | `[U2e] tes dan dokumen` | — | tes token, selektor Security Center, dokumen ini |

## Kejanggalan per Halaman

| Halaman | Sebelum | Sesudah |
|---|---|---|
| Global (`base.css`) | Hanya `.kx-hidden` yang memaksa sembunyi; atribut `hidden` kalah oleh `display` komponen | `[hidden], .kx-hidden { display: none !important; }` sehingga seluruh keadaan tersembunyi konsisten |
| Global (`dropzone.js`) | Tombol hapus berkas tidak menghentikan propagasi; reset formulir tidak menyegarkan pratinjau | Klik hapus memanggil `preventDefault`/`stopPropagation`; event `reset` menyegarkan pratinjau |
| Dokumen (`vault.html`, `collection_folders.js`) | Pesan "tidak ada di luar folder" tampil walau koleksi masih kosong; pemindahan ke folder memuat ulang halaman | Pesan hanya muncul saat koleksi berisi data dan tab Tanpa folder kosong; item dipindah tanpa reload, badge folder di tab Semua diperbarui |
| Audio (`musik.html`, `musik.js`, `audio.css`) | Menu titik tiga terpotong pembungkus tabel; pencarian tanpa hasil tetap menampilkan tabel; pesan kosong muncul walau belum ada audio | Pembungkus dibuat `overflow: visible`, menu membalik ke atas bila mepet bawah, Escape menutup menu, tabel disembunyikan saat pencarian kosong, pesan Tanpa folder bersyarat |
| Media (`media_vault.html`, `media_albums.js`, `media.css`) | Menu kartu terpotong `overflow: hidden`; grid tetap tampil saat pencarian kosong; pesan kosong album muncul walau belum ada media; latar kartu memakai token tak terdefinisi | `overflow: visible`, menu membalik dan ditutup Escape, grid disembunyikan saat pencarian kosong, pesan album bersyarat, `--kx-surface-card` diganti `--kx-surface-2` |
| Sampah (`sampah.html`, `sampah.js`, `sampah.css`) | Filter tanpa hasil menampilkan tabel kosong; token `--kx-sp-*` dan token warna/radius/font tidak terdefinisi membuat jarak nol | Pesan "Tidak ditemukan" tampil dan tabel disembunyikan; token diganti token sah (`--kx-space-*`, `--kx-text-2`, `--kx-accent`, `--kx-danger`, `--kx-radius-pill`, `--kx-fs-caption`, `--kx-fs-title`, `--kx-border`) |
| Steganografi (`steganography.js`, `steganography.css`) | Menu aksi terpotong kartu/tabel dan tidak menutup dengan Escape | Pembungkus `overflow: visible`, varian `kx-sg-menu-atas`, Escape menutup menu, reset dropzone ikut diperbaiki |
| Catatan Aman (`secure_notes.html`) | Pesan pencarian kosong hanya paragraf; tombol "Catatan baru" berulang di dua keadaan kosong | Pesan memakai `kx-empty`; tombol dipusatkan di kepala daftar, keadaan kosong mengarahkan ke tombol tersebut |
| Account Vault (`account_vault.html`, `account_vault.css`) | Keadaan kosong menampilkan tombol tambahan yang menduplikasi formulir; jarak tombol aksi 4px | Keadaan kosong menautkan formulir di samping; jarak aksi menjadi 8px dan dapat membungkus |
| Crypto Tools (`crypto_tools.html`, `crypto_tools.js`, `modules/strings.py`) | Petunjuk kunci modern tampil juga saat Vigenere; kolom kunci rahasia tampil walau bukan Super Encryption; konstanta petunjuk duplikat | Petunjuk dan kolom mengikuti cipher/aksi; kolom kunci rahasia `hidden` bawaan; `CRYPTO_MODERN_KEY_HINT` duplikat dihapus |
| Pengaturan (`settings.css`) | Form dalam kartu tidak berjarak sehingga field menempel; deretan aksi kartu tanpa gaya | Form menjadi kolom dengan jarak 16px; deretan aksi memakai jarak 8px dan margin antarbagian |
| Security Center (`security_center.css`) | Media query 640px memakai `.kx-sc-card-head` yang tidak ada di markup, sehingga kepala kartu tidak menumpuk | Selektor diganti `.kx-sc-page .kx-card-head` sesuai markup |
| Semua halaman | Bar aksi mengambang tidak memiliki aturan untuk wadah tombolnya | `.kx-aksi-mengambang-tombol` memakai flex, wrap, dan jarak 8px |

## Keputusan

1. **Aturan `[hidden]` global** dipilih daripada menambah `!important` per
   komponen. Satu aturan di `base.css` menutup seluruh kasus dan mencegah
   komponen `kx-*` menimpa keadaan tersembunyi.
2. **Tab Semua dan Tanpa folder.** Tab Semua menampilkan seluruh berkas,
   termasuk yang berada di folder, beserta badge nama folder. Tab Tanpa folder
   hanya menampilkan berkas tanpa folder. Pesan kosong "tidak ada di luar
   folder" hanya dirender bila koleksi memiliki data dan disembunyikan bila
   masih ada berkas tanpa folder. Bila koleksi sama sekali kosong, keadaan
   kosong umum yang ditampilkan, bukan pesan Tanpa folder.
3. **Pemindahan ke folder tanpa reload.** Item yang dipindah dihapus dari
   daftar Tanpa folder, badge folder diperbarui di tab Semua, bilah pilihan
   ditutup, dan keadaan kosong dimunculkan bila daftar menjadi kosong.
4. **Token terdekat, bukan token baru.** Token yang tidak terdefinisi diganti
   dengan token yang sudah ada dan paling dekat maknanya. Tidak ada token baru
   yang dibuat.
5. **Tes token global.** Tes membaca `tokens.css`, `components.css`,
   `base.css`, dan `static/css/halaman/*.css`, lalu memastikan setiap
   `var(--kx-...)` terdefinisi secara global atau lokal pada berkas yang sama.
6. **Satu perbaikan global di `components.css`.** Aturan
   `.kx-aksi-mengambang-tombol` ditambahkan karena wadah tombol bar aksi
   mengambang tidak memiliki aturan sama sekali dan dipakai lintas halaman.

## Temuan yang Dibiarkan

| Temuan | Alasan |
|---|---|
| Bar penyimpanan Dashboard hanya satu segmen penuh, sedangkan legend menampilkan empat jenis | Perlu data ukuran per jenis dari backend; di luar lingkup perbaikan tampilan |
| Warna `rgba(13, 148, 136, ...)` hardcoded pada `sampah.css` | Nilai masih sesuai warna aksen; penggantian token warna memerlukan token bayangan/aksen transparan baru |
| `audio.css` tidak diakhiri newline | Tidak memengaruhi tampilan atau perilaku; dibiarkan agar diff tidak melebar |

## Hasil Tes

- Tes kontrak terarah: `7 passed in 0.85s`
  (`test_u2e_token_css.py`, `test_u2e_spacing.py`).
- Suite penuh: `787 passed in 339.24s (0:05:39)`.
- Jumlah tes berada di atas 774 dan tidak ada tes yang dilemahkan.
