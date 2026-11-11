# UB — Sampah (hapus lunak, pulihkan, hapus permanen)

## Ringkasan
Fitur Sampah untuk berkas, catatan, kredensial, dan gambar stego:
- Hapus lunak lewat kolom `deleted_at` (TEXT NULL) pada `vault_files`,
  `secure_notes`, `account_vault`, `stego_images`; migrasi aditif dan
  idempoten, format serta konstanta kriptografi tidak berubah.
- Semua daftar, hitungan dashboard, pencarian, thumbnail, pratinjau,
  stream, unduh, dan ekstraksi stego mengecualikan item sampah; akses
  langsung ke item sampah mengembalikan 404.
- Halaman `/sampah` dengan kolom pilih/nama/jenis/tanggal dihapus/sisa
  hari; judul dan nama didekripsi di server memakai kunci field sesi.
- API `POST /api/sampah/pulihkan`, `POST /api/sampah/hapus-permanen`,
  `POST /api/sampah/kosongkan` menerima daftar `{jenis,id}`; CSRF tetap
  wajib, hapus permanen dan kosongkan memerlukan grant sekali pakai
  `trash.purge`.
- Purge menghapus baris DB, berkas terenkripsi di disk, dan relasi
  `collection_items`, lalu mencatat blok `DELETE`; pindah ke sampah
  dicatat sebagai blok `TRASH_MOVE` (terdaftar di ACTIONS dan diberi
  badge merah di Security Center).
- Retensi `TRASH_RETENTION_DAYS = 30`: item kedaluwarsa dibersihkan saat
  startup (semua pengguna) dan saat `/sampah` dibuka (pengguna sesi),
  tanpa scheduler.

## File yang berubah
- Inti: `modules/trash.py` (baru), `routes/trash_routes.py` (baru),
  `templates/sampah.html` (baru), `static/js/sampah.js` (baru).
- Skema/migrasi: `config.py`, `database/schema.sql`, `database/db.py`
  (`_TABEL_SAMPAH` + `_tambah_kolom_sampah()` dari `init_db()`).
- Registri: `modules/blockchain/blockchain.py` (`TRASH_MOVE` di ACTIONS),
  `modules/authentication/reauth.py` (`trash.purge` di SCOPES),
  `modules/strings.py` (konstanta `TRASH_*`).
- Endpoint hapus menjadi lunak: `routes/{vault,notes,account,stego}_routes.py`.
- Filter `deleted_at IS NULL`: `routes/media_routes.py`,
  `routes/collection_routes.py`, `routes/collection_shared.py`,
  `routes/dashboard_routes.py`, serta daftar indeks vault/notes/account/stego.
- Antarmuka: `templates/base.html` (menu Sampah), `templates/vault.html`,
  `templates/documents.html`, `templates/account_vault.html`,
  `templates/secure_notes.html` (tombol hapus tanpa `data-reauth`),
  `templates/security_center.html` (badge), `static/js/collection_folders.js`.
- Bootstrap: `app.py` (registrasi `trash_bp` + `bersihkan_kedaluwarsa()`
  saat startup).
- Uji: `tests/test_ub_sampah.py` (baru), `tests/test_encrypted_storage.py`
  (3 test hapus disesuaikan).

## Keputusan
1. Blok `DELETE` ditulis di dalam `modules/trash.py` (bukan di route),
   dengan hash aset dihitung SEBELUM berkas fisik dihapus — kritis untuk
   gambar stego yang hash-nya adalah SHA-256 berkas tersimpan.
   `add_block` selalu setelah commit DB, mengikuti pola rute lain.
2. `hapus_permanen_banyak` dan `pulihkan_banyak` bersifat all-or-nothing:
   seluruh item divalidasi lebih dulu, lalu diubah, commit sekali;
   `hapus_permanen` satu item mendelegasikan versi batch.
3. `bersihkan_kedaluwarsa(user_id=None)`: cutoff dibandingkan sebagai
   string `deleted_at <= (now - retensi)` terhadap format SQLite
   `YYYY-MM-DD HH:MM:SS`.
4. `verify_assets` blockchain sengaja tidak diubah: item sampah tetap
   diverifikasi rantai sampai benar-benar di-purge (aset masih ada).
5. Hapus lunak tidak memerlukan grant (ubah spek dari `item.delete`);
   login, limiter, dan CSRF tetap wajib. Scope `item.delete` tetap
   terdaftar di SCOPES karena dipakai uji mismatch scope pada rute
   unduh/reveal.
6. Restore tidak dicatat di blockchain (lihat Keterbatasan).
7. Respons API: JSON bila permintaan JSON/XHR, selain itu 302 + flash ke
   `/sampah` (helper `_selesai`).
8. Tombol "Hapus permanen"/"Kosongkan sampah" berupa `type="button"` +
   `data-reauth="trash.purge"`; setelah grant terbit, `sampah.js`
   menampilkan dialog konfirmasi lalu mengirim form dengan field
   `reauth_grant` — tanpa JavaScript inline dan tanpa melonggarkan CSP.
9. Endpoint hapus stego tetap tanpa limiter/grant sesuai perilaku lama.

## Keterbatasan
- Pemulihan (restore) tidak menulis blok blockchain apa pun; jejak
  pindah-ke-sampah (`TRASH_MOVE`) tetap terlihat di log.
- `_humanize_action` pada `modules/assistant/security_agent.py` tidak
  diubah sehingga `TRASH_MOVE` tampil sebagai teks mentah di penjelasan
  log asisten (perilaku pra-ada untuk aksi baru lain juga demikian).
- Pembersihan retensi hanya terjadi saat startup dan saat halaman
  `/sampah` dibuka; tidak ada scheduler latar belakang.
- Uji manual peramban (alur konfirmasi + modal autentikasi ulang) belum
  dilakukan; hanya diuji otomatis di level endpoint.

## Temuan di luar lingkup
- Berkas tak terlacak `t fix N2B matcher endpoint test` sudah ada di
  repo sebelum perubahan ini; tidak disentuh dan tidak ikut di-commit.
- `templates/documents.html` masih memakai atribut `style="display:inline"`
  (pra-ada; tidak diubah agar diff tetap fokus).
- `_humanize_action` belum mengenali `DOWNLOAD` dan `TAMPER_DETECTED`
  (pra-ada).

## Tes
- `tests/test_ub_sampah.py` (baru): 41 lulus — migrasi dua kali tanpa
  galat, kolom `deleted_at`, hapus lunak tanpa grant + blok `TRASH_MOVE`
  + berkas fisik tetap ada, 404 akses langsung (decrypt/view/thumb/
  stream/download/open/reveal/extract/stego), daftar dan dashboard
  mengecualikan sampah, halaman sampah (judul terdekripsi, kosong),
  pulihkan (form + JSON + CSRF + all-or-nothing + item tidak sah),
  hapus permanen (401 tanpa grant, 403 scope salah, sekali pakai,
  berkas fisik + relasi koleksi terhapus, blok `DELETE`, banyak jenis,
  stego), kosongkan, retensi fake date (kedaluwarsa dibersihkan, segar
  tetap, hanya milik pengguna sesi), isolasi antar pengguna (pulihkan/
  purge/kosongkan/halaman), dan scope `trash.purge`.
- `tests/test_encrypted_storage.py`: 3 test hapus diperbarui ke semantik
  sampah (302 tanpa grant, `deleted_at` terisi, blok `TRASH_MOVE`,
  baris dan berkas fisik tetap ada) — perubahan spek, bukan pelemahan;
  uji IDOR hapus lama tetap lolos tanpa perubahan.
- Suite penuh: 731 lulus (baseline sebelum perubahan: 690).
