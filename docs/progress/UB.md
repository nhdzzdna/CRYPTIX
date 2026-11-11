# UB — Sampah, kunci item & album, pratinjau dokumen

## Bagian 1 — Sampah (hapus lunak, pulihkan, hapus permanen)

### Ringkasan
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

### File yang berubah
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

### Keputusan
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

### Keterbatasan
- Pemulihan (restore) tidak menulis blok blockchain apa pun; jejak
  pindah-ke-sampah (`TRASH_MOVE`) tetap terlihat di log.
- `_humanize_action` pada `modules/assistant/security_agent.py` tidak
  diubah sehingga `TRASH_MOVE` tampil sebagai teks mentah di penjelasan
  log asisten (perilaku pra-ada untuk aksi baru lain juga demikian).
- Pembersihan retensi hanya terjadi saat startup dan saat halaman
  `/sampah` dibuka; tidak ada scheduler latar belakang.
- Uji manual peramban (alur konfirmasi + modal autentikasi ulang) belum
  dilakukan; hanya diuji otomatis di level endpoint.

### Temuan di luar lingkup
- Berkas tak terlacak `t fix N2B matcher endpoint test` sudah ada di
  repo sebelum perubahan ini; tidak disentuh dan tidak ikut di-commit.
- `templates/documents.html` masih memakai atribut `style="display:inline"`
  (pra-ada; tidak diubah agar diff tetap fokus).
- `_humanize_action` belum mengenali `DOWNLOAD` dan `TAMPER_DETECTED`
  (pra-ada).

### Tes
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

## Bagian 2 — Kunci item dan kunci album/folder

### Ringkasan
Fitur kunci per item dan kunci album/folder untuk Media, Dokumen, dan
Audio:
- State item `hidden` dihapus total (schema, kode, uji); migrasi aditif
  idempoten `_migrasi_state_item()` mengubah baris lama `hidden` menjadi
  `locked` saat startup. State sah tinggal `normal`/`locked`.
- Item terkunci tetap tampil di daftar dengan penanda (ikon gembok,
  label "Terkunci"); thumbnail-nya ditolak server dengan 403 JSON
  reason `terkunci` sampai grant aktif.
- Scope baru: `item.view` (reusable 15 menit per item) dan `item.unlock`
  (sekali pakai, resource = id koleksi). Kunci koleksi tetap
  `album.unlock` (reusable) dan hanya menjadi pintu masuk — isi album
  terkunci tidak muncul di bagian "Semua".
- "Semua" = "Tanpa album" + isi koleksi terbuka; isi koleksi terkunci
  ikut disertakan hanya bila grant `album.unlock` koleksi itu sedang
  aktif saat render.
- Mengunci item tidak memerlukan grant; melepas kunci memerlukan
  `item.unlock` sekali pakai untuk koleksi pemilik item.
- Semua endpoint konten (thumb/view/stream/play/download/decrypt)
  menolak item terkunci dengan 403 JSON reason `terkunci`.
- Filter `deleted_at` Bagian 1 tetap bekerja di semua jalur baru
  (item sampah 404 walau grant valid).

### File yang berubah
- Skema/migrasi: `database/schema.sql`, `database/db.py`.
- Registri: `modules/authentication/reauth.py` (`item.view`,
  `item.unlock` di SCOPES; `item.view` di REUSABLE_TTL),
  `modules/strings.py` (`ITEM_LOCKED`, `ITEM_UNLOCKED`,
  `COLLECTION_ALL_SECTION`, tombol Kunci/Lepas kunci, dsb.; string
  `*HIDDEN*` lama dihapus).
- Backend: `routes/collection_routes.py` (`set_item_state` dengan grant
  manual saat melepas kunci, `list_items` mengirim state terkunci,
  `musik()` mengirim "Semua"), `routes/collection_shared.py`
  (`akses_item`, `grant_sah` dengan fallback grant aktif,
  `halaman_koleksi` menyusun "Semua", `file_info` membawa state dan
  collection_id), `routes/media_routes.py` (helper `_respons_terkunci`
  + cek `akses_item` di view/thumb/stream/play/download),
  `routes/vault_routes.py` (decrypt terkunci + pesan dialog kunci).
- Antarmuka: `templates/media_vault.html`, `templates/musik.html`,
  `templates/vault.html` (bagian "Semua", tombol Kunci/Lepas kunci,
  penanda item terkunci), `static/js/item_lock.js` (baru — dialog
  CryptixLock: Lihat sekali / Lepas kunci / Batal),
  `static/js/collection_folders.js`, `static/js/media_albums.js`,
  `static/js/musik.js`, `static/js/dokumen.js` (dedupe pencarian),
  `static/css/style.css`.
- Uji: `tests/test_ub_kunci.py` (baru), `tests/test_n3a_koleksi.py` dan
  `tests/test_n3b_musik_dokumen.py` diperbarui dari semantik
  tersembunyi ke semantik terkunci.

### Keputusan
1. Urutan cek akses: album terkunci dicek DULU (`album.unlock`,
   resource = id koleksi), baru state item (`item.view`, resource = id
   berkas). Penolakan berupa JSON 403 reason `terkunci` lewat helper
   `_respons_terkunci`.
2. `/api/collections/<id>/items` tetap 401 REAUTH_REQUIRED saat album
   terkunci tanpa grant (perilaku pra-ada); hanya endpoint konten yang
   memakai 403 `terkunci` agar `<img>` gagal senyap dan fetch JS
   mendapat alasan yang jelas.
3. `set_item_state`: grant `item.unlock` dicek manual HANYA saat state
   target `normal` (mengunci bebas grant), dan dicek SEBELUM cek
   eksistensi/milik koleksi — item sampah tanpa grant ditolak 401
   (bukan 404); dengan grant valid baru 404. 401 untuk
   missing/expired/invalid, 403 untuk scope/resource salah.
4. Pesan sukses melepas kunci = `ITEM_UNLOCKED` (mengunci tetap
   `COLLECTION_STATE_CHANGED`) agar UI dapat membedakan hasil.
5. Bagian "Semua" ditempatkan setelah panel detail koleksi, sebelum
   "Tanpa album/folder"; pencarian dokumen melakukan dedupe hanya saat
   kueri aktif (wadah yang lebih dulu menang).
6. Dialog pilihan tampil DULU ("Lihat sekali"/"Lepas kunci"/"Batal")
   sebelum autentikasi ulang — penyimpangan disengaja dari spek
   ("verifikasi dulu") agar hanya SATU reauth sesuai aksi yang dipilih.
7. `mintaGrant` selalu via tombol sintetis ber-atribut `data-reauth`
   (memakai modal `reauth.js` tanpa menyalin logikanya); guard generasi
   mencegah grant basi dari dialog yang sudah ditutup.
8. Thumbnail terkunci ditolak server (403), bukan disembunyikan dari
   daftar — klien mengganti gambar gagal dengan ikon gembok lewat
   listener fase capture.
9. `grant_sah` mencoba token header lebih dulu lalu kembali ke grant
   berulang aktif sesi — dibutuhkan saat header membawa token scope
   lain (mis. `item.view`) sementara cek album membutuhkan
   `album.unlock` yang sudah aktif.

### Keterbatasan
- Item di luar koleksi ("Tanpa album") tidak dapat dikunci — baris
  `collection_items` mengharuskan koleksi; tombol lepas kunci juga
  menolaknya di klien.
- Isi koleksi terkunci hanya muncul di "Semua" bila grant
  `album.unlock` aktif saat render; tidak ada tautan khusus untuk
  membukanya dari bagian itu (harus lewat panel album).
- Halaman Media dan Audio tidak memiliki pencarian nama (pra-ada;
  hanya halaman Dokumen).
- Aturan CSS `.hidden-section`/`.media-hidden-*` lama kini tanpa
  pemakai (pra-ada; dibiarkan agar diff tetap fokus).

### Tes
- `tests/test_ub_kunci.py` (baru): 22 lulus — migrasi `hidden`→
  `locked` idempoten, state invalid 400, mengunci tanpa grant, item
  terkunci tetap tampil dengan penanda + `data-locked`, `/hidden` 404,
  tanpa `hidden_count`, view/thumb/stream/play/download/decrypt 403
  reason `terkunci`, `item.view` membuka semua endpoint, grant
  reusable kedaluwarsa (+901 detik), `item.unlock` sekali pakai /
  scope salah / resource salah / koleksi salah, "Semua"
  mengecualikan lalu menyertakan album terkunci (Media, Musik,
  Dokumen), interaksi sampah (404 walau grant ada).
- `tests/test_n3a_koleksi.py`, `tests/test_n3b_musik_dokumen.py`:
  tes "tersembunyi" lama diganti semantik terkunci (item tetap tampil
  tapi butuh grant) — perubahan spek, bukan pelemahan.
- Suite penuh pada tree Bagian 2 (tanpa tes pratinjau): 661 lulus
  (639 baseline setelah merge origin/main + 22 tes kunci baru).

## Bagian 3 — Pratinjau dokumen

### Ringkasan
- Endpoint `GET /media-vault/preview/<file_id>` dengan grant reusable
  `doc.preview` (15 menit per item). Dekripsi hanya di memori; hash
  plaintext diverifikasi seperti rute view — tamper memicu blok
  `TAMPER_DETECTED` + 403.
- Jenis dideteksi dari magic bytes plaintext (bukan ekstensi): PDF
  (`%PDF-`) dan gambar (PNG/JPEG/GIF87a/GIF89a/BMP/WEBP) disajikan
  inline; teks UTF-8 tanpa byte NUL dikirim sebagai JSON (dipotong
  `MAX_TEXT_BYTES` = 1.000.000, penanda `truncated`); jenis lain
  ditolak 415 JSON reason `jenis`.
- Header khusus hanya untuk pratinjau PDF: `X-Frame-Options:
  SAMEORIGIN` dan `Content-Security-Policy: frame-ancestors 'self'`
  (global tetap DENY/`'none'`; `after_request` memakai `setdefault`
  sehingga tidak menimpa). Semua respons pratinjau `no-store`.
- Antarmuka: tombol "Pratinjau" pada setiap baris dokumen (termasuk
  kartu dinamis isi folder) dan klik baris dokumen terkunci → dialog
  CryptixLock → grant `doc.preview` → modal sederhana (gambar/PDF via
  blob URL, teks via `<pre>`; Escape/klik latar menutup dan mencabut
  blob).

### File yang berubah
- `routes/media_routes.py` (endpoint `preview`, `_deteksi_jenis`,
  konstanta magic bytes), `modules/authentication/reauth.py`
  (`doc.preview` di SCOPES dan REUSABLE_TTL),
  `modules/strings.py` (`DOC_PREVIEW_*`), `routes/vault_routes.py`
  (kunci pesan pratinjau di `_dokumen_msg`),
  `templates/vault.html` (tombol Pratinjau, modal `#preview-modal`),
  `static/js/dokumen.js` (logika modal pratinjau),
  `static/js/collection_folders.js` (tombol Pratinjau kartu dinamis +
  klik baris dokumen terkunci), `static/css/style.css` (gaya modal),
  `tests/test_ub_pratinjau.py` (baru).

### Keputusan
1. `doc.preview` berlaku sebagai pengganti `item.view` di
   `akses_item` (parameter `scope_item`) — keduanya verifikasi ulang
   per item, dan kunci koleksi tetap memerlukan `album.unlock`.
   Konsekuensi teruji: decorator `require_grant` tetap menuntut
   `doc.preview` di header (grant `item.view` aktif saja → 401
   missing), salah scope → 403 scope, album terkunci tanpa
   `album.unlock` aktif → 403 `terkunci`.
2. Fallback `find_active_grant` pada `grant_sah` memungkinkan header
   yang membawa token `doc.preview` tetap lolos cek `album.unlock`
   yang sudah aktif di sesi (token header gagal untuk scope lain,
   grant berulang dicari ulang).
3. Teks dikirim sebagai JSON, bukan `text/plain`, agar ukuran dan
   status terpotong eksplisit serta tidak dapat disalahartikan
   sebagai HTML; browser merendernya lewat `textContent` (aman XSS).
4. PDF dan gambar dimuat klien sebagai blob di memori
   (`URL.createObjectURL`, dicabut saat modal ditutup) — tidak ada
   berkas sementara di disk.
5. Berkas kosong (`b""`) terdeteksi sebagai teks — kasus tepi
   diterima karena tanpa NUL dan valid UTF-8.

### Keterbatasan
- DOCX/PPTX/XLSX tidak dipratinjau (415) — hanya PDF, gambar, dan
  teks; format kantor perlu diunduh untuk dilihat.
- Deteksi hanya mengenali magic bytes yang terdaftar (TIFF dll. tidak
  didukung). SVG jatuh ke jalur teks (XML valid UTF-8), bukan
  dirender sebagai gambar — menghindari skrip aktif dalam SVG.
- Pratinjau memuat seluruh plaintext ke memori klien; berkas sangat
  besar dapat memakan RAM (batas teks ada, batas PDF/gambar tidak).
- PDF ditampilkan lewat `<iframe>` blob — bergantung penampil PDF
  bawaan peramban.
- Verifikasi ulang untuk pratinjau berjenjang (401 decorator → 403
  `terkunci`) — dua lapis; pengguna melihat dialog reauth dulu,
  baru penolakan kunci.

### Catatan pemeliharaan
- Commit Bagian 2 (`1289c70`) tanpa sengaja menyertakan fragmen kode
  mati di `routes/media_routes.py` (draf lama `_deteksi_jenis` +
  `MAX_TEXT_BYTES = 512*1024`, tak pernah direferensikan di state
  Bagian 2; suite 661 tetap lulus dengannya). Diterapkan fix-forward:
  commit Bagian 3 ini menghapus fragmen tersebut sekaligus memasang
  versi final `_deteksi_jenis` — tidak ada rewrite history.

### Tes
- `tests/test_ub_pratinjau.py` (baru): 28 lulus — deteksi jenis
  (PDF, semua magic gambar + WEBP, teks; NUL dan non-UTF-8 → None),
  tanpa grant 401 missing, salah scope 403, PDF inline + header
  SAMEORIGIN/CSP `frame-ancestors 'self'`/inline/no-store, 6 jenis
  gambar inline + mime, teks JSON + terpotong, 415 reason `jenis`,
  grant reusable 15 menit, item terkunci (`item.view` aktif tidak
  cukup → `doc.preview` 200), album terkunci (403 lalu 200 dengan
  `album.unlock` aktif — menguji fallback `grant_sah`), pengguna lain
  404, item sampah 404, berkas dirusak → 403 + `TAMPER_DETECTED`.
- Suite penuh tree lengkap Bagian 2+3: 689 lulus (661 + 28).
