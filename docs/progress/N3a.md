# N3a — Koleksi dan Album Media (foto dan video)
- Audit: media_routes.py menyajikan audio/video lewat vault_files; stream memakai grant `media.stream` berulang 15 menit; play/download memakai scope masing-masing; semua query memakai user_id.
- Audit: media_vault.html masih tabel audio/video; media_vault.js hanya mengisi src setelah grant `media.stream`; tidak ada inline JS.
- Audit: reauth.py SCOPES + REUSABLE_TTL menjadi titik tambah `album.unlock`; require_grant mengambil resource dari resource_id/file_id/img_id dan mencari grant aktif untuk scope berulang.
- Audit: vault_routes.py menyimpan original_name terenkripsi AES-GCM dengan field_aad(user_id,"vault_files","original_name"); stored_name acak; pola ini dipakai untuk collections.name_enc.
- Audit: schema.sql memakai CREATE TABLE IF NOT EXISTS; init_db menjalankan skrip penuh sehingga DB lama otomatis mendapat tabel baru tanpa ALTER.
- Audit: test_media_routes.py dan test_j2_grants.py bergantung pada stream/play/download yang tidak boleh berubah; halaman media harus tetap memuat audio/video controls, jalur stream, dan csrf_token.
- Rencana Fase 1: tabel collections + collection_items; blueprint collection_routes.py; scope album.unlock; rute view/thumb dengan Range dan aturan state.
- Rencana Fase 2: galeri album, penampil modal, pilih banyak, JS media_albums.js, CSS tambahan.
- Rencana Fase 3: tests/test_n3a_koleksi.py dan verifikasi database lama.
