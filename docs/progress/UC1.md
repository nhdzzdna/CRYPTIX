# Sesi UC1: wajah, pilihan biometrik, dongle

## Ringkasan

Sesi ini memperbaiki tiga hal pada alur autentikasi:

1. Pendaftaran dan verifikasi wajah lebih tahan terhadap deteksi palsu,
   wajah sekunder, dan mata tertutup.
2. Tahap 2 login memakai satu metode biometrik pilihan pengguna, bukan
   menuntut semua metode terdaftar.
3. Daftar ulang dongle tidak lagi memilih drive secara diam-diam dan tidak
   merusak berkas token lama bila proses gagal.

## Perubahan

### Wajah

- `modules/authentication/face_recognition.py`
  - Deteksi wajah memakai `scaleFactor=1.1`, `minNeighbors=6`, dan ukuran
    minimum sekitar 15% sisi terpendek frame.
  - Kandidat wajah sekunder hanya dihitung bila luasnya minimal 40% wajah
    terbesar. Penolakan wajah ganda memakai ambang lebih dari 30% frame,
    bukan satu frame.
  - Pemeriksaan mata memakai `haarcascade_eye.xml` pada 60% bagian atas ROI
    wajah, dengan cadangan `haarcascade_eye_tree_eyeglasses.xml`.
  - Pendaftaran membuang frame dengan mata tertutup. Verifikasi menolak bila
    kurang dari 70% frame memiliki mata terbuka dan mengembalikan kode
    `mata_tertutup`.
- `modules/strings.py`
  - Pesan `FACE_EYES_CLOSED` dan `FACE_ENROLL_EYES_CLOSED`.
- `tests/test_uc1_wajah.py`
  - Uji kandidat kecil palsu, dua wajah sebanding, mata tertutup pada
    pendaftaran dan verifikasi, serta cadangan kacamata.
- Tes wajah lama disesuaikan hanya pada bagian tiruan deteksi: fungsi mata
  kini juga perlu ditirukan agar tes lama tetap menguji alur yang sama.

### Pilihan biometrik

- `modules/authentication/biometrics.py`
  - Fungsi baru `verifikasi_metode_biometrik()` memeriksa tepat satu metode
    yang dipilih. Metode yang tidak terdaftar ditolak sebelum bukti diperiksa.
  - Detail kegagalan metode (mis. `mata_tertutup`) diteruskan ke pemanggil.
  - `verifikasi_tahap_biometrik()` dan `kebijakan_dipenuhi()` diberi tanda
    DEPRECATED dan dipertahankan sementara untuk pengujian unit registry.
- `routes/auth_routes.py`
  - `/login/biometric` menerima `metode` dan hanya memverifikasi metode itu.
  - Klien lama yang mengirim satu kunci bukti tanpa `metode` tetap dilayani.
    Bila ada lebih dari satu bukti tanpa pilihan, permintaan ditolak.
  - Batas laju `FACE_VERIFY_LIMIT` dan urutan tahap tidak berubah.
- `static/js/login.js`, `templates/login.html`
  - Satu metode langsung dijalankan otomatis.
  - Dua metode atau lebih menampilkan tombol per metode; pengguna memilih
    satu. Tidak ada JavaScript inline dan CSP tetap ketat.
- `tests/test_uc1_pilih_biometrik.py`
  - Uji masing-masing metode, satu bukti tanpa `metode`, metode tidak
    terdaftar, tanpa tahap 1, dan penerusan kode `mata_tertutup`.
- `tests/test_two_stage_login.py`
  - Uji rute kebijakan `all_enrolled`/`any` diganti uji pilihan satu metode.
    Kebijakan lama tidak lagi dipakai rute; pengujian unit fungsi kebijakan
    lama tetap dipertahankan.

### Dongle

- `modules/authentication/usb_authentication.py`
  - `buat_token()` menyiapkan rahasia baru di memori tanpa menulis berkas.
  - `tulis_token()` menulis berkas sementara lalu `os.replace` (atomik).
  - `pulihkan_token()` mengembalikan berkas lama bila pembaruan basis data
    gagal.
  - Format berkas token tidak berubah.
- `modules/authentication/auth.py`
  - `reregister_usb_token()` menolak mountpoint kosong bila ada lebih dari
    satu kandidat, memakai satu-satunya kandidat bila hanya ada satu, dan
    menolak mountpoint yang bukan kandidat.
  - Rahasia baru dibungkus ulang dan diuji buka di memori lebih dahulu.
  - Berkas token baru ditulis atomik, lalu basis data diperbarui. Bila
    pembaruan basis data gagal, berkas lama dipulihkan.
- `routes/settings_routes.py`, `templates/settings.html`
  - Settings menerima `drives` dari `daftar_drive()` dan menampilkan
    `<select name="mountpoint">`.
  - Pesan panduan: "Cabut dongle lama, colok dongle baru, lalu daftarkan."
- `tests/test_uc1_dongle.py`
  - Reproduksi sebelum perbaikan: mountpoint kosong memilih drive pertama
    secara diam-diam dan kegagalan bungkus ulang tetap menimpa berkas token.
  - Setelah perbaikan: daftar ulang berulang, penggantian dongle, satu dan
    dua kandidat, mountpoint tidak dikenal, kegagalan bungkus ulang,
    kegagalan tulis token, kegagalan simpan basis data, serta login dengan
    dua dongle tercolok.
- `tests/test_settings.py`
  - Uji pilihan dongle pada Settings berasal dari `daftar_drive()`.

## Keputusan

- Wajah sekunder tetap dipakai sebagai sampel pendaftaran bila lolos
  pemeriksaan, tetapi frame yang memuatnya ikut dihitung pada ambang 30%.
- Bila sampel tidak cukup dan ada frame mata tertutup yang dibuang, pesan
  yang ditampilkan adalah pesan mata tertutup.
- Pemilihan satu metode biometrik menggantikan kebijakan `all_enrolled`
  pada rute login. Konstanta `BIOMETRIC_POLICY` masih dibaca fungsi lama
  yang DEPRECATED agar pengujian unit lama tidak berubah.
- Mountpoint eksplisit dari pengguna selalu divalidasi terhadap kandidat
  drive; nilai kosong tidak pernah diterjemahkan menjadi "drive pertama"
  saat ada lebih dari satu kandidat.

## Keterbatasan

- Pemeriksaan mata hanya memakai Haar Cascade dan ROI sederhana. Ini bukan
  anti-spoofing dan tidak dapat menolak foto atau tampilan layar yang
  menampilkan wajah dengan mata terbuka.
- Penulisan berkas token dan pembaruan basis data belum merupakan transaksi
  dua fase lintas media. Bila proses berhenti tepat di antara keduanya,
  pemulihan otomatis tidak berjalan; pengguna perlu mendaftarkan ulang.
- Deteksi drive masih bergantung pada penanda "removable" dari sistem dan
  folder simulasi mode pengembangan.

## Temuan di luar lingkup

- Baseline sebelum sesi ini: `1 failed, 689 passed`. Kegagalan
  `tests/test_n2b_matcher.py::test_endpoint_menjawab_topik_cocok`
  (`feature_help` bukan `topik`) sudah ada dan tidak berkaitan dengan UC1.
- Setelah perubahan: `1 failed, 721 passed`; satu-satunya kegagalan adalah
  baseline tersebut.
- Rute lama `/api/register_usb` tetap memakai `reregister_usb_token()` dan
  kini ikut memperoleh validasi mountpoint yang sama.

## Uji manual yang disarankan

1. Daftarkan wajah dengan mata terbuka; ulangi dengan mata tertutup dan
   pastikan pendaftaran ditolak.
2. Login dengan akun yang punya wajah dan WebAuthn; pastikan tahap 2
   menampilkan dua tombol dan salah satu saja sudah cukup.
3. Login dengan akun yang hanya punya satu metode; pastikan verifikasi
   berjalan otomatis.
4. Buka Settings dengan dua drive terpasang; pastikan pilihan dongle
   tampil. Daftarkan dongle baru, lalu login memakai dongle baru.
5. Cabut dongle baru dan colok dongle lama; pastikan login gagal.
