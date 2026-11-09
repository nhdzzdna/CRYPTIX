# N2A - Basis pengetahuan terstruktur untuk Security Assistant

## Audit
- Struktur lama memakai dataclass dengan teks jawaban di `modules.strings.MSG`;
  struktur yang diminta adalah `TOPIK: list[dict]` dengan `jawaban` di dalamnya.
- Penyambungan lama di `security_agent.py` memanggil `cari_topik`, sehingga
  alias kompatibilitas tetap diperlukan agar tes lama tetap lulus.

## Perubahan
- `modules/assistant/knowledge.py`: `TOPIK` berisi 32 kamus dengan kunci tepat
  `id`, `judul`, `kata_kunci`, `sinonim`, dan `jawaban`.
- `id` memakai huruf kecil dan tanda hubung; `kata_kunci` huruf kecil tanpa
  tanda baca; setiap `jawaban` terdiri atas empat kalimat.
- Isi jawaban diverifikasi terhadap kode: batas sesi, penguncian akun, grant
  autentikasi ulang, format `CRYPTIX1`, `CXSE2`, `FG1`, serta enkripsi field
  database; fitur yang tidak ada tidak diklaim.
- Alias `DAFTAR_TOPIK` dan `cari_topik` dipertahankan; `security_agent.py`,
  rute, template, dan JavaScript tidak diubah.

## Hasil
- `tests/test_n2a_pengetahuan.py`: 10 tes untuk jumlah topik, kunci dan tipe,
  keunikan serta format `id`, isi `kata_kunci`, jumlah kalimat, dan istilah
  yang dilarang.
- Tes terarah 137 lulus; pytest penuh dijalankan sekali di akhir.
- Uji manual: tanyakan cara daftar akun, WebAuthn, kunci pemulihan, dan mode
  pengembangan; pastikan jawaban sesuai dan pertanyaan status tetap status.

## Di luar lingkup
- Penyambungan `TOPIK` ke `security_agent.py` dikerjakan terpisah.
- README menyebut autentikasi sidik jari, tetapi UI hanya wajah dan WebAuthn; tidak diubah.
