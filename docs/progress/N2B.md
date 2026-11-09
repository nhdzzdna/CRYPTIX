# N2B — Pencocokan pertanyaan dan saran Security Assistant

- Cabang: `n2b-matcher`.
- Audit intent lama: `security_status`, `encryption_advice`, `password_check`, `explain_log`, `feature_help`, `fallback` (aturan kata kunci/regex, tanpa model bahasa).
- Urutan `classify_intent`: password_check → feature_help → security_status → encryption_advice → explain_log → fallback.
- Bentuk JSON `/assistant/chat` sebelum perubahan: `{thinking_steps, answer, intent}`; sekarang dapat menambah `saran` berisi `[{id, judul}]`.
- Riwayat: `modules.assistant.history` di memori proses per `session_id` server; entri `{role, content, intent}`; password hanya dicatat `[password diperiksa]`.
- `modules/assistant/knowledge.py` tidak dibuat/diubah; pemuatan ditunda dan dilindungi. Bila tidak ada/`TOPIK` kosong, asisten memakai fallback lama.
- `matcher.py` baru: `normalisasi` (huruf kecil, buang tanda baca/kata hubung, batas 500 karakter), `muat_topik`, `cari_topik` (frasa sinonim > kata kunci > judul, toleransi salah ketik `SequenceMatcher` ≥ 0,85, ambang 0,40).
- `security_agent.py`: intent lama tetap didahulukan; bila fallback, `cari_topik` dijalankan. Cocok → jawaban topik (`intent="topik"`); tidak cocok → pesan jujur + tiga saran; tanpa topik → fallback lama.
- `strings.py`: tambah `ASSISTANT_TOPIC_FALLBACK` dan `ASSISTANT_TOPIC_SUGGESTIONS`.
- `assistant_routes.py`: mengirim `topik` ke template dan kunci opsional `saran` pada JSON.
- `assistant.html`: tombol saran awal dirender server dari judul topik (maksimal 6, `data-pertanyaan`); kosong bila `TOPIK` kosong.
- `assistant.js`: klik saran mengisi dan mengirim pertanyaan lewat `apiFetch`; saran balasan dirender dengan `textContent`; tanpa JavaScript inline.
- `style.css`: tambah gaya `.msg-suggestions` di akhir berkas.
- Tes baru `tests/test_n2b_matcher.py`: normalisasi, frasa sinonim, kata kunci, salah ketik, ambang/saran, batas masukan, endpoint cocok/tidak cocok, tombol server, password tidak masuk riwayat, tanpa JS inline, integrasi knowledge asli (dilewati bila belum ada).
- Hasil terarah: 94 passed, 1 skipped (knowledge.py belum ada).
- pytest penuh: 595 passed, 1 skipped (273,77 detik); tidak ada tes lama yang dihapus/dilemahkan.
- Belum diuji otomatis: interaksi klik di peramban dan animasi.
- Uji manual: 1) buka `/assistant`, pastikan tombol saran awal muncul dari judul topik; 2) klik tombol, pastikan pertanyaan terisi dan terkirim; 3) ajukan pertanyaan yang cocok, pastikan jawaban topik tampil; 4) ajukan pertanyaan acak, pastikan pesan jujur dan tiga tombol saran muncul; 5) klik saran balasan; 6) isi kolom password lalu klik saran, pastikan pertanyaan tetap terkirim dan riwayat hanya memuat penanda password.
