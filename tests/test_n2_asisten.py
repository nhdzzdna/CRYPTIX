"""
tests/test_n2_asisten.py
────────────────────────
Uji basis pengetahuan Security Assistant:

* jumlah topik dan kelengkapan bidang,
* setiap kata kunci/sinonim menemukan topiknya sendiri,
* pertanyaan cara pakai diarahkan ke panduan fitur yang benar,
* intent lain (status keamanan, password, enkripsi, log) tidak direbut,
* jawaban berasal dari ``MSG``.
"""

import pytest

from modules.assistant import knowledge
from modules.assistant.security_agent import classify_intent, process_message
from modules.strings import MSG


class TestStrukturBasisPengetahuan:
    def test_minimal_30_topik(self):
        assert len(knowledge.DAFTAR_TOPIK) >= 30

    def test_bidang_topik_lengkap(self):
        for topik in knowledge.DAFTAR_TOPIK:
            assert topik.id, "id topik kosong"
            assert topik.judul, f"judul kosong untuk {topik.id}"
            assert topik.kata_kunci, f"kata kunci kosong untuk {topik.id}"
            assert topik.sinonim, f"sinonim kosong untuk {topik.id}"
            assert topik.kunci_msg.startswith("ASSISTANT_KB_"), topik.id

            teks = getattr(MSG, topik.kunci_msg)
            assert isinstance(teks, str)
            assert len(teks) >= 80, f"jawaban terlalu pendek: {topik.id}"
            assert topik.jawaban == teks

    def test_id_dan_kunci_msg_unik(self):
        id_topik = [t.id for t in knowledge.DAFTAR_TOPIK]
        kunci_msg = [t.kunci_msg for t in knowledge.DAFTAR_TOPIK]
        assert len(id_topik) == len(set(id_topik))
        assert len(kunci_msg) == len(set(kunci_msg))

    def test_setiap_frasa_menemukan_topiknya(self):
        salah = []
        for topik in knowledge.DAFTAR_TOPIK:
            for frasa in topik.kata_kunci + topik.sinonim:
                hasil = knowledge.cari_topik(frasa)
                if hasil is None or hasil.id != topik.id:
                    salah.append((topik.id, frasa, hasil.id if hasil else None))
        assert salah == [], f"frasa ambigu/tidak cocok: {salah}"

    @pytest.mark.parametrize("pesan", [
        "", "   ", "akun", "file", "password", "media", "sesi",
        "blockchain", "token", "kredensial",
    ])
    def test_kata_umum_tidak_memicu_topik(self, pesan):
        assert knowledge.cari_topik(pesan) is None


class TestPertanyaanDikenali:
    @pytest.mark.parametrize("pesan, topik_id, cuplikan", [
        ("Bagaimana cara daftar akun?", "daftar_akun", "Dongle USB"),
        ("Bagaimana cara login dua tahap?", "login_dua_tahap", "Tahap 1"),
        ("Bagaimana cara mendaftarkan dongle?", "dongle_usb", "cryptix_token"),
        ("Apa yang harus dilakukan saat setup awal?", "setup_awal", "/setup"),
        ("Bagaimana cara mendaftarkan wajah?", "wajah", "FG1"),
        ("Bagaimana verifikasi wajah saat login?", "verifikasi_wajah", "5 frame"),
        ("Apa itu WebAuthn?", "webauthn", "Windows Hello"),
        ("Bagaimana cara menghapus biometrik?", "biometrik", "all_enrolled"),
        ("Apa itu kunci pemulihan?", "kunci_pemulihan", "satu kali"),
        ("Bagaimana cara memulihkan akun?", "pemulihan_akun", "Pulihkan Akun"),
        ("Bagaimana cara mengubah password?", "ganti_password", "Ganti Password"),
        ("Bagaimana cara menampilkan kredensial?", "reveal_akun", "120 detik"),
        ("Apa itu Account Vault?", "account_vault", "v1:"),
        ("Di mana melihat catatan aman?", "catatan_aman", "Secure Notes"),
        ("Bagaimana cara mengunggah berkas?", "unggah_berkas", "CRYPTIX1"),
        ("Bagaimana cara memutar media?", "media_vault", "HTTP Range"),
        ("Bagaimana cara menyembunyikan pesan di gambar?", "steganografi", "4000"),
        ("Bagaimana cara cek blockchain?", "verifikasi_integritas", "HMAC-SHA256"),
        ("Apa itu Security Center?", "security_center", "Verifikasi Integritas"),
        ("Di mana mengatur batas sesi?", "batas_sesi", "10 menit"),
        ("Mengapa akun saya terkunci?", "akun_terkunci", "60 detik"),
        ("Apa itu Super Encryption?", "super_encryption", "Vigenère"),
        ("Apa itu AES-256-GCM?", "aes_gcm", "CRYPTIX1"),
        ("Apakah database terenkripsi?", "enkripsi_database", "tidak dienkripsi seluruhnya"),
        ("Apa itu mode pengembangan?", "mode_pengembangan", "CRYPTIX_DEV_MODE"),
        ("Apa itu Crypto Tools?", "crypto_tools", "Playfair"),
        ("Apa itu Dashboard?", "dashboard", "Lima aktivitas"),
        ("Kapan autentikasi ulang diminta?", "reauth", "120 detik"),
        ("Apa itu token CSRF?", "csrf", "X-CSRFToken"),
        ("Berapa rate limit login?", "rate_limit", "15/menit"),
        ("Bagaimana cara logout?", "logout", "tombol POST"),
        ("Apa itu Security Assistant?", "assistant", "tanpa model bahasa"),
    ])
    def test_diarahkan_ke_panduan_fitur(self, pesan, topik_id, cuplikan):
        topik = knowledge.cari_topik(pesan)
        assert topik is not None
        assert topik.id == topik_id

        assert classify_intent(pesan) == "feature_help"
        hasil = process_message(pesan, user_id=1)
        assert hasil["intent"] == "feature_help"
        assert cuplikan in hasil["answer"]


class TestIntentLainTetapMenang:
    @pytest.mark.parametrize("pesan, harap", [
        ("Bagaimana status keamanan akun saya?", "security_status"),
        ("Apakah wajah saya terdaftar?", "security_status"),
        ("USB token sudah terpasang?", "security_status"),
        ("Cek password: Rahasia123!", "password_check"),
        ("Apakah password ini kuat?", "password_check"),
        ("Bagaimana cara enkripsi file PDF?", "encryption_advice"),
        ("Jelaskan log aktivitas saya.", "explain_log"),
        ("Apa resep nasi goreng?", "fallback"),
        ("Berapa harga bitcoin?", "fallback"),
    ])
    def test_urutan_intent_dipertahankan(self, pesan, harap):
        assert classify_intent(pesan) == harap
