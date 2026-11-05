"""
tests/test_assistant.py
────────────────────────
Unit tests for the rule-based Security Assistant agent.

Tests cover:
  1. Intent classification for all 5 recognised categories
  2. Password strength checker (never stored)
  3. Fallback response for unrecognised input
  4. Password not stored in DB, log, or hash chain
  5. Answer content correctness for each intent
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from modules.assistant.security_agent import (
    classify_intent,
    check_password_strength,
    process_message,
    _handle_fallback,
    _handle_encryption_advice,
    _handle_password_check,
    THINKING_STEPS,
)


# ── 1. Intent classification ───────────────────────────────────────────────

class TestIntentClassification:
    """classify_intent() must map messages to the correct intent."""

    # ── security_status ───────────────────────────────────────────────────
    @pytest.mark.parametrize("msg", [
        "Bagaimana status keamanan akun saya?",
        "Apakah akunnya aman?",
        "Cek integritas blockchain",
        "USB token sudah terdaftar?",
        "Apakah biometrik saya aktif?",
        "status keamanan",
        "seberapa aman akun saya",
    ])
    def test_security_status(self, msg):
        assert classify_intent(msg) == "security_status"

    # ── encryption_advice ─────────────────────────────────────────────────
    @pytest.mark.parametrize("msg", [
        "Bagaimana cara enkripsi file PDF saya?",
        "Rekomendasi enkripsi untuk teks",
        "Encrypt gambar saya",
        "Bagaimana saya mengamankan kredensial?",
        "Algoritma mana yang terbaik untuk file?",
        "Lindungi data saya",
        "Sebaiknya enkripsi apa untuk catatan?",
    ])
    def test_encryption_advice(self, msg):
        assert classify_intent(msg) == "encryption_advice"

    # ── password_check ────────────────────────────────────────────────────
    @pytest.mark.parametrize("msg", [
        "Cek password: MyPass123!",
        "Periksa password: secretword",
        "Apakah password ini kuat?",
        "Password strength check",
        "seberapa kuat password ini",
        "cek password Abc123@xyz",
    ])
    def test_password_check(self, msg):
        assert classify_intent(msg) == "password_check"

    # ── explain_log ───────────────────────────────────────────────────────
    @pytest.mark.parametrize("msg", [
        "Jelaskan log aktivitas saya.",
        "Apa saja yang terjadi belakangan ini?",
        "Ringkas aktivitas terakhir",
        "Ceritakan log blockchain",
        "Riwayat aktivitas terbaru",
        "blok terakhir",
    ])
    def test_explain_log(self, msg):
        assert classify_intent(msg) == "explain_log"

    # ── feature_help ──────────────────────────────────────────────────────
    @pytest.mark.parametrize("msg", [
        "Cara pakai Steganografi?",
        "Bagaimana cara menggunakan My Vault?",
        "Apa itu Crypto Tools?",
        "Jelaskan fitur blockchain",
        "Cara memakai USB token",
        "Bagaimana cara kerja biometrik?",
        "Media vault itu apa?",
    ])
    def test_feature_help(self, msg):
        assert classify_intent(msg) == "feature_help"

    # ── fallback ──────────────────────────────────────────────────────────
    @pytest.mark.parametrize("msg", [
        "Apa resep nasi goreng?",
        "Berapa harga bitcoin?",
        "Siapa presiden Indonesia?",
        "hello",
        "xyz123",
        "",
    ])
    def test_fallback(self, msg):
        assert classify_intent(msg) == "fallback"


# ── 2. Password strength checker ──────────────────────────────────────────

class TestPasswordStrength:
    def test_weak_password_low_score(self):
        result = check_password_strength("abc")
        assert result["score"] < 40
        assert "Lemah" in result["level"]

    def test_strong_password_high_score(self):
        result = check_password_strength("Tr0ub4dor&3#Secure!")
        assert result["score"] >= 80
        assert "Kuat" in result["level"] or "Sangat" in result["level"]

    def test_common_pattern_penalised(self):
        result = check_password_strength("password123")
        assert result["score"] < 60
        assert any("pola umum" in s.lower() or "hindari" in s.lower()
                   for s in result["suggestions"])

    def test_suggestions_not_empty(self):
        result = check_password_strength("abc")
        assert len(result["suggestions"]) > 0

    def test_repeated_chars_penalised(self):
        result = check_password_strength("aaaa1234")
        assert any("pengulangan" in s.lower() for s in result["suggestions"])

    def test_missing_uppercase_suggests_fix(self):
        result = check_password_strength("lowercase123!")
        assert any("kapital" in s.lower() or "A–Z" in s for s in result["suggestions"])

    def test_missing_special_suggests_fix(self):
        result = check_password_strength("NoSpecialChar1")
        assert any("khusus" in s.lower() or "!@#" in s for s in result["suggestions"])

    def test_score_in_valid_range(self):
        for pw in ["a", "Abcdef12", "Tr0ub4dor&3#", "x" * 20]:
            r = check_password_strength(pw)
            assert 0 <= r["score"] <= 100

    def test_result_has_required_keys(self):
        r = check_password_strength("Test123!")
        assert "score"       in r
        assert "level"       in r
        assert "suggestions" in r


# ── 3. Handler output correctness ─────────────────────────────────────────

class TestHandlerOutputs:
    def test_fallback_lists_capabilities(self):
        answer = _handle_fallback()
        assert "keamanan" in answer.lower()
        assert "enkripsi" in answer.lower()
        assert "password" in answer.lower()
        assert "log" in answer.lower()

    def test_encryption_advice_file(self):
        answer = _handle_encryption_advice("Bagaimana cara enkripsi file PDF?")
        assert "AES-256-GCM" in answer

    def test_encryption_advice_text(self):
        answer = _handle_encryption_advice("Bagaimana cara enkripsi teks?")
        assert "Super Encryption" in answer

    def test_encryption_advice_image_stego(self):
        answer = _handle_encryption_advice("Sembunyikan pesan di gambar")
        assert "LSB" in answer or "Steganografi" in answer

    def test_encryption_advice_credentials(self):
        answer = _handle_encryption_advice("Amankan kredensial dan password akun")
        assert "Account Vault" in answer

    def test_encryption_advice_generic(self):
        # No specific data type mentioned → generic advice returned
        answer = _handle_encryption_advice("Bagaimana cara enkripsi data?")
        assert "AES-256-GCM" in answer or "Super Encryption" in answer

    def test_password_check_no_password_returns_prompt(self):
        answer = _handle_password_check("cek kekuatan password saya")
        assert "cek password:" in answer.lower() or "ketik" in answer.lower()

    def test_password_check_extracts_password(self):
        answer = _handle_password_check("cek password: Abc123!")
        assert "Skor" in answer or "Level" in answer or "karakter" in answer

    def test_thinking_steps_are_three(self):
        assert len(THINKING_STEPS) == 3

    def test_thinking_steps_content(self):
        assert any("memahami" in s.lower() for s in THINKING_STEPS)
        assert any("membaca" in s.lower()  for s in THINKING_STEPS)
        assert any("menyusun" in s.lower() for s in THINKING_STEPS)


# ── 4. Security: password not persisted ───────────────────────────────────

class TestPasswordNotPersisted:
    """
    Verify that process_message() with a password_check intent does NOT
    write the password to the database, session, or any log.
    """

    def test_password_not_stored_in_db(self, tmp_path):
        """Run password check and verify nothing is written to DB."""
        import sqlite3
        import config

        original_db_path = config.DATABASE_PATH
        test_db = str(tmp_path / "security_test.db")
        config.DATABASE_PATH = test_db

        from database.db import init_db
        init_db()

        try:
            # Call agent with a password
            secret_pw = "MyVerySecretP@ssw0rd_12345"
            result = process_message(f"cek password: {secret_pw}", user_id=1)
            assert result["intent"] == "password_check"

            # Check that the password literal does not appear in any DB table
            conn = sqlite3.connect(test_db)
            # Check blockchain_log
            rows = conn.execute("SELECT * FROM blockchain_log").fetchall()
            all_text = " ".join(str(r) for r in rows)
            assert secret_pw not in all_text, (
                "Password found in blockchain_log!"
            )
            # Check users table (should be empty for user_id=1 in fresh DB)
            rows = conn.execute("SELECT * FROM users").fetchall()
            all_text = " ".join(str(r) for r in rows)
            assert secret_pw not in all_text
            conn.close()
        finally:
            config.DATABASE_PATH = original_db_path

    def test_password_not_in_agent_answer(self):
        """The agent answer should NOT echo the full password back."""
        secret_pw = "SuperSecretPassword99!"
        answer_data = _handle_password_check(f"cek password: {secret_pw}")
        # The raw password should not be in the output
        assert secret_pw not in answer_data

    def test_password_check_answer_mentions_memory_only(self):
        """Answer must include a disclaimer that password is only in memory."""
        answer = _handle_password_check("cek password: TestPassword1!")
        assert "memori" in answer.lower()


# ── 5. process_message integration ────────────────────────────────────────

class TestProcessMessageIntegration:
    """Integration tests for process_message() using a temp DB."""

    @pytest.fixture(autouse=True)
    def temp_db(self, tmp_path):
        import config
        self._orig = config.DATABASE_PATH
        config.DATABASE_PATH = str(tmp_path / "pm_test.db")
        from database.db import init_db
        init_db()
        yield
        config.DATABASE_PATH = self._orig

    def test_returns_dict_with_required_keys(self):
        result = process_message("hello", user_id=1)
        assert "intent"         in result
        assert "thinking_steps" in result
        assert "answer"         in result

    def test_fallback_intent_for_unknown_message(self):
        result = process_message("Apa itu pizza?", user_id=1)
        assert result["intent"] == "fallback"
        assert len(result["answer"]) > 0

    def test_security_status_reads_metadata(self):
        result = process_message("Status keamanan akun saya?", user_id=1)
        assert result["intent"] == "security_status"
        assert "Blockchain" in result["answer"] or "keamanan" in result["answer"].lower()

    def test_explain_log_empty_chain(self):
        result = process_message("Jelaskan log aktivitas saya.", user_id=1)
        assert result["intent"] == "explain_log"
        # With an empty chain, the answer should mention no activity yet
        assert "belum" in result["answer"].lower() or "kosong" in result["answer"].lower() \
               or "aktivitas" in result["answer"].lower()

    def test_thinking_steps_always_three(self):
        result = process_message("Cara pakai vault?", user_id=1)
        assert len(result["thinking_steps"]) == 3
