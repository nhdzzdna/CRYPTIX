"""
modules/assistant/security_agent.py
─────────────────────────────────────
Rule-based Security Assistant Agent for CRYPTIX.

This is a pure rule-based agent — no LLM, no external API, no network calls.
All reasoning is done via keyword matching and regex patterns over application
metadata.

Recognised intent categories
─────────────────────────────
  1. security_status   — status keamanan akun (blockchain, USB, biometrik)
  2. encryption_advice — rekomendasi enkripsi berdasarkan jenis data
  3. password_check    — cek kekuatan password (tidak disimpan ke mana pun)
  4. explain_log       — ringkasan 5 blok terakhir blockchain dalam bahasa natural
  5. feature_help      — cara menggunakan fitur/menu tertentu
  6. fallback          — pertanyaan tidak dikenali

Security constraints
──────────────────────
  • Agent HANYA membaca metadata (jumlah, status, tipe aksi log, jangkar kepala).
  • Agent TIDAK membaca / menampilkan isi file terenkripsi, kunci, atau password.
  • Password yang diperiksa hanya hidup di memori; tidak disimpan ke DB, log,
    riwayat percakapan, atau hash chain.
"""

from __future__ import annotations

import re
from typing import Any


# ── Thinking steps (shown incrementally in the UI) ───────────────────────────

THINKING_STEPS: list[str] = [
    "Memahami pertanyaan…",
    "Membaca data aplikasi…",
    "Menyusun jawaban…",
]


# ── Intent patterns ───────────────────────────────────────────────────────────

_SECURITY_STATUS_PATTERNS = re.compile(
    r"(status\s*keamanan|keamanan\s*akun|\baman(kah)?(\s+akun|\s+saya)?\b|"
    r"blockchain.*(?:ok|baik|valid|rusak)|"
    r"integritas(?!\s*fitur)|"
    r"usb\s*(token\s*)?(sudah|belum|aktif|status)|"
    r"biometrik.*aktif|biometrik.*terdaftar|biometrik.*status|"
    r"wajah.*(?:terdaftar|aktif|status)|"
    r"security\s*status|seberapa\s*aman)",
    re.I,
)

_ENCRYPTION_ADVICE_PATTERNS = re.compile(
    r"(enkripsi\s*(apa|yang|terbaik|rekomendasi|saran)|rekomendasi\s*enkripsi|"
    r"bagaimana\s*(cara\s*)?enkripsi|sebaiknya\s*(enkripsi|pakai)|"
    r"encrypt\s*(file|teks|text|gambar|image|foto|kredensial|password|akun)|"
    r"lindungi\s*(file|data|teks|gambar|foto|kredensial)|"
    r"amankan\s*(file|data|teks|gambar|foto)|"
    r"mengamankan\s*(file|data|teks|gambar|foto|kredensial|akun)|"
    r"cipher\s*(mana|apa|yang)|algoritma\s*(mana|apa|yang))",
    re.I,
)

_PASSWORD_CHECK_PATTERNS = re.compile(
    r"(cek\s*password|periksa\s*password|"
    r"(kuat|lemah|aman|bagus|buruk|baik)(kah)?\s*password|"
    r"password\s*(kuat|lemah|aman|bagus|buruk|baik)|"
    r"check\s*password|password\s*strength|seberapa\s*(kuat|aman)\s*password|"
    r"apakah\s*password\s*(ini|itu|saya)\s*(kuat|aman|bagus)|"
    r"password\s*(ini|itu|saya)\s*(kuat|aman|bagus))",
    re.I,
)

# Extract the actual password value from the message — requires colon separator
_PASSWORD_EXTRACT = re.compile(
    r"""(?:password\s*:\s*|kata\s*sandi\s*:\s*|pw\s*:\s*)(['"]?)(\S+)\1""",
    re.I,
)

_EXPLAIN_LOG_PATTERNS = re.compile(
    r"(log\s*aktivitas|aktivitas\s*terakhir|riwayat|history|blockchain.*log|"
    r"blok\s*terakhir|apa\s*(saja\s*)?yang\s*(terjadi|dilakukan)|"
    r"jelaskan\s*log|ringkas.*aktivitas|ceritakan.*log)",
    re.I,
)

_FEATURE_MENU_NAMES = (
    r"vault|steganografi|blockchain|crypto\s*tools|"
    r"secure\s*notes|media\s*vault|account\s*vault|security\s*center|"
    r"dashboard|winamp|lsb|fitur\s*ini"
)

_FEATURE_HELP_PATTERNS = re.compile(
    r"(cara\s*(pakai|memakai|menggunakan|membuka|mengakses|kerja)|"
    r"bagaimana\s*cara\s*(pakai|memakai|menggunakan|membuka|mengakses|kerja)|"
    r"how\s*to|petunjuk|tutorial|panduan|"
    r"apa\s*(fungsi\s*(dari|fitur|menu)|itu\s*(fitur|menu|aplikasi)|kegunaan)|"
    r"jelaskan\s*(fitur|menu|cara\s+(pakai|memakai|kerja))|"
    r"apa\s*itu\s*(" + _FEATURE_MENU_NAMES + r")|"
    r"(" + _FEATURE_MENU_NAMES + r")\s*(itu|adalah|cara|fungsi|apa|bagaimana|digunakan))",
    re.I,
)


# ── Feature help knowledge base ───────────────────────────────────────────────

_FEATURE_KB: dict[str, str] = {
    "vault|my vault": (
        "**My Vault** adalah tempat menyimpan semua jenis file secara terenkripsi.\n"
        "• Upload file → file dienkripsi dengan **AES-256-GCM** sebelum disimpan.\n"
        "• Download/Dekripsi → file didekripsi ke browser Anda, tag GCM diverifikasi "
        "terlebih dahulu (tamper-proof).\n"
        "• Setiap upload dan dekripsi dicatat di **Blockchain Log**."
    ),
    "account vault|kredensial": (
        "**Account Vault** menyimpan username, password, dan URL situs secara terenkripsi.\n"
        "• Setiap field dienkripsi **AES-256-GCM** dengan kunci turunan HKDF yang "
        "terpisah dari kunci file.\n"
        "• Data sensitif **tidak pernah tersimpan sebagai plaintext** di database.\n"
        "• Gunakan ikon mata (👁) untuk menampilkan password sementara."
    ),
    "secure notes|catatan": (
        "**Secure Notes** menyimpan catatan teks rahasia.\n"
        "• Judul dan isi dienkripsi **AES-256-GCM** sebelum masuk database.\n"
        "• Anda bisa mengedit dan menghapus catatan kapan saja.\n"
        "• Kunci enkripsi berasal dari sesi login Anda, tidak tersimpan di disk."
    ),
    "crypto tools|cipher": (
        "**Crypto Tools** memungkinkan Anda menguji setiap algoritma secara mandiri:\n"
        "• **Vigenere** — cipher substitusi klasik, kunci berupa teks.\n"
        "• **Playfair** — cipher digram 5×5, hanya huruf A–Z.\n"
        "• **ChaCha20** — stream cipher modern, nonce acak per operasi.\n"
        "• **Blowfish-CBC** — block cipher dengan padding PKCS#7.\n"
        "• **Super Encryption** — pipeline Vigenere→Playfair→ChaCha20→Blowfish-CBC "
        "yang diakhiri HMAC-SHA256 untuk mendeteksi perubahan."
    ),
    "steganografi|steganography|lsb": (
        "**Steganografi LSB** menyembunyikan pesan di dalam gambar PNG.\n"
        "• Upload gambar carrier (PNG/JPG/BMP) + tulis pesan → klik **Sisipkan**.\n"
        "• Opsi enkripsi: pesan bisa di-Super-Encrypt sebelum disisipkan.\n"
        "• Untuk mengekstrak: klik **Ekstrak** pada gambar yang tersimpan.\n"
        "• Kapasitas ≈ (lebar × tinggi × 3 − 32) / 8 byte."
    ),
    "blockchain|security center|integritas": (
        "**Security Center** menampilkan log audit berbasis blockchain.\n"
        "• Setiap aksi (upload, dekripsi, hapus, login) dicatat sebagai **blok** "
        "dengan tautan SHA-256, tanda tangan HMAC, dan proof-of-work ringan.\n"
        "• Jangkar kepala (head hash) disimpan terpisah sebagai pembanding.\n"
        "• Klik **Verifikasi Integritas** untuk memeriksa seluruh rantai dan status "
        "tiap aset (OK/DIUBAH/HILANG/TANPA CATATAN).\n"
        "• Blok yang dimanipulasi akan ditandai ⚠ RUSAK."
    ),
    "usb|token|dongle": (
        "**USB Token** adalah lapisan autentikasi tambahan.\n"
        "• Daftarkan/daftar ulang flashdisk di **Settings → Dongle**.\n"
        "• HMAC-SHA256 ditandatangani dan ditulis ke file `.cryptix_token` di flashdisk.\n"
        "• Token terikat pada serial number volume drive.\n"
        "• Status dongle terpasang/tidak tampil di Dashboard dan Settings."
    ),
    "biometrik|wajah|face|sidik jari|fingerprint": (
        "**Biometrik** di CRYPTIX:\n"
        "• **WebAuthn** — kredensial platform (Windows Hello, sidik jari perangkat, "
        "atau kunci keamanan) dengan user verification wajib.\n"
        "• **Face Recognition** — model LBPH dilatih dari sampel webcam dan "
        "template-nya disimpan terenkripsi. Verifikasi saat login via kamera.\n"
        "• Daftar/perbarui biometrik di **Settings → Biometrik**."
    ),
    "media vault|audio|winamp": (
        "**Media Vault** menyimpan file audio/video secara terenkripsi.\n"
        "• File dienkripsi **AES-256-GCM** per potongan (chunk) dengan salt acak "
        "per berkas dan nonce counter per chunk.\n"
        "• Tombol ▶ Play mendekripsi sementara dan memutar via HTML5.\n"
        "• Jika Winamp terinstal (path dikonfigurasi di `config.py`), gunakan "
        "tombol 🎵 Winamp — file sementara dihapus otomatis setelah 60 detik."
    ),
    "dashboard": (
        "**Dashboard** menampilkan ringkasan keamanan Anda:\n"
        "• Total file, kredensial, catatan, dan stego image tersimpan.\n"
        "• Kapasitas penyimpanan terpakai (encrypted files).\n"
        "• Status dongle (terpasang/tidak) dan metode biometrik terdaftar "
        "(WebAuthn + wajah).\n"
        "• Hasil verifikasi rantai terakhir beserta jangkar kepala (head hash).\n"
        "• 5 aktivitas terbaru milik Anda dari audit log."
    ),
}


# ── Password strength checker ─────────────────────────────────────────────────

_COMMON_PATTERNS = re.compile(
    r"(12345|password|qwerty|abc123|111111|letmein|admin|iloveyou|welcome|monkey)",
    re.I,
)


def check_password_strength(password: str) -> dict:
    """
    Evaluate password strength entirely in memory.

    Parameters
    ----------
    password : str  The password to evaluate. NEVER stored anywhere.

    Returns
    -------
    dict with keys: score (0-100), level (str), suggestions (list[str]).
    """
    score = 0
    suggestions: list[str] = []

    length = len(password)

    # Length scoring
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        score += 0
        suggestions.append("Panjang password minimal 12 karakter sangat disarankan.")

    # Character variety
    has_lower   = bool(re.search(r"[a-z]", password))
    has_upper   = bool(re.search(r"[A-Z]", password))
    has_digit   = bool(re.search(r"\d",    password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety = sum([has_lower, has_upper, has_digit, has_special])
    score += variety * 15

    if not has_lower:
        suggestions.append("Tambahkan huruf kecil (a–z).")
    if not has_upper:
        suggestions.append("Tambahkan huruf kapital (A–Z).")
    if not has_digit:
        suggestions.append("Tambahkan angka (0–9).")
    if not has_special:
        suggestions.append("Tambahkan karakter khusus (!@#$%^&*…).")

    # Common patterns penalty
    if _COMMON_PATTERNS.search(password):
        score = max(0, score - 30)
        suggestions.append("Hindari pola umum seperti '12345', 'password', atau 'qwerty'.")

    # Repeated characters penalty
    if re.search(r"(.)\1{3,}", password):
        score = max(0, score - 10)
        suggestions.append("Hindari pengulangan karakter yang sama secara berurutan.")

    # Clamp
    score = min(100, max(0, score))

    if score >= 80:
        level = "Sangat Kuat 🟢"
    elif score >= 60:
        level = "Kuat 🟡"
    elif score >= 40:
        level = "Sedang 🟠"
    else:
        level = "Lemah 🔴"

    if not suggestions:
        suggestions.append("Password sudah terlihat baik! Pastikan Anda tidak menggunakannya di tempat lain.")

    return {"score": score, "level": level, "suggestions": suggestions}


# ── Context data readers ──────────────────────────────────────────────────────

def _read_security_metadata(user_id: int) -> dict:
    """
    Read ONLY metadata counts and statuses from the database.
    No file content, no keys, no passwords are read.
    """
    from database.db import get_db
    from modules.authentication import biometrics, usb_authentication
    from modules.authentication.face_recognition import template_ada
    from modules.authentication.webauthn import kredensial_pengguna
    from modules.blockchain.blockchain import (
        get_head_info,
        get_last_verification,
        verify_chain,
    )

    with get_db() as db:
        user_row = db.execute(
            "SELECT usb_token_id FROM users WHERE id=?", (user_id,)
        ).fetchone()

        file_count = db.execute(
            "SELECT COUNT(*) FROM vault_files WHERE user_id=?", (user_id,)
        ).fetchone()[0]

        note_count = db.execute(
            "SELECT COUNT(*) FROM secure_notes WHERE user_id=?", (user_id,)
        ).fetchone()[0]

        account_count = db.execute(
            "SELECT COUNT(*) FROM account_vault WHERE user_id=?", (user_id,)
        ).fetchone()[0]

    chain = verify_chain()
    tampered = sum(1 for b in chain if b.get("tampered"))

    return {
        "file_count":       file_count,
        "note_count":       note_count,
        "account_count":    account_count,
        "total_blocks":     len(chain),
        "tampered_blocks":  tampered,
        "has_usb":          bool(user_row["usb_token_id"]) if user_row else False,
        "dongle_attached":  usb_authentication.dongle_pengguna_terpasang(user_id),
        "biometric_methods": biometrics.metode_biometrik_terdaftar(user_id),
        "webauthn_count":   len(kredensial_pengguna(user_id)),
        "has_face":         template_ada(user_id),
        "head":             get_head_info(),
        "last_verification": get_last_verification(user_id),
    }


def _read_recent_log(user_id: int, limit: int = 5) -> list[dict]:
    """Return the most recent *limit* blockchain blocks for *user_id*."""
    from database.db import get_db
    with get_db() as db:
        rows = db.execute(
            "SELECT block_index, timestamp, action, asset_hash FROM blockchain_log "
            "WHERE user_id=? ORDER BY block_index DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# ── Intent handlers ───────────────────────────────────────────────────────────

def _handle_security_status(user_id: int) -> str:
    meta = _read_security_metadata(user_id)

    lines = ["## 🛡 Status Keamanan Akun\n"]

    # Blockchain
    if meta["tampered_blocks"] == 0:
        lines.append(
            f"✅ **Blockchain Log** — {meta['total_blocks']} blok, semua valid (tidak ada manipulasi)."
        )
    else:
        lines.append(
            f"⚠️ **Blockchain Log** — {meta['total_blocks']} blok, "
            f"**{meta['tampered_blocks']} blok terdeteksi rusak!** "
            f"Segera periksa Security Center."
        )

    # Chain head anchor
    head = meta["head"]
    if head:
        lines.append(
            f"⛓ **Jangkar kepala** — blok #{head.get('block_index')} · "
            f"`{head.get('head_hash', '')[:16]}…` (SHA-256 + HMAC + PoW)"
        )
    else:
        lines.append("⛓ **Jangkar kepala** — belum tersedia.")

    # Last verification (bila pernah dijalankan)
    verifikasi = meta["last_verification"]
    if verifikasi:
        waktu = verifikasi["timestamp"][:19].replace("T", " ")
        keadaan = "utuh" if verifikasi["valid"] else (
            f"{verifikasi['tampered_blocks']} blok rusak"
        )
        lines.append(
            f"🔎 **Verifikasi terakhir** — {waktu} UTC · {keadaan}."
        )

    # Data counts
    lines.append(
        f"📁 **File tersimpan**: {meta['file_count']} (terenkripsi AES-256-GCM)"
    )
    lines.append(
        f"📝 **Catatan aman**: {meta['note_count']} | "
        f"🔑 **Kredensial**: {meta['account_count']}"
    )

    # USB / dongle
    if meta["has_usb"]:
        usb_status = (
            "✅ Terdaftar dan terpasang"
            if meta["dongle_attached"]
            else "⚠️ Terdaftar, tetapi tidak terpasang"
        )
    else:
        usb_status = "⚠️ Belum terdaftar"
    lines.append(f"🔌 **Dongle/USB Token**: {usb_status}")
    if not meta["has_usb"]:
        lines.append(
            "  → Daftarkan dongle di **Settings → Dongle** untuk keamanan ekstra."
        )

    # Biometrics: registry riil (WebAuthn + wajah)
    label_metode = {"webauthn": "WebAuthn", "wajah": "Wajah"}
    metode = [
        label_metode.get(nama, nama) for nama in meta["biometric_methods"]
    ]
    lines.append(
        "🧬 **Biometrik terdaftar**: "
        + (", ".join(metode) if metode else "belum ada")
    )
    lines.append(
        f"🔏 **WebAuthn**: {meta['webauthn_count']} kredensial  |  "
        f"👤 **Wajah**: {'✅ terdaftar' if meta['has_face'] else '⚠️ belum terdaftar'}"
    )

    # Overall assessment
    strong_count = sum([meta["has_usb"], bool(meta["biometric_methods"])])
    if meta["tampered_blocks"] > 0:
        lines.append(
            "\n🔴 **Kesimpulan**: Ada masalah integritas! Periksa Security Center segera."
        )
    elif strong_count >= 2:
        lines.append(
            "\n🟢 **Kesimpulan**: Akun Anda terlindungi dengan baik (multi-faktor aktif)."
        )
    elif strong_count == 1:
        lines.append(
            "\n🟡 **Kesimpulan**: Keamanan cukup, tapi pertimbangkan menambah "
            "lapisan autentikasi."
        )
    else:
        lines.append(
            "\n🟠 **Kesimpulan**: Hanya password yang aktif. Sangat disarankan "
            "mendaftarkan dongle dan biometrik."
        )

    return "\n".join(lines)


def _handle_encryption_advice(message: str) -> str:
    msg_lower = message.lower()

    recommendations: list[str] = []

    if re.search(r"file|dokumen|pdf|foto\b|gambar\b|video|audio|media", msg_lower):
        recommendations.append(
            "**📁 File / Dokumen / Gambar / Media**\n"
            "→ Gunakan **AES-256-GCM** (My Vault / Documents / Media Vault)\n"
            "  • Alasan: enkripsi authenticated — tag GCM mendeteksi tampering.\n"
            "  • Format CRYPTIX1: salt acak 16-byte per berkas dan nonce counter "
            "per potongan (chunk); kunci diturunkan HKDF dari sesi."
        )

    if re.search(r"teks|text|pesan|message|catatan|note|tulisan", msg_lower):
        recommendations.append(
            "**📝 Teks / Pesan / Catatan**\n"
            "→ Gunakan **Super Encryption** (Crypto Tools) atau **Secure Notes**\n"
            "  • Super Encryption: 4 layer (Vigenere→Playfair→ChaCha20→Blowfish-CBC).\n"
            "  • Secure Notes: teks langsung terenkripsi AES-256-GCM di database."
        )

    if re.search(r"gambar\b|image|foto\b|png|jpg|sembunyi|rahasia.*gambar|gambar.*rahasia", msg_lower):
        recommendations.append(
            "**🖼 Menyembunyikan Pesan di Gambar**\n"
            "→ Gunakan **Steganografi LSB** (menu Steganography)\n"
            "  • Pesan disisipkan di bit paling rendah tiap channel RGB.\n"
            "  • Aktifkan opsi 'Enkripsi dengan Super Encryption' untuk lapisan ganda."
        )

    if re.search(r"kredensial|akun|username|password|login|sandi|situs|website", msg_lower):
        recommendations.append(
            "**🔑 Kredensial / Password Akun**\n"
            "→ Gunakan **Account Vault**\n"
            "  • Setiap field (username, password, URL) dienkripsi AES-256-GCM.\n"
            "  • Kunci DB terpisah dari kunci file (HKDF label berbeda).\n"
            "  • Tidak ada plaintext yang tersimpan di database."
        )

    if not recommendations:
        # Generic advice
        recommendations = [
            "Berikut rekomendasi enkripsi berdasarkan jenis data:\n",
            "**📁 File** → AES-256-GCM (My Vault)",
            "**📝 Teks** → Super Encryption (Crypto Tools) atau Secure Notes",
            "**🖼 Gambar** → Steganografi LSB (Steganography)",
            "**🔑 Kredensial** → Account Vault (AES-256-GCM per-field)",
        ]

    header = "## 🔐 Rekomendasi Enkripsi\n"
    return header + "\n\n".join(recommendations)


def _handle_password_check(message: str) -> str:
    """
    Check password strength. Password is ONLY processed in memory —
    never stored in DB, log, session, or hash chain.
    """
    # Try to extract password from message
    m = _PASSWORD_EXTRACT.search(message)
    if not m:
        return (
            "## 🔐 Cek Kekuatan Password\n\n"
            "Isi kolom **Password** di bawah chat lalu klik **Cek Password**.\n"
            "Kolom itu terpisah dari pesan sehingga password tidak masuk riwayat "
            "percakapan.\n\n"
            "Lewat pesan teks: `cek password: NamaPassword123!`\n\n"
            "⚠️ **Catatan keamanan**: Password yang Anda kirim **tidak disimpan** "
            "di database, log, riwayat, maupun hash chain. Hanya diproses di memori."
        )

    password = m.group(2)

    # SECURITY: process entirely in memory, do not store
    result = check_password_strength(password)

    # Mask password in output: show only length and character types
    length = len(password)
    lines = [
        f"## 🔐 Hasil Cek Kekuatan Password\n",
        f"**Panjang**: {length} karakter  |  **Skor**: {result['score']}/100  |  "
        f"**Level**: {result['level']}\n",
        "**Saran perbaikan:**",
    ]
    for s in result["suggestions"]:
        lines.append(f"• {s}")

    lines.append(
        "\n⚠️ *Password hanya diproses di memori — tidak disimpan di mana pun.*"
    )
    return "\n".join(lines)


def _humanize_action(action: str) -> str:
    return {
        "UPLOAD":   "mengunggah file",
        "DECRYPT":  "mendekripsi file",
        "MODIFY":   "mengubah catatan",
        "DELETE":   "menghapus item",
        "LOGIN":    "login ke aplikasi",
        "REGISTER": "mendaftarkan akun",
    }.get(action.upper(), action)


def _handle_explain_log(user_id: int) -> str:
    blocks = _read_recent_log(user_id, limit=5)

    if not blocks:
        return (
            "## 📋 Log Aktivitas Terbaru\n\n"
            "Belum ada aktivitas yang tercatat di blockchain log.\n"
            "Aktivitas akan muncul setelah Anda upload, dekripsi, atau hapus file."
        )

    lines = ["## 📋 Log Aktivitas Terbaru (5 Terakhir)\n"]
    for i, blk in enumerate(blocks, 1):
        ts  = blk["timestamp"][:19].replace("T", " ")
        act = _humanize_action(blk["action"])
        # Show only first 8 chars of asset hash (enough to identify, not enough to leak)
        ah  = blk["asset_hash"][:8] + "…"
        lines.append(f"**{i}.** `{ts}` — Anda **{act}** _(ref: {ah})_")

    lines.append(
        "\n💡 Untuk verifikasi integritas seluruh rantai, kunjungi **Security Center** "
        "dan klik tombol **Verifikasi Integritas**."
    )
    return "\n".join(lines)


def _handle_feature_help(message: str) -> str:
    msg_lower = message.lower()
    for keywords, explanation in _FEATURE_KB.items():
        for kw in keywords.split("|"):
            if kw.strip() in msg_lower:
                return f"## ℹ️ Panduan Fitur\n\n{explanation}"
    # Generic help list
    return (
        "## ℹ️ Panduan Fitur\n\n"
        "Saya bisa menjelaskan cara menggunakan fitur berikut:\n\n"
        + "\n".join(f"• {k.split('|')[0].title()}" for k in _FEATURE_KB)
        + "\n\nCoba tanyakan, misalnya: *\"Bagaimana cara pakai Steganografi?\"*"
    )


def _handle_fallback() -> str:
    return (
        "## 🤖 Security Assistant\n\n"
        "Maaf, saya tidak mengenali pertanyaan tersebut.\n\n"
        "Saya dapat membantu Anda dengan:\n\n"
        "1. 🛡 **Status keamanan** — *\"Bagaimana status keamanan akun saya?\"*\n"
        "2. 🔐 **Rekomendasi enkripsi** — *\"Bagaimana cara enkripsi file PDF?\"*\n"
        "3. 🔑 **Cek kekuatan password** — *\"Cek password: Contoh123!\"*\n"
        "4. 📋 **Ringkasan log aktivitas** — *\"Jelaskan log aktivitas saya.\"*\n"
        "5. ℹ️ **Panduan fitur** — *\"Cara pakai Steganografi?\"*\n"
    )


# ── Main agent entry point ────────────────────────────────────────────────────

def classify_intent(message: str) -> str:
    """
    Classify a user message into one of the five intent categories.

    Check order (most-specific first to avoid false matches):
      1. password_check — checked before security_status to avoid "password aman?" → status
      2. feature_help   — checked before security_status to avoid "cara pakai USB" → status
      3. security_status
      4. encryption_advice
      5. explain_log
      6. fallback

    Parameters
    ----------
    message : str  Raw user message.

    Returns
    -------
    str  One of: 'security_status', 'encryption_advice', 'password_check',
                 'explain_log', 'feature_help', 'fallback'.
    """
    if _PASSWORD_CHECK_PATTERNS.search(message):
        return "password_check"
    if _FEATURE_HELP_PATTERNS.search(message):
        return "feature_help"
    if _SECURITY_STATUS_PATTERNS.search(message):
        return "security_status"
    if _ENCRYPTION_ADVICE_PATTERNS.search(message):
        return "encryption_advice"
    if _EXPLAIN_LOG_PATTERNS.search(message):
        return "explain_log"
    return "fallback"


def process_message(message: str, user_id: int) -> dict:
    """
    Process a user message and return the agent's response.

    Parameters
    ----------
    message : str  The user's input text.
    user_id : int  The authenticated user's ID (for data-reading intents).

    Returns
    -------
    dict with keys:
      ``intent``        str   — classified intent
      ``thinking_steps`` list[str] — steps shown before the answer
      ``answer``        str   — markdown-formatted response
    """
    intent = classify_intent(message)

    if intent == "security_status":
        answer = _handle_security_status(user_id)
    elif intent == "encryption_advice":
        answer = _handle_encryption_advice(message)
    elif intent == "password_check":
        answer = _handle_password_check(message)
    elif intent == "explain_log":
        answer = _handle_explain_log(user_id)
    elif intent == "feature_help":
        answer = _handle_feature_help(message)
    else:
        answer = _handle_fallback()

    return {
        "intent":        intent,
        "thinking_steps": THINKING_STEPS,
        "answer":        answer,
    }
