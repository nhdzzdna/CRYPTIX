"""
modules/blockchain/blockchain.py
──────────────────────────────────
Rantai hash (hash chain) sebagai log audit di SQLite.

Kolom blok: block_index, timestamp, user_id, action, asset_ref,
asset_hash, previous_hash, nonce, block_hash, signature.

Alur kunci:
  • Kunci rantai: 32 byte acak di instance/chain.key — tidak pernah
    masuk basis data, cookie, flash, maupun log. Dipakai untuk
    signature = HMAC-SHA256(kunci rantai, block_hash) dan untuk
    menurunkan kunci konten (HMAC isi catatan/akun).
  • Jangkar kepala: head hash terbaru ditulis ke instance/chain_head.json
    dan, bila dongle terpasang, ke berkas di dongle.

Kekuatan verifikasi: PoW ringan (POW_DIFFICULTY digit nol heksadesimal di
depan block_hash), tautan previous_hash, signature, dan kecocokan head
dengan jangkar. add_block memakai BEGIN IMMEDIATE agar indeks unik dan
berurutan walau dua penulisan bersamaan.
"""

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import config
from database.db import get_db
from modules.logger import get_logger

_logger = get_logger(__name__)

# ── Daftar aksi yang sah ─────────────────────────────────────────────────────
ACTIONS: frozenset[str] = frozenset({
    "REGISTER", "LOGIN", "LOGIN_FAIL", "LOGOUT", "REAUTH",
    "UPLOAD", "DOWNLOAD", "STREAM", "REVEAL", "MODIFY", "DELETE",
    "TRASH_MOVE",
    "STEGO_EMBED", "STEGO_EXTRACT", "PASSWORD_CHANGE",
    "DONGLE_REGISTER", "BIOMETRIC_ENROLL", "BIOMETRIC_REMOVE",
    "RECOVERY", "RECOVERY_ROTATE", "SESSION_TIMEOUT",
    "ACCOUNT_RESET", "ACCOUNT_DELETE",
    "TAMPER_DETECTED",
})

_INSTANCE_DIR = getattr(config, "_INSTANCE_DIR", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "instance"
))
CHAIN_KEY_PATH = os.path.join(_INSTANCE_DIR, "chain.key")
CHAIN_HEAD_PATH = os.path.join(_INSTANCE_DIR, "chain_head.json")
_DONGLE_HEAD_NAME = ".cryptix_chain_head"
_LOGIN_FAIL_WINDOW_SECONDS = 60
_LOGIN_FAIL_MAX = 3
_CONTENT_HASH_INFO = b"cryptix-content-hash-v1"

# Hasil verifikasi terakhir per pengguna; hanya metadata, disimpan di memori
# agar Dashboard dapat menampilkan status tanpa memverifikasi ulang rantai.
_verifikasi_lock = threading.Lock()
_verifikasi_terakhir: dict[int, dict] = {}


# ── Kunci rantai dan kunci konten ────────────────────────────────────────────

def _chain_key() -> bytes:
    """Kunci rantai 32 byte di instance/chain.key; tidak pernah ke basis data."""
    try:
        with open(CHAIN_KEY_PATH, "rb") as handle:
            raw = handle.read()
        if len(raw) == 32:
            return raw
    except OSError:
        pass
    key = os.urandom(32)
    os.makedirs(os.path.dirname(CHAIN_KEY_PATH), exist_ok=True)
    try:
        with open(CHAIN_KEY_PATH, "xb") as handle:
            handle.write(key)
        _logger.info("Kunci rantai dibuat di %s", CHAIN_KEY_PATH)
        return key
    except FileExistsError:
        with open(CHAIN_KEY_PATH, "rb") as handle:
            return handle.read()


def _content_key() -> bytes:
    """Kunci konten = HKDF(kunci rantai, info "cryptix-content-hash-v1")."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=_CONTENT_HASH_INFO
    ).derive(_chain_key())


def content_hash(data: bytes) -> str:
    """
    HMAC-SHA256(kunci konten, data) untuk hash isi catatan, akun, dan pesan.

    Berbeda dari SHA-256 polos, HMAC tidak dapat dihitung ulang oleh pihak
    yang hanya memiliki isi basis data.
    """
    return hmac.new(_content_key(), data, hashlib.sha256).hexdigest()


def account_hash(site_enc: str, username_enc: str, password_enc: str) -> str:
    """HMAC gabungan tiga field terenkripsi kredensial (satu sumber kebenaran)."""
    blob = "\x1f".join((site_enc, username_enc, password_enc)).encode("utf-8")
    return content_hash(blob)


# ── Jangkar kepala rantai ────────────────────────────────────────────────────

def _write_head(block_index: int, block_hash: str) -> None:
    """Tulis head terbaru ke instance/chain_head.json dan dongle bila ada."""
    payload = json.dumps({
        "database": config.DATABASE_PATH,
        "block_index": block_index,
        "head_hash": block_hash,
    }, sort_keys=True)
    os.makedirs(os.path.dirname(CHAIN_HEAD_PATH), exist_ok=True)
    with open(CHAIN_HEAD_PATH, "w", encoding="utf-8") as handle:
        handle.write(payload)
    _write_dongle_head(payload)


def _read_head() -> dict | None:
    """Baca jangkar kepala; None bila belum ada atau tidak terbaca."""
    try:
        with open(CHAIN_HEAD_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def get_head_info() -> dict | None:
    """Jangkar kepala terakhir (database, block_index, head_hash) atau None."""
    return _read_head()


def _write_dongle_head(payload: str) -> None:
    """Salin jangkar ke dongle terdaftar bila terpasang (upaya terbaik)."""
    try:
        from modules.authentication.usb_authentication import (
            _get_removable_drives,
        )
        for mount in _get_removable_drives():
            token = os.path.join(mount, config.USB_TOKEN_FILENAME)
            if not os.path.exists(token):
                continue
            with open(os.path.join(mount, _DONGLE_HEAD_NAME), "w",
                      encoding="utf-8") as handle:
                handle.write(payload)
    except Exception:
        # Dongle tidak wajib ada; kegagalan menulis tidak menggagalkan rantai.
        return


# ── Hash, signature, dan proof of work ───────────────────────────────────────

def _hash_fields(block: dict) -> str:
    """SHA-256 kanonik atas seluruh isi blok kecuali signature."""
    raw = json.dumps(
        {
            "block_index": block["block_index"],
            "timestamp": block["timestamp"],
            "user_id": block["user_id"],
            "action": block["action"],
            "asset_ref": block.get("asset_ref", ""),
            "asset_hash": block["asset_hash"],
            "previous_hash": block["previous_hash"],
            "nonce": block.get("nonce", 0),
        },
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sign(key: bytes, block_hash: str) -> str:
    """signature = HMAC-SHA256(kunci rantai, block_hash)."""
    return hmac.new(key, block_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def _genesis_hash() -> str:
    """Hash tetap untuk previous_hash blok pertama."""
    return hashlib.sha256(b"CRYPTIX-GENESIS-BLOCK").hexdigest()


def _mine(base: dict, difficulty: int) -> tuple[str, int]:
    """Cari nonce sehingga block_hash diawali *difficulty* nol heksadesimal."""
    prefix = "0" * max(difficulty, 0)
    nonce = 0
    while True:
        block_hash = _hash_fields({**base, "nonce": nonce})
        if block_hash.startswith(prefix):
            return block_hash, nonce
        nonce += 1


def _login_fail_limited(db, user_id: int | None) -> bool:
    """Batas laju: maksimal 3 blok LOGIN_FAIL per pengguna tiap 60 detik."""
    cutoff = datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() - _LOGIN_FAIL_WINDOW_SECONDS,
        timezone.utc,
    ).isoformat()
    row = db.execute(
        "SELECT COUNT(*) AS jumlah FROM blockchain_log "
        "WHERE action='LOGIN_FAIL' AND user_id IS ? AND timestamp > ?",
        (user_id, cutoff),
    ).fetchone()
    return row["jumlah"] >= _LOGIN_FAIL_MAX


# ── API publik ───────────────────────────────────────────────────────────────

def add_block(
    user_id: int | None,
    action: str,
    asset_ref: str,
    asset_hash: str,
) -> int | None:
    """
    Tambahkan blok baru: PoW ringan, signature HMAC, jangkar head ikut
    diperbarui.

    Parameters
    ----------
    user_id    : int or None  Pelaku aksi.
    action     : str          Salah satu ACTIONS.
    asset_ref  : str          Rujukan aset "jenis:id" (contoh "file:12").
    asset_hash : str          Hash aset saat peristiwa (SHA-256 ciphertext
                              atau HMAC isi, lihat content_hash()).

    Returns
    -------
    int  Indeks blok baru, atau None bila LOGIN_FAIL dibatasi laju.

    Raises
    ------
    ValueError  Jika aksi tidak termasuk ACTIONS.
    """
    if action not in ACTIONS:
        raise ValueError(f"Aksi rantai tidak dikenal: {action}")

    key = _chain_key()
    with get_db() as db:
        # BEGIN IMMEDIATE mengunci basis data sejak awal sehingga indeks
        # yang dibaca dan ditulis tidak balapan dengan penulis lain.
        db.execute("BEGIN IMMEDIATE")
        try:
            if action == "LOGIN_FAIL" and _login_fail_limited(db, user_id):
                db.rollback()
                return None

            last = db.execute(
                "SELECT block_index, block_hash FROM blockchain_log "
                "ORDER BY block_index DESC LIMIT 1"
            ).fetchone()
            if last is None:
                block_index, previous_hash = 0, _genesis_hash()
            else:
                block_index = last["block_index"] + 1
                previous_hash = last["block_hash"]

            timestamp = datetime.now(timezone.utc).isoformat()
            base = {
                "block_index": block_index,
                "timestamp": timestamp,
                "user_id": user_id,
                "action": action,
                "asset_ref": asset_ref or "",
                "asset_hash": asset_hash,
                "previous_hash": previous_hash,
            }
            block_hash, nonce = _mine(base, config.POW_DIFFICULTY)
            signature = _sign(key, block_hash)

            db.execute(
                """INSERT INTO blockchain_log
                   (block_index, timestamp, user_id, action, asset_ref,
                    asset_hash, previous_hash, nonce, block_hash, signature)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    block_index, timestamp, user_id, action, asset_ref or "",
                    asset_hash, previous_hash, nonce, block_hash, signature,
                ),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise

    _write_head(block_index, block_hash)
    return block_index


def verify_chain() -> list[dict]:
    """
    Verifikasi seluruh rantai: hash isi, tautan, PoW, signature, dan
    kecocokan head terakhir dengan jangkar instance/chain_head.json.

    Returns
    -------
    list of dict per blok (field asli plus ``is_valid`` dan ``tampered``).
    Kegagalan jangkar menandai blok terakhir sebagai tampered.
    """
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM blockchain_log ORDER BY block_index ASC"
        ).fetchall()

    key = _chain_key()
    results = []
    expected_previous = _genesis_hash()
    prefix = "0" * max(config.POW_DIFFICULTY, 0)

    for row in rows:
        block = dict(row)
        recomputed = _hash_fields(block)
        hash_ok = recomputed == block["block_hash"]
        link_ok = block["previous_hash"] == expected_previous
        pow_ok = str(block["block_hash"]).startswith(prefix)
        signature_ok = hmac.compare_digest(
            str(block["signature"]), _sign(key, block["block_hash"])
        )
        block["is_valid"] = hash_ok and link_ok and pow_ok and signature_ok
        block["tampered"] = not block["is_valid"]
        results.append(block)
        expected_previous = block["block_hash"]

    # Jangkar kepala: rantai yang dimanipulasi (hash dihitung ulang) tetap
    # tertangkap walau signature ikut dihitung ulang tanpa kunci rantai.
    if results:
        anchor = _read_head()
        if anchor and anchor.get("database") == config.DATABASE_PATH:
            if anchor.get("head_hash") != results[-1]["block_hash"]:
                results[-1]["is_valid"] = False
                results[-1]["tampered"] = True

    return results


def verify_assets(user_id: int) -> list[dict]:
    """
    Verifikasi aset milik *user_id* terhadap catatan dan blok rantai.

    Status per aset:
      • "OK"           — nilai di disk/basis data cocok dengan catatan
                         dan blok UPLOAD/MODIFY terakhir.
      • "DIUBAH"       — nilai berbeda dari catatan atau blok.
      • "HILANG"       — berkas tidak ada di disk.
      • "TANPA CATATAN" — tidak ada blok UPLOAD/MODIFY untuk aset itu.

    Returns
    -------
    list of dict {"jenis", "ref", "id", "status"}.
    """
    entries: list[dict] = []

    def _blok_aset(ref: str) -> dict | None:
        row = db.execute(
            "SELECT asset_hash FROM blockchain_log "
            "WHERE user_id=? AND asset_ref=? AND action IN ('UPLOAD','MODIFY') "
            "ORDER BY block_index DESC LIMIT 1",
            (user_id, ref),
        ).fetchone()
        return dict(row) if row else None

    def _tambah(jenis: str, ref: str, aset_id: int, status: str) -> None:
        entries.append({"jenis": jenis, "ref": ref, "id": aset_id,
                        "status": status})

    with get_db() as db:
        for row in db.execute(
            "SELECT id, stored_name, sha256_ciphertext FROM vault_files "
            "WHERE user_id=?",
            (user_id,),
        ).fetchall():
            ref = f"file:{row['id']}"
            path = os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
            if not os.path.exists(path):
                _tambah("berkas", ref, row["id"], "HILANG")
                continue
            disk_hash = _sha256_file(path)
            blok = _blok_aset(ref)
            if blok is None:
                _tambah("berkas", ref, row["id"], "TANPA CATATAN")
            elif disk_hash != row["sha256_ciphertext"] or \
                    disk_hash != blok["asset_hash"]:
                _tambah("berkas", ref, row["id"], "DIUBAH")
            else:
                _tambah("berkas", ref, row["id"], "OK")

        for row in db.execute(
            "SELECT id, content_enc FROM secure_notes WHERE user_id=?",
            (user_id,),
        ).fetchall():
            ref = f"note:{row['id']}"
            blok = _blok_aset(ref)
            if blok is None:
                _tambah("catatan", ref, row["id"], "TANPA CATATAN")
            elif content_hash(row["content_enc"].encode("utf-8")) != blok["asset_hash"]:
                _tambah("catatan", ref, row["id"], "DIUBAH")
            else:
                _tambah("catatan", ref, row["id"], "OK")

        for row in db.execute(
            """SELECT id, site_name_enc, username_enc, password_enc
               FROM account_vault WHERE user_id=?""",
            (user_id,),
        ).fetchall():
            ref = f"cred:{row['id']}"
            blok = _blok_aset(ref)
            if blok is None:
                _tambah("akun", ref, row["id"], "TANPA CATATAN")
            elif account_hash(row["site_name_enc"], row["username_enc"],
                              row["password_enc"]) != blok["asset_hash"]:
                _tambah("akun", ref, row["id"], "DIUBAH")
            else:
                _tambah("akun", ref, row["id"], "OK")

    return entries


def _sha256_file(path: str) -> str:
    """SHA-256 berkas terenkripsi di disk per potongan 1 MiB."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_recent_blocks(user_id: int, limit: int = 20) -> list[dict]:
    """Blok milik *user_id* saja, terbaru dahulu; tanpa milik pengguna lain."""
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM blockchain_log WHERE user_id=? "
            "ORDER BY block_index DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_chain_stats() -> dict:
    """Statistik global rantai (keutuhan rantai berlaku untuk semua blok)."""
    with get_db() as db:
        row = db.execute(
            "SELECT COUNT(*) as total, MAX(block_index) as last_index "
            "FROM blockchain_log"
        ).fetchone()
        return {"total_blocks": row["total"], "last_index": row["last_index"]}


def record_verification(user_id: int, chain_result: list[dict]) -> dict:
    """
    Simpan hasil verifikasi terakhir milik ``user_id`` di memori proses.

    Hanya metadata yang disimpan (waktu, jumlah blok rusak, head hash);
    tidak ada isi blok atau kunci. Dipakai Dashboard agar tidak memicu
    verifikasi ulang setiap kali halaman dibuka.
    """
    tampered = sum(1 for blok in chain_result if blok.get("tampered"))
    hasil = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_blocks": len(chain_result),
        "tampered_blocks": tampered,
        "valid": tampered == 0,
        "head_hash": chain_result[-1]["block_hash"] if chain_result else None,
    }
    with _verifikasi_lock:
        _verifikasi_terakhir[user_id] = hasil
    return dict(hasil)


def get_last_verification(user_id: int) -> dict | None:
    """Hasil verifikasi terakhir milik ``user_id``, atau None bila belum ada."""
    with _verifikasi_lock:
        hasil = _verifikasi_terakhir.get(user_id)
        return dict(hasil) if hasil else None
