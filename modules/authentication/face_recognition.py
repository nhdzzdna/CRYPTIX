"""
modules/authentication/face_recognition.py
──────────────────────────────────────────
Pengenalan wajah LBPH sebagai metode biometrik kedua (butir 2.6).

Alur:
  • Pendaftaran: klien mengirim sedikitnya 30 frame selama 3 detik; server
    mendeteksi wajah Haar, mengambil ROI abu-abu 200x200, dan menyimpan
    minimal 25 sampel valid dengan variasi cukup. Array ROI dikompresi
    (numpy savez di memori) lalu dienkripsi dengan
    purpose_key(DEK, "face-template") dan disimpan sebagai BLOB pada tabel
    biometric_templates. Tidak ada model atau citra wajah di disk.
  • Verifikasi: klien mengirim 5 frame; server mendekripsi template di
    memori, melatih LBPH di memori, lalu menerima bila minimal 3 dari 5
    frame lolos FACE_CONFIDENCE_THRESHOLD, median confidence di bawah
    ambang, dan frame tidak identik (menolak gambar beku).

Catatan keamanan: LBPH berbasis tekstur sehingga masih dapat dikelabui oleh
foto wajah yang dicetak atau ditampilkan di layar. Modul ini bukan pengganti
liveness detection.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os

import numpy as np

import config
from database.db import get_db
from modules.authentication import biometrics
from modules.cryptography.key_management import purpose_key
from modules.strings import MSG

try:
    import cv2
    _CV2_AVAILABLE = True
except ImportError:  # pragma: no cover - lingkungan tanpa OpenCV
    _CV2_AVAILABLE = False

_LABEL_TUJUAN = "face"
_AAD = b"cryptix-face-template-v1"
_VERSI_BLOB = b"FG1"
_UKURAN_ROI = (200, 200)
_MIN_SAMPEL = 25
_MIN_VARIASI = 5
_MAKS_SAMPEL = 60
_JUMLAH_FRAME_VERIFIKASI = 5
_AMBANG_IOU = 0.3
_AMBANG_CAKUPAN = 0.8

# Deteksi wajah: kandidat kecil di latar sering muncul sebagai deteksi palsu.
# Ukuran minimum 15% sisi terpendek frame, scaleFactor 1.1, minNeighbors 6.
_RASIO_MIN_WAJAH = 0.15
_SCALE_FACTOR_WAJAH = 1.1
_MIN_NEIGHBORS_WAJAH = 6
# Wajah sekunder baru dianggap "wajah lain" bila luasnya minimal 40% wajah
# terbesar pada frame yang sama.
_RASIO_WAJAH_LAIN = 0.40
# Penolakan "lebih dari satu wajah" diambil dari seluruh frame, bukan satu
# frame: tolak bila lebih dari 30% frame memuat wajah sekunder signifikan.
_AMBANG_FRAME_WAJAH_LAIN = 0.30

# Pemeriksaan mata: hanya 60% bagian atas ROI wajah yang diperiksa.
_RASIO_ATAS_MATA = 0.60
_CASCADE_MATA = "haarcascade_eye.xml"
_CASCADE_MATA_CADANGAN = "haarcascade_eye_tree_eyeglasses.xml"
_MIN_KOTAK_MATA = 2
# Verifikasi login menuntut minimal 70% frame dengan mata terbuka.
_AMBANG_FRAME_MATA_TERBUKA = 0.70


def _perlu_cv2() -> None:
    """Pastikan OpenCV tersedia sebelum operasi gambar dijalankan."""
    if not _CV2_AVAILABLE:
        raise RuntimeError("opencv-contrib-python-headless belum terpasang.")


def _get_cascade():
    """Muat Haar Cascade wajah depan (bawaan OpenCV atau config)."""
    _perlu_cv2()
    if config.HAAR_CASCADE_PATH and os.path.exists(config.HAAR_CASCADE_PATH):
        path = config.HAAR_CASCADE_PATH
    else:
        path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    cascade = cv2.CascadeClassifier(path)
    if cascade.empty():
        raise RuntimeError("Berkas Haar Cascade tidak ditemukan atau gagal dimuat.")
    return cascade


def _decode_frame(item) -> np.ndarray | None:
    """Ubah data URI/base64 JPEG menjadi array BGR, atau None bila gagal."""
    if not isinstance(item, str) or not item:
        return None
    try:
        _perlu_cv2()
        mentah = base64.b64decode(item.split(",")[-1])
        arr = np.frombuffer(mentah, dtype=np.uint8)
        return cv2.imdecode(arr, cv2.IMREAD_COLOR)
    except Exception:
        return None


def _irisan_kotak(a, b) -> tuple[int, int, int]:
    """Kembalikan luas irisan serta luas masing-masing bounding box."""
    ax, ay, aw, ah = a
    bx, by, bw, bh = b
    lebar = max(0, min(ax + aw, bx + bw) - max(ax, bx))
    tinggi = max(0, min(ay + ah, by + bh) - max(ay, by))
    return lebar * tinggi, aw * ah, bw * bh


def _duplikat(a, b) -> bool:
    """
    True bila dua bounding box kemungkinan menandai wajah yang sama.

    Selain IoU, dipakai rasio cakupan (irisan terhadap kotak terkecil) agar
    deteksi bersarang pada skala berbeda tetap dianggap duplikat.
    """
    irisan, luas_a, luas_b = _irisan_kotak(a, b)
    if irisan <= 0 or luas_a <= 0 or luas_b <= 0:
        return False
    iou = irisan / (luas_a + luas_b - irisan)
    cakupan = irisan / min(luas_a, luas_b)
    return iou > _AMBANG_IOU or cakupan > _AMBANG_CAKUPAN


def _deduplikasi_kotak(kotak) -> list:
    """
    Buang bounding box tumpang tindih memakai Non-Maximum Suppression.

    Kotak diurutkan dari yang terluas; kotak yang tumpang tindih dengan
    kotak terpilih sebelumnya tidak dihitung sebagai wajah terpisah.
    """
    terurut = sorted(kotak, key=lambda item: item[2] * item[3], reverse=True)
    dipilih: list = []
    for kandidat in terurut:
        if all(not _duplikat(kandidat, lain) for lain in dipilih):
            dipilih.append(kandidat)
    return dipilih


def _saring_wajah_signifikan(kotak: list) -> list:
    """
    Buang kandidat yang luasnya kurang dari 40% wajah terbesar.

    Deteksi palsu di latar biasanya jauh lebih kecil daripada wajah utama;
    kandidat seperti itu tidak boleh dihitung sebagai wajah kedua.
    """
    if not kotak:
        return []
    terbesar = max(w * h for _x, _y, w, h in kotak)
    return [
        item for item in kotak
        if item[2] * item[3] >= _RASIO_WAJAH_LAIN * terbesar
    ]


def _deteksi_semua_wajah(frame) -> list[np.ndarray]:
    """
    Deteksi seluruh wajah pada frame dan kembalikan ROI abu-abu 200x200.

    Urutan ROI mengikuti luas wajah dari terbesar ke terkecil. Bounding box
    yang saling tumpang tindih dideduplikasi, lalu kandidat yang jauh lebih
    kecil daripada wajah terbesar dibuang agar deteksi palsu di latar tidak
    dihitung sebagai wajah lain. Dipisah agar pendaftaran dapat menolak frame
    tanpa wajah atau dengan lebih dari satu wajah, dan agar dapat diganti pada
    pengujian.
    """
    _perlu_cv2()
    if frame is None or getattr(frame, "size", 0) == 0:
        return []
    abu = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    tinggi, lebar = abu.shape[:2]
    sisi_min = max(20, int(min(tinggi, lebar) * _RASIO_MIN_WAJAH))
    wajah = _get_cascade().detectMultiScale(
        abu,
        scaleFactor=_SCALE_FACTOR_WAJAH,
        minNeighbors=_MIN_NEIGHBORS_WAJAH,
        minSize=(sisi_min, sisi_min),
    )
    kotak = _saring_wajah_signifikan(_deduplikasi_kotak(wajah))
    return [
        cv2.resize(abu[y:y + h, x:x + w], _UKURAN_ROI)
        for x, y, w, h in kotak
    ]


def _get_cascade_mata(nama: str = _CASCADE_MATA):
    """Muat Haar Cascade mata; None bila berkas tidak tersedia atau rusak."""
    _perlu_cv2()
    path = cv2.data.haarcascades + nama
    cascade = cv2.CascadeClassifier(path)
    return None if cascade.empty() else cascade


def _kotak_mata(roi) -> list:
    """
    Deteksi kotak mata pada 60% bagian atas ROI wajah.

    Cascade mata biasa dicoba lebih dahulu; bila kurang dari dua kotak
    ditemukan, cascade kacamata dipakai sebagai cadangan. Kotak yang saling
    tumpang tindih dideduplikasi agar satu mata tidak dihitung dua kali.
    """
    if roi is None or getattr(roi, "size", 0) == 0:
        return []
    tinggi = roi.shape[0]
    atas = roi[:max(1, int(tinggi * _RASIO_ATAS_MATA)), :]
    sisi_min = max(8, int(min(atas.shape[:2]) * 0.08))
    for nama in (_CASCADE_MATA, _CASCADE_MATA_CADANGAN):
        cascade = _get_cascade_mata(nama)
        if cascade is None:
            continue
        try:
            kotak = cascade.detectMultiScale(
                atas,
                scaleFactor=1.1,
                minNeighbors=6,
                minSize=(sisi_min, sisi_min),
            )
        except Exception:
            continue
        terpilih = _deduplikasi_kotak(
            [tuple(int(nilai) for nilai in item) for item in kotak]
        )
        if len(terpilih) >= _MIN_KOTAK_MATA:
            return terpilih
    return []


def _mata_terbuka(roi) -> bool:
    """True bila minimal dua kotak mata tak-tumpang-tindih terdeteksi."""
    return len(_kotak_mata(roi)) >= _MIN_KOTAK_MATA


def _deteksi_roi(frame) -> np.ndarray | None:
    """Kembalikan ROI wajah terbesar pada frame, atau None bila tidak ada."""
    wajah = _deteksi_semua_wajah(frame)
    return wajah[0] if wajah else None


def _latih(samples: np.ndarray):
    """Latih LBPH di memori dari array ROI; label selalu nol (per pengguna)."""
    _perlu_cv2()
    pengenal = cv2.face.LBPHFaceRecognizer_create()
    pengenal.train(list(samples), np.zeros(len(samples), dtype=np.int32))
    return pengenal


def _prediksi(pengenal, roi) -> float:
    """Kembalikan confidence LBPH untuk satu ROI (kecil = lebih cocok)."""
    _label, confidence = pengenal.predict(roi)
    return float(confidence)


def _aad(user_id: int) -> bytes:
    return _AAD + b":" + str(user_id).encode("ascii")


def _kemas_template(dek: bytes, user_id: int, data: bytes) -> bytes:
    """Enkripsi array ROI dengan AES-256-GCM; format b"FG1" + nonce + ct."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    ct = AESGCM(purpose_key(dek, "face")).encrypt(nonce, data, _aad(user_id))
    return _VERSI_BLOB + nonce + ct


def _buka_template(dek: bytes, user_id: int, blob: bytes) -> bytes:
    """Balikan _kemas_template; kegagalan apa pun menjadi ValueError."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not isinstance(blob, (bytes, bytearray)) or not bytes(blob).startswith(_VERSI_BLOB):
        raise ValueError("Blob template wajah tidak dikenal.")
    isi = bytes(blob)[len(_VERSI_BLOB):]
    nonce, ct = isi[:12], isi[12:]
    try:
        return AESGCM(purpose_key(dek, "face")).decrypt(nonce, ct, _aad(user_id))
    except Exception as exc:
        raise ValueError("Template wajah tidak dapat dibuka.") from exc


def _paket_sampel(samples: list[np.ndarray]) -> bytes:
    """Kompresi array ROI ke bytes npz di memori (tidak menyentuh disk)."""
    buf = io.BytesIO()
    np.savez_compressed(buf, samples=np.stack(samples))
    return buf.getvalue()


def _baca_sampel(data: bytes) -> np.ndarray:
    """Muat kembali array ROI dari bytes npz di memori."""
    with np.load(io.BytesIO(data)) as isi:
        return isi["samples"]


def _simpan_template(user_id: int, dek: bytes, samples: list[np.ndarray]) -> None:
    """Simpan template wajah terenkripsi sebagai BLOB milik ``user_id``."""
    import sqlite3

    blob = _kemas_template(dek, user_id, _paket_sampel(samples))
    with get_db() as db:
        db.execute(
            "INSERT INTO biometric_templates (user_id, metode, template, sampel) "
            "VALUES (?, 'wajah', ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            "template=excluded.template, sampel=excluded.sampel, "
            "dibuat=datetime('now')",
            (user_id, sqlite3.Binary(blob), len(samples)),
        )
        db.commit()


def _ambil_template(user_id: int) -> bytes | None:
    """Ambil BLOB template wajah milik pengguna, atau None."""
    with get_db() as db:
        baris = db.execute(
            "SELECT template FROM biometric_templates WHERE user_id=? AND metode='wajah'",
            (user_id,),
        ).fetchone()
    return bytes(baris["template"]) if baris is not None else None


def template_ada(user_id: int) -> bool:
    """True bila pengguna sudah punya template wajah tersimpan."""
    with get_db() as db:
        baris = db.execute(
            "SELECT 1 FROM biometric_templates WHERE user_id=? AND metode='wajah'",
            (user_id,),
        ).fetchone()
    return baris is not None


def daftarkan_wajah(user_id: int, frames: list, dek: bytes) -> dict:
    """
    Daftarkan wajah dari daftar frame base64 dan simpan template terenkripsi.

    Returns
    -------
    dict ``success`` (bool), ``sampel`` (int), dan ``error`` bila gagal.
    """
    if not isinstance(frames, list) or not frames:
        return {"success": False, "error": MSG.FACE_NO_FRAMES}

    samples: list[np.ndarray] = []
    terdeteksi = 0
    frame_wajah_lain = 0
    mata_tertutup = 0
    for item in frames:
        wajah = _deteksi_semua_wajah(_decode_frame(item))
        if not wajah:
            continue
        terdeteksi += 1
        # Frame dengan kandidat wajah sekunder tetap menyumbang wajah
        # terbesar sebagai sampel, tetapi dihitung untuk keputusan akhir.
        if len(wajah) > 1:
            frame_wajah_lain += 1
        if not _mata_terbuka(wajah[0]):
            mata_tertutup += 1
            continue
        if len(samples) < _MAKS_SAMPEL:
            samples.append(wajah[0])

    if frame_wajah_lain / len(frames) > _AMBANG_FRAME_WAJAH_LAIN:
        return {"success": False, "error": MSG.FACE_MULTIPLE_FACES}

    if terdeteksi / len(frames) < 0.8:
        return {"success": False, "error": MSG.FACE_LOW_DETECTION_RATE}

    if len(samples) < _MIN_SAMPEL:
        if mata_tertutup:
            return {"success": False, "error": MSG.FACE_ENROLL_EYES_CLOSED}
        return {"success": False, "error": MSG.FACE_NOT_ENOUGH_SAMPLES}

    unik = {hashlib.sha256(s.tobytes()).hexdigest() for s in samples}
    if len(unik) < _MIN_VARIASI:
        return {
            "success": False,
            "error": "Variasi sampel wajah terlalu rendah. Gerakkan kepala sedikit.",
        }

    _simpan_template(user_id, dek, samples)
    return {"success": True, "sampel": len(samples)}


def verifikasi_wajah(user_id: int, bukti, dek: bytes | None = None) -> dict:
    """
    Verifikasi 5 frame terhadap template wajah pengguna.

    ``bukti`` berupa list frame base64 atau dict ``{"frames": [...]}``.
    Menerima bila minimal 3 dari 5 frame lolos ambang, median confidence di
    bawah ambang, dan frame tidak identik (bukan gambar beku). Nilai
    confidence dikembalikan untuk kalibrasi di CRYPTIX_DEV_MODE.
    """
    if isinstance(bukti, dict):
        frames = bukti.get("frames")
    else:
        frames = bukti
    if not isinstance(frames, list) or len(frames) < _JUMLAH_FRAME_VERIFIKASI:
        return {"success": False, "error": "Lima frame wajah diperlukan.",
                "confidences": [], "median": None}
    if dek is None:
        return {"success": False, "error": "Kunci sesi tidak tersedia.",
                "confidences": [], "median": None}

    blob = _ambil_template(user_id)
    if blob is None:
        return {"success": False, "error": "Template wajah belum terdaftar.",
                "confidences": [], "median": None}
    try:
        samples = _baca_sampel(_buka_template(dek, user_id, blob))
    except Exception:
        return {"success": False, "error": "Template wajah tidak dapat dibuka.",
                "confidences": [], "median": None}

    frames = frames[:_JUMLAH_FRAME_VERIFIKASI]
    sidik = [
        hashlib.sha256(str(item).encode("utf-8")).hexdigest() for item in frames
    ]
    beku = len(set(sidik)) < 2

    roi_frame = [_deteksi_roi(_decode_frame(item)) for item in frames]
    mata_terbuka = sum(1 for roi in roi_frame if _mata_terbuka(roi))
    if mata_terbuka / len(frames) < _AMBANG_FRAME_MATA_TERBUKA:
        return {
            "success": False,
            "error": MSG.FACE_EYES_CLOSED,
            "code": "mata_tertutup",
            "confidences": [],
            "median": None,
            "lolos": 0,
            "beku": beku,
        }

    pengenal = _latih(samples)
    ambang = float(config.FACE_CONFIDENCE_THRESHOLD)
    confidence: list[float] = []
    for roi in roi_frame:
        if roi is None:
            confidence.append(float("inf"))
            continue
        confidence.append(_prediksi(pengenal, roi))

    lolos = sum(1 for c in confidence if c <= ambang)
    median = float(np.median(confidence)) if confidence else float("inf")
    sukses = (not beku) and lolos >= 3 and median <= ambang
    return {
        "success": sukses,
        "confidences": confidence,
        "median": None if median == float("inf") else median,
        "lolos": lolos,
        "beku": beku,
    }


def _verifikasi_registri(user_id: int, bukti, dek: bytes | None = None) -> bool:
    """Pembungkus registry biometrik: bool dari verifikasi_wajah()."""
    return bool(verifikasi_wajah(user_id, bukti, dek=dek).get("success"))


# Metode biometrik tahap 2: bukti berupa 5 frame base64.
biometrics.tambah_metode(
    "wajah",
    "Wajah (kamera)",
    terdaftar=template_ada,
    verifikasi=_verifikasi_registri,
)
