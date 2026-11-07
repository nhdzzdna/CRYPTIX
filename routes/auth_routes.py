"""
routes/auth_routes.py
──────────────────────
Login, logout, register, and biometric setup routes.
"""

import os
import secrets
import time
import base64

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, jsonify, make_response
)
from werkzeug.utils import secure_filename

import config
from modules.strings import MSG
from modules.authentication.auth import (
    create_account, validate_registration,
    verifikasi_tahap_satu, get_user_by_id,
    store_usb_token, update_face_model_path, update_fingerprint_path,
)
from modules.authentication import biometrics
from modules.authentication import face_recognition as face_mod
from modules.authentication import fingerprint as fp_mod
from modules.authentication import usb_authentication as usb_mod
from modules.cryptography import pending_keys, session_keys
from modules.blockchain.blockchain import add_block, content_hash

auth_bp = Blueprint("auth", __name__)


def login_required(f):
    """Decorator: tolak bila belum masuk atau kunci sesi sudah habis."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash(MSG.LOGIN_REQUIRED, "warning")
            return redirect(url_for("auth.login"))
        if session_keys.get(session.get("session_id", "")) is None:
            # Timeout diam/mutlak atau server pernah restart: kunci hilang.
            session.clear()
            flash(MSG.SESSION_EXPIRED, "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


# ── Register ──────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Form pendaftaran (butir 2.3a): username, email, kata sandi, konfirmasi,
    dan pilihan dongle terdeteksi. Tanpa dongle terpasang pendaftaran ditolak
    (kecuali mode pengembangan yang menyediakan folder simulasi).
    """
    drives = usb_mod.daftar_drive()
    if request.method == "GET":
        return render_template("register.html", drives=drives)

    username = request.form.get("username", "").strip()
    email    = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")

    galat = validate_registration(username, email, password, confirm)
    if galat:
        flash(galat, "danger")
        return render_template("register.html", drives=drives)

    mountpoint = request.form.get("dongle", "").strip()
    if not mountpoint and drives:
        mountpoint = drives[0]["mountpoint"]
    if not mountpoint:
        flash(MSG.REGISTER_USB_REQUIRED, "danger")
        return render_template("register.html", drives=usb_mod.daftar_drive())

    token = usb_mod.register_usb_token(mountpoint)
    if token is None:
        flash(MSG.REGISTER_USB_INVALID, "danger")
        return render_template("register.html", drives=usb_mod.daftar_drive())

    hasil = create_account(username, email, password, token)
    if not hasil["success"]:
        flash(hasil["error"], "danger")
        return render_template("register.html", drives=usb_mod.daftar_drive())

    add_block(hasil["user_id"], "REGISTER", "auth:register",
              content_hash(username.encode("utf-8")))
    return _respon_tanpa_simpan(
        "recovery.html",
        recovery_key=hasil["recovery_key"],
        pending=_simpan_kunci_pulih(hasil["user_id"], hasil["recovery_key"]),
    )


@auth_bp.route("/api/usb_drives", methods=["GET"])
def usb_drives():
    """Daftar dongle terdeteksi untuk dipilih pada form pendaftaran."""
    return jsonify({"drives": usb_mod.daftar_drive()})


# ── Kunci pemulihan (tampil sekali, butir 2.3b) ──────────────────────────────

# Penyimpanan sementara sisi server: kunci pemulihan tidak pernah masuk
# cookie, flash, URL, log, maupun basis data.
_KUNCI_PULIH: dict[str, tuple[int, str, float]] = {}
_TTL_KUNCI_PULIH = 600.0


def _simpan_kunci_pulih(user_id: int, recovery_key: str) -> str:
    """Simpan kunci pemulihan di memori server; kembalikan token acak sekali pakai."""
    sekarang = time.monotonic()
    kadaluarsa = [
        k for k, (_, _, t) in _KUNCI_PULIH.items()
        if sekarang - t > _TTL_KUNCI_PULIH
    ]
    for k in kadaluarsa:
        _KUNCI_PULIH.pop(k)
    token = secrets.token_urlsafe(32)
    _KUNCI_PULIH[token] = (user_id, recovery_key, sekarang)
    return token


def _respon_tanpa_simpan(template: str, **konteks):
    """Render halaman berisi rahasia dengan header anti-cache (no-store)."""
    resp = make_response(render_template(template, **konteks))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@auth_bp.route("/register/recovery", methods=["POST"])
def recovery_confirm():
    """Kunci pemulihan hanya tampil sekali; kotak konfirmasi wajib dicentang."""
    token = request.form.get("pending", "")
    entri = _KUNCI_PULIH.get(token)
    if entri is None:
        flash(MSG.RECOVERY_ONLY_ONCE, "warning")
        return redirect(url_for("auth.login"))
    user_id, recovery_key, _ = entri
    if not request.form.get("confirm_saved"):
        flash(MSG.RECOVERY_CHECK_REQUIRED, "warning")
        return _respon_tanpa_simpan(
            "recovery.html", recovery_key=recovery_key, pending=token
        )
    _KUNCI_PULIH.pop(token, None)
    session["setup_user_id"] = user_id
    return redirect(url_for("auth.setup"))


# ── Setup keamanan (wizard butir 2.3c) ───────────────────────────────────────

def _biometrik_terdaftar(user_id: int) -> bool:
    """True bila pengguna sudah punya minimal satu biometrik (wajah/sidik jari)."""
    return face_mod.has_face_model(user_id) or fp_mod.has_fingerprint(user_id)


_IZIN_PENYIAPAN = frozenset({"static", "auth.setup", "auth.register_face"})


@auth_bp.before_app_request
def _gerbang_penyiapan():
    """Selama penyiapan keamanan belum selesai, hanya halaman setup yang boleh diakses."""
    user_id = session.get("setup_user_id")
    if not user_id:
        return None
    if _biometrik_terdaftar(user_id):
        session.pop("setup_user_id", None)
        return None
    if request.endpoint in _IZIN_PENYIAPAN:
        return None
    return redirect(url_for("auth.setup"))


@auth_bp.before_app_request
def _gerbang_dongle_sesi():
    """Sesi masuk: dongle pengguna wajib terpasang (hasil di-cache maksimal 2 detik)."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    if usb_mod.dongle_pengguna_terpasang(user_id):
        return None
    session_keys.drop(session.get("session_id", ""))
    session.clear()
    flash(MSG.USB_NOT_ATTACHED, "warning")
    return redirect(url_for("auth.login"))


@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    """
    Wizard penyiapan keamanan: pengguna wajib mendaftarkan minimal satu
    biometrik sebelum halaman lain dapat diakses.
    """
    user_id = session.get("setup_user_id") or session.get("user_id")
    if user_id is None:
        flash(MSG.LOGIN_REQUIRED, "warning")
        return redirect(url_for("auth.login"))

    if _biometrik_terdaftar(user_id):
        selesai = session.pop("setup_user_id", None) is not None
        if selesai:
            flash(MSG.SETUP_COMPLETE, "success")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        fp_file = request.files.get("fingerprint_image")
        if not fp_file or not fp_file.filename:
            flash(MSG.SETUP_FP_REQUIRED, "danger")
            return render_template("setup.html")
        ext = os.path.splitext(secure_filename(fp_file.filename))[1].lower()
        if ext not in {".png", ".jpg", ".jpeg", ".bmp"}:
            flash(MSG.FINGERPRINT_INVALID_FORMAT, "warning")
            return render_template("setup.html")
        os.makedirs(config.TEMPORARY_FILES_DIR, exist_ok=True)
        tmp_path = os.path.join(config.TEMPORARY_FILES_DIR, f"fp_setup_{user_id}{ext}")
        fp_file.save(tmp_path)
        try:
            terdaftar = fp_mod.register_fingerprint(user_id, tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        if not terdaftar:
            flash(MSG.SETUP_FP_FAILED, "danger")
            return render_template("setup.html")
        update_fingerprint_path(user_id, fp_mod._fp_path(user_id))
        add_block(user_id, "BIOMETRIC_ENROLL", "auth:fingerprint",
                  content_hash(str(user_id).encode("utf-8")))
        session.pop("setup_user_id", None)
        flash(MSG.SETUP_COMPLETE, "success")
        return redirect(url_for("auth.login"))

    return render_template("setup.html")


# ── Login dua tahap (butir 2.4) ──────────────────────────────────────────────

def _isian_masuk() -> dict:
    """Terima badan JSON maupun form; kembalikan dict isian permintaan."""
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    return request.form.to_dict()


def _galat_masuk(pesan: str, status: int = 401):
    """Balasan galat tahap login sebagai JSON."""
    return jsonify({"success": False, "error": pesan}), status


def _hentikan_tahap_masuk() -> None:
    """Buang tahap yang tertunda (permintaan ulang lewat GET atau kedaluwarsa)."""
    token = session.pop("login_pending", None)
    session.pop("login_stage", None)
    if token:
        pending_keys.buang(token)


def _finalisasi_masuk(user: dict, dek: bytes) -> None:
    """
    Setelah kedua tahap lulus: session.clear(), session id baru, isi
    user_id, dan pindahkan DEK ke penyimpanan kunci aktif.
    """
    session.clear()
    sid = session_keys.create_session_id()
    session["user_id"]   = user["id"]
    session["username"]  = user["username"]
    session.permanent    = True
    session["session_id"] = sid
    session_keys.put(sid, dek)

    from database.db import get_db as _get_db
    with _get_db() as db:
        db.execute(
            "UPDATE users SET last_login = datetime('now') WHERE id = ?",
            (user["id"],),
        )
        db.commit()
    add_block(user["id"], "LOGIN", "auth:login",
              content_hash(user["username"].encode("utf-8")))
    flash(MSG.LOGIN_SUCCESS.format(username=user["username"]), "success")


@auth_bp.route("/api/dongle/status", methods=["GET"])
def dongle_status():
    """Status dongle pada mesin ini saja: "terdeteksi atau tidak", tanpa username."""
    terdeteksi = any(
        os.path.isdir(d["mountpoint"]) for d in usb_mod.daftar_drive()
    )
    return jsonify({"detected": terdeteksi})


@auth_bp.route("/login", methods=["GET", "POST"])
@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        if request.method == "POST":
            # Sudah masuk: tahap 1 tidak boleh diulang.
            return _galat_masuk(MSG.LOGIN_STAGE_ORDER, 400)
        return redirect(url_for("dashboard.index"))

    if request.method == "GET":
        # Permintaan ulang halaman membatalkan tahap yang tertunda sehingga
        # pengguna dapat memulai dari awal dengan akun berbeda.
        _hentikan_tahap_masuk()
        return render_template("login.html")

    # ── Tahap 1: password dan dongle dalam satu permintaan ───────────────────
    if session.get("login_stage") == 1:
        return _galat_masuk(MSG.LOGIN_STAGE_ORDER, 400)

    isian = _isian_masuk()
    username = str(isian.get("username", "")).strip()
    password = str(isian.pop("password", ""))

    hasil = verifikasi_tahap_satu(username, password)
    del password          # referensi password dibuang sebelum melangkah
    isian.clear()

    if not hasil["success"]:
        # LOGIN_FAIL dicatat (dengan batas laju di modul rantai) agar
        # percobaan gagal ikut teraudit tanpa membajak rantai.
        from database.db import get_db as _get_db
        with _get_db() as db:
            pemilik = db.execute(
                "SELECT id FROM users WHERE username=?", (username,)
            ).fetchone()
        add_block(
            pemilik["id"] if pemilik else None,
            "LOGIN_FAIL", "auth:login",
            content_hash(username.encode("utf-8")),
        )
        return _galat_masuk(
            MSG.LOGIN_FAILED.format(error=hasil["error"])
        )

    user = hasil.pop("user")
    dek = hasil.pop("dek")
    token_pending = pending_keys.letakkan(user["id"], dek)
    del dek

    # Cookie hanya berisi token acak penunjuk DEK yang tertahan di server.
    # Token CSRF dipertahankan agar tahap 2 tetap boleh memakai halaman yang
    # sama tanpa dimuat ulang.
    csrf_lama = {k: v for k, v in session.items() if "csrf" in k}
    session.clear()
    session.update(csrf_lama)
    session["login_stage"] = 1
    session["login_pending"] = token_pending

    return jsonify({
        "success": True,
        "pending": token_pending,
        "metode": biometrics.metode_untuk_pengguna(user["id"]),
        "kebijakan": config.BIOMETRIC_POLICY,
    })


@auth_bp.route("/login/biometric", methods=["POST"])
def login_biometric():
    """
    Tahap 2: verifikasi seluruh metode biometrik terdaftar sesuai
    BIOMETRIC_POLICY, lalu pindahkan DEK ke penyimpanan kunci aktif.
    """
    if "user_id" in session:
        return _galat_masuk(MSG.LOGIN_STAGE_ORDER, 400)

    isian = _isian_masuk()
    token = str(isian.get("pending", ""))
    if (session.get("login_stage") != 1 or not token
            or session.get("login_pending") != token):
        return _galat_masuk(MSG.LOGIN_STAGE_ORDER, 400)

    entri = pending_keys.periksa(token)
    if entri is None:
        _hentikan_tahap_masuk()
        return _galat_masuk(MSG.LOGIN_PENDING_EXPIRED)

    user_id, _dek = entri
    if not biometrics.metode_biometrik_terdaftar(user_id):
        return _galat_masuk(MSG.LOGIN_BIOMETRIC_NONE)

    hasil = biometrics.verifikasi_tahap_biometrik(
        user_id, isian.get("bukti")
    )
    if not biometrics.kebijakan_dipenuhi(hasil):
        return _galat_masuk(MSG.LOGIN_BIOMETRIC_FAILED)

    entri = pending_keys.ambil(token)
    if entri is None:
        return _galat_masuk(MSG.LOGIN_STAGE_ORDER, 400)
    user_id, dek = entri

    user = get_user_by_id(user_id)
    if user is None:
        del dek
        return _galat_masuk(MSG.LOGIN_STAGE_ORDER, 400)

    _finalisasi_masuk(user, dek)
    del dek
    return jsonify({"success": True, "redirect": url_for("dashboard.index")})


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Keluar sesi: buang DEK server-side dan hapus cookie (wajib POST + CSRF)."""
    user_id = session.get("user_id")
    if user_id is not None:
        add_block(user_id, "LOGOUT", "auth:logout",
                  content_hash(str(user_id).encode("utf-8")))
    session_keys.drop(session.get("session_id", ""))
    session.clear()
    flash(MSG.LOGOUT_SUCCESS, "info")
    return redirect(url_for("auth.login"))


# ── Face registration (AJAX endpoint) ────────────────────────────────────────

@auth_bp.route("/api/register_face", methods=["POST"])
def register_face():
    """
    Receives a JSON list of base64-encoded JPEG frames from the webcam
    and trains the LBPH model. Berjalan pada sesi login maupun sesi
    penyiapan keamanan.
    """
    import cv2
    import numpy as np

    user_id = session.get("user_id") or session.get("setup_user_id")
    if user_id is None:
        return jsonify({"success": False, "error": MSG.LOGIN_REQUIRED}), 401

    data = request.get_json()
    if not data or "frames" not in data:
        return jsonify({"success": False, "error": MSG.FACE_NO_FRAMES})

    frames = []
    for b64 in data["frames"]:
        try:
            img_bytes = base64.b64decode(b64.split(",")[-1])
            arr = np.frombuffer(img_bytes, dtype=np.uint8)
            frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if frame is not None:
                frames.append(frame)
        except Exception:
            continue

    ok = face_mod.register_face_from_frames(user_id, frames)
    if ok:
        update_face_model_path(user_id, face_mod._model_path(user_id))
        add_block(user_id, "BIOMETRIC_ENROLL", "auth:face",
                  content_hash(str(user_id).encode("utf-8")))
        selesai_penyiapan = (
            session.get("setup_user_id") == user_id
            and session.pop("setup_user_id", None) is not None
        )
        return jsonify({
            "success": True,
            "message": MSG.FACE_MODEL_SAVED,
            "setup_done": selesai_penyiapan,
        })
    return jsonify({"success": False, "error": MSG.FACE_NOT_ENOUGH_SAMPLES})


# ── Face verification (AJAX endpoint) ────────────────────────────────────────

@auth_bp.route("/api/verify_face", methods=["POST"])
def verify_face():
    """Verify a single base64 webcam frame during login."""
    import cv2
    import numpy as np

    data = request.get_json()
    username = data.get("username", "")
    b64 = data.get("frame", "")

    from database.db import get_db as _get_db
    with _get_db() as db:
        row = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({"verified": False})

    try:
        img_bytes = base64.b64decode(b64.split(",")[-1])
        arr = np.frombuffer(img_bytes, dtype=np.uint8)
        frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    except Exception:
        return jsonify({"verified": False})

    verified = face_mod.verify_face_from_frame(row["id"], frame)
    return jsonify({"verified": verified})


# ── USB Token registration ────────────────────────────────────────────────────

@auth_bp.route("/api/register_usb", methods=["POST"])
@login_required
def register_usb():
    """Tulis berkas token ke dongle terpilih (atau drive pertama) dan simpan verifier."""
    mountpoint = request.form.get("mountpoint", "").strip()
    if not mountpoint:
        drives = usb_mod.daftar_drive()
        mountpoint = drives[0]["mountpoint"] if drives else ""
    result = usb_mod.register_usb_token(mountpoint)
    if result is None:
        return jsonify({"success": False, "error": MSG.USB_NO_DRIVE})
    store_usb_token(
        session["user_id"],
        result["token_id"],
        result["verifier"],
        result["volume_serial"],
    )
    usb_mod.lupakan_cache(session["user_id"])
    add_block(session["user_id"], "DONGLE_REGISTER", "auth:usb",
              content_hash(str(session["user_id"]).encode("utf-8")))
    return jsonify({"success": True, "message": MSG.USB_REGISTERED})
