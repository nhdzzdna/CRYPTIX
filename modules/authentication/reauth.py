"""
modules/authentication/reauth.py
────────────────────────────────
Autentikasi ulang (step-up) untuk tindakan sensitif.

Alur:
  • Rute meminta grant lewat ``POST /api/reauth`` dengan metode ``password``
    atau ``webauthn``, scope, dan resource id.
  • Grant adalah token acak yang disimpan hanya di memori sisi server,
    dikunci thread, dan terikat pada session id + scope + resource id.
  • Grant sekali pakai berlaku 120 detik. Scope ``media.stream`` dapat
    dipakai berulang untuk satu resource selama 15 menit agar permintaan
    HTTP Range tidak menghabiskan grant pada byte pertama.
  • Metode verifikasi berada pada registri yang dapat ditambah. WebAuthn
    memakai tantangan khusus step-up (webauthn.kunci_reauth) yang diterbitkan
    lewat POST /api/reauth/webauthn/options.

Kata sandi hanya diverifikasi terhadap hash autentikasi. Modul ini tidak
menurunkan, menyimpan, atau mengirim kunci apa pun, dan tidak menulis kata
sandi ke sesi, cookie, log, maupun blockchain.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from functools import wraps

from flask import jsonify, request, session

from database.db import get_db
from modules.authentication.password_hash import verify_password
from modules.strings import MSG

# ── Scope yang dikenal (butir 3.5d) ─────────────────────────────────────────
SCOPES = frozenset({
    "account.reveal",
    "note.open",
    "note.edit",
    "file.download",
    "media.stream",
    "media.winamp",
    "album.unlock",
    "stego.extract",
    "stego.download",
    "item.delete",
    "trash.purge",
    "settings.change",
    "biometric.manage",
})

MEDIA_STREAM_SCOPE = "media.stream"
ALBUM_UNLOCK_SCOPE = "album.unlock"
GRANT_TTL_SECONDS = 120
MEDIA_STREAM_TTL_SECONDS = 15 * 60
REUSABLE_TTL = {
    MEDIA_STREAM_SCOPE: MEDIA_STREAM_TTL_SECONDS,
    ALBUM_UNLOCK_SCOPE: MEDIA_STREAM_TTL_SECONDS,
}

_GRANT_HEADER = "X-Reauth-Grant"
_GRANT_FIELD = "reauth_grant"

_lock = threading.Lock()
_grants: dict[str, dict] = {}

_METHOD_REGISTRY: dict[str, object] = {}


def _now() -> float:
    """Waktu monotonik; dibungkus agar dapat diuji tanpa menunggu."""
    return time.monotonic()


def normalize_resource_id(value) -> str | None:
    """Samakan resource id menjadi string atau None (route int vs JSON str)."""
    if value is None:
        return None
    teks = str(value).strip()
    return teks or None


def register_method(name: str):
    """
    Daftarkan metode autentikasi ulang.

    Fungsi metode menerima ``(user_id, payload)`` dan mengembalikan
    ``(berhasil: bool, pesan_galat: str | None)``.
    """
    def dekorator(fungsi):
        _METHOD_REGISTRY[name] = fungsi
        return fungsi
    return dekorator


def available_methods() -> frozenset[str]:
    """Nama metode yang terdaftar saat ini."""
    return frozenset(_METHOD_REGISTRY)


def verify_method(method: str, user_id: int, payload: dict | None):
    """Jalankan metode terdaftar; kembalikan (berhasil, pesan_galat)."""
    fungsi = _METHOD_REGISTRY.get(method)
    if fungsi is None:
        return False, MSG.REAUTH_METHOD_UNSUPPORTED
    return fungsi(user_id, payload or {})


@register_method("password")
def _metode_password(user_id: int, payload: dict):
    """Verifikasi kata sandi akun melalui hash autentikasi PBKDF2."""
    password = payload.get("password")
    if not isinstance(password, str) or not password:
        return False, MSG.REAUTH_PASSWORD_REQUIRED

    with get_db() as db:
        baris = db.execute(
            "SELECT password_hash, salt FROM users WHERE id = ?", (user_id,)
        ).fetchone()

    if baris is None:
        return False, MSG.REAUTH_FAILED
    if not verify_password(password, baris["password_hash"], baris["salt"]):
        return False, MSG.REAUTH_FAILED
    return True, None


@register_method("wajah")
def _metode_wajah(user_id: int, payload: dict):
    """Verifikasi frame kamera terhadap template wajah milik sesi aktif."""
    from modules.authentication import face_recognition
    from modules.cryptography import session_keys

    frames = payload.get("frames")
    if not isinstance(frames, list):
        return False, MSG.FACE_NO_FRAMES

    session_id = session.get("session_id", "")
    dek = session_keys.get(session_id)
    if dek is None:
        return False, MSG.FACE_NO_SESSION_KEY

    try:
        hasil = face_recognition.verifikasi_wajah(user_id, frames, dek=dek)
    finally:
        del dek

    if hasil.get("success"):
        return True, None
    return False, MSG.AUTH_FACE_FAILED


@register_method("webauthn")
def _metode_webauthn(user_id: int, payload: dict):
    """Verifikasi WebAuthn untuk autentikasi ulang (tantangan kunci_reauth)."""
    from modules.authentication import webauthn

    respons = payload.get("response")
    if not isinstance(respons, dict):
        return False, MSG.REAUTH_WEBAUTHN_FAILED
    hasil = webauthn.verifikasi_webauthn(
        user_id, respons, webauthn.kunci_reauth(user_id)
    )
    if hasil.get("success"):
        return True, None
    if hasil.get("error") == MSG.WEBAUTHN_NO_CREDENTIAL:
        return False, MSG.REAUTH_WEBAUTHN_NONE
    return False, MSG.REAUTH_WEBAUTHN_FAILED


def issue_grant(session_id: str, scope: str, resource_id=None) -> dict:
    """
    Terbitkan grant baru dan kembalikan detail yang aman dikirim ke klien.

    Grant tidak pernah disimpan di cookie atau sesi; klien menyimpannya di
    memori JavaScript dan mengirimkannya lewat header ``X-Reauth-Grant``.
    """
    if not session_id:
        raise ValueError("session_id wajib terisi")
    if scope not in SCOPES:
        raise ValueError(f"Scope tidak dikenal: {scope}")

    resource = normalize_resource_id(resource_id)
    reusable = scope in REUSABLE_TTL
    berlaku = REUSABLE_TTL.get(scope, GRANT_TTL_SECONDS)
    token = secrets.token_urlsafe(32)
    sekarang = _now()

    with _lock:
        _buang_kedaluwarsa(sekarang)
        _grants[token] = {
            "session_id": session_id,
            "scope": scope,
            "resource_id": resource,
            "expires_at": sekarang + berlaku,
            "reusable": reusable,
        }

    return {
        "token": token,
        "scope": scope,
        "resource_id": resource,
        "expires_in": berlaku,
        "reusable": reusable,
    }


def consume_grant(token: str, session_id: str, scope: str, resource_id=None):
    """
    Validasi dan pakai grant.

    Returns
    -------
    (bool, str)
        ``(True, "ok")`` bila sah; selain itu pesan alasan
        ``missing``, ``invalid``, ``expired``, ``session``, ``scope``,
        atau ``resource``.
    """
    if not token:
        return False, "missing"

    resource = normalize_resource_id(resource_id)
    sekarang = _now()

    with _lock:
        entri = _grants.get(token)
        if entri is None:
            return False, "invalid"
        if sekarang >= entri["expires_at"]:
            del _grants[token]
            return False, "expired"
        _buang_kedaluwarsa(sekarang)
        if not hmac.compare_digest(entri["session_id"], session_id or ""):
            return False, "session"
        if entri["scope"] != scope:
            return False, "scope"
        if entri["resource_id"] != resource:
            return False, "resource"
        if not entri["reusable"]:
            del _grants[token]
        return True, "ok"


def find_active_grant(session_id: str, scope: str, resource_id=None) -> str | None:
    """
    Cari token grant berulang yang masih berlaku untuk sesi, scope, dan
    resource yang sama.

    Dipakai ``require_grant`` ketika klien tidak dapat mengirim header,
    misalnya elemen ``<audio>``/``<video>`` yang memuat URL langsung. Hanya
    grant berulang (``media.stream``) yang dicari agar scope sekali pakai
    tetap wajib menyertakan token secara eksplisit.
    """
    if not session_id:
        return None
    resource = normalize_resource_id(resource_id)
    sekarang = _now()
    with _lock:
        _buang_kedaluwarsa(sekarang)
        kandidat = None
        for token, entri in _grants.items():
            if not entri.get("reusable"):
                continue
            if not hmac.compare_digest(entri["session_id"], session_id):
                continue
            if entri["scope"] != scope:
                continue
            if entri["resource_id"] != resource:
                continue
            if (kandidat is None
                    or entri["expires_at"] > _grants[kandidat]["expires_at"]):
                kandidat = token
        return kandidat


def _buang_kedaluwarsa(sekarang: float) -> None:
    """Buang seluruh grant kedaluwarsa; pemanggil memegang lock."""
    for token in [
        token for token, entri in _grants.items()
        if sekarang >= entri["expires_at"]
    ]:
        del _grants[token]


def clear() -> None:
    """Kosongkan penyimpanan grant (logout, pengujian, atau pembersihan)."""
    with _lock:
        _grants.clear()


def _token_dari_permintaan() -> str:
    """
    Ambil grant dari header, form, atau badan JSON.

    Query string sengaja tidak dibaca agar token tidak pernah masuk URL.
    """
    token = request.headers.get(_GRANT_HEADER)
    if token:
        return token
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = request.form.get(_GRANT_FIELD)
        if token:
            return token
        if request.is_json:
            badan = request.get_json(silent=True) or {}
            token = badan.get(_GRANT_FIELD)
    return token or ""


def _pesan_penolakan(alasan: str) -> str:
    """Pesan pengguna untuk setiap alasan penolakan grant."""
    return {
        "missing": MSG.REAUTH_REQUIRED,
        "invalid": MSG.REAUTH_INVALID,
        "expired": MSG.REAUTH_INVALID,
        "session": MSG.REAUTH_SESSION_MISMATCH,
        "scope": MSG.REAUTH_SCOPE_MISMATCH,
        "resource": MSG.REAUTH_RESOURCE_MISMATCH,
    }.get(alasan, MSG.REAUTH_INVALID)



def _resource_id_dari_kwargs(kwargs: dict):
    """Ambil resource id dari argumen rute yang lazim dipakai."""
    for nama in ("resource_id", "file_id", "img_id"):
        if nama in kwargs:
            return kwargs[nama]
    return None


def require_grant(scope: str, when=None):
    """
    Decorator rute: tolak bila grant untuk *scope* tidak sah.

    Resource ID diambil dari argumen route bernama resource_id,
    file_id, atau img_id. Grant dikirim melalui header
    X-Reauth-Grant (atau field form reauth_grant), tidak pernah
    melalui URL.

    when opsional: callable tanpa argumen. Bila hasilnya False,
    grant tidak diminta. Digunakan agar alur penyiapan awal
    tetap bebas grant.

    Untuk scope berulang (media.stream), grant aktif milik
    sesi yang sama dicari bila header/field tidak ada.
    """
    if scope not in SCOPES:
        raise ValueError(f"Scope tidak dikenal: {scope}")

    def dekorator(view):
        @wraps(view)
        def terbungkus(*args, **kwargs):
            if when is not None and not when():
                return view(*args, **kwargs)

            session_id = session.get("session_id", "")
            resource_id = _resource_id_dari_kwargs(kwargs)

            token = _token_dari_permintaan()
            if not token and scope in REUSABLE_TTL:
                token = find_active_grant(session_id, scope, resource_id) or ""

            sah, alasan = consume_grant(
                token,
                session_id,
                scope,
                resource_id,
            )
            if not sah:
                status = 403 if alasan in {"scope", "resource"} else 401
                return jsonify({
                    "success": False,
                    "error": _pesan_penolakan(alasan),
                    "reason": alasan,
                }), status
            return view(*args, **kwargs)
        return terbungkus
    return dekorator
