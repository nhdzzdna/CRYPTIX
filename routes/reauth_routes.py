"""
routes/reauth_routes.py
───────────────────────
Endpoint autentikasi ulang (step-up) untuk tindakan sensitif.

``POST /api/reauth`` menerima JSON atau form:
    {"method": "password", "scope": "file.download",
     "resource_id": "12", "password": "..."}

Respons berhasil berisi grant berumur pendek. Grant tidak disimpan di
sesi/cookie; klien mengirimkannya kembali melalui header ``X-Reauth-Grant``
ke rute yang memakai ``@require_grant(scope)``.
"""

from flask import Blueprint, jsonify, request, session

from modules.authentication import reauth
from modules.authentication import webauthn
from modules.blockchain.blockchain import add_block, content_hash
from modules.cryptography import session_keys
from modules.strings import MSG

reauth_bp = Blueprint("reauth", __name__)


def _badan_permintaan() -> dict:
    """Terima JSON maupun form tanpa menyimpan isinya di sesi."""
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    return request.form.to_dict()


@reauth_bp.route("/api/reauth/webauthn/options", methods=["POST"])
def reauth_webauthn_options():
    """Terbitkan tantangan WebAuthn sekali pakai untuk autentikasi ulang."""
    user_id = session.get("user_id")
    session_id = session.get("session_id", "")
    if not user_id or session_keys.get(session_id) is None:
        return jsonify({
            "success": False,
            "error": MSG.SESSION_EXPIRED,
        }), 401

    if not webauthn.ada_kredensial(user_id):
        return jsonify({
            "success": False,
            "error": MSG.REAUTH_WEBAUTHN_NONE,
        }), 400

    try:
        opsi = webauthn.buat_opsi_reauth(user_id)
    except Exception:
        return jsonify({
            "success": False,
            "error": MSG.REAUTH_WEBAUTHN_FAILED,
        }), 500
    return jsonify({"success": True, "options": opsi})


@reauth_bp.route("/api/reauth", methods=["POST"])
def reauth_endpoint():
    """Verifikasi ulang identitas lalu terbitkan grant sesuai scope."""
    user_id = session.get("user_id")
    session_id = session.get("session_id", "")
    if not user_id or session_keys.get(session_id) is None:
        return jsonify({
            "success": False,
            "error": MSG.SESSION_EXPIRED,
        }), 401

    data = _badan_permintaan()
    method = str(data.get("method", "")).strip()
    scope = str(data.get("scope", "")).strip()
    resource_id = data.get("resource_id")

    if method not in reauth.available_methods():
        return jsonify({
            "success": False,
            "error": MSG.REAUTH_METHOD_UNSUPPORTED,
        }), 400
    if scope not in reauth.SCOPES:
        return jsonify({
            "success": False,
            "error": MSG.REAUTH_SCOPE_UNKNOWN,
        }), 400

    berhasil, galat = reauth.verify_method(method, user_id, data)
    if not berhasil:
        return jsonify({
            "success": False,
            "error": galat or MSG.REAUTH_FAILED,
        }), 401

    grant = reauth.issue_grant(session_id, scope, resource_id)

    # Hanya rujukan non-rahasia yang dicatat; token grant dan kata sandi
    # tidak pernah masuk blockchain.
    rujukan = f"reauth:{scope}"
    sidik = content_hash(
        f"{user_id}:{scope}:{grant['resource_id'] or ''}".encode("utf-8")
    )
    add_block(user_id, "REAUTH", rujukan, sidik)

    return jsonify({
        "success": True,
        "grant": grant["token"],
        "scope": grant["scope"],
        "resource_id": grant["resource_id"],
        "expires_in": grant["expires_in"],
        "reusable": grant["reusable"],
    })
