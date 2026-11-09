"""
routes/assistant_routes.py
────────────────────────────
Security Assistant chat routes.

Riwayat percakapan disimpan di sisi server (modules.assistant.history) dengan
kunci id sesi acak — bukan di cookie. Setiap entri:
{'role': 'user'|'agent', 'content': str, 'intent': str|None}

Kata sandi yang diperiksa memakai kolom terpisah (``password``) dan hanya
hidup di memori: tidak masuk riwayat, log, atau rantai blok. Riwayat hanya
mencatat penanda ``[password diperiksa]``.

The /assistant/chat endpoint returns JSON so the JS frontend can animate
thinking steps before showing the answer.
"""

from flask import Blueprint, render_template, request, session, jsonify

from modules.strings import MSG
from routes.auth_routes import login_required
from modules.assistant import history as chat_history
from modules.assistant import matcher
from modules.assistant.security_agent import process_message

assistant_bp = Blueprint("assistant", __name__)

_PENANDA_SANDI = "[password diperiksa]"


def _session_id() -> str:
    return session.get("session_id", "")


@assistant_bp.route("/assistant")
@login_required
def index():
    """Render the chat page with existing server-side history and topic buttons."""
    return render_template(
        "assistant.html",
        history=chat_history.get(_session_id()),
        topik=matcher.muat_topik(),
    )


@assistant_bp.route("/assistant/chat", methods=["POST"])
@login_required
def chat():
    """
    Process a user message/password and return the agent response as JSON.

    Request body (JSON): {"message": "..."} atau {"password": "..."}

    Kata sandi pada ``password`` tidak pernah disimpan: jawaban hanya memuat
    panjang, skor, dan saran; riwayat mencatat ``[password diperiksa]``.

    Response JSON:
    {
      "thinking_steps": [...],
      "answer": "...",
      "intent": "...",
      "saran": [{"id": "...", "judul": "..."}]   # opsional
    }
    """
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    password = data.get("password") or ""

    if not message and not password:
        return jsonify({"error": MSG.ASSISTANT_EMPTY_MESSAGE}), 400

    user_id = session["user_id"]

    # Periksa kata sandi hanya di memori; nilainya tidak pernah ditulis ke
    # riwayat, log, atau rantai blok.
    if password:
        result = process_message(f"cek password: {password}", user_id)
        catatan_pengguna = _PENANDA_SANDI
    else:
        result = process_message(message, user_id)
        # Pesan teks yang memuat kata sandi juga disamarkan di riwayat.
        catatan_pengguna = (
            _PENANDA_SANDI if result["intent"] == "password_check" else message
        )

    chat_history.append(_session_id(), [
        {"role": "user", "content": catatan_pengguna, "intent": None},
        {"role": "agent", "content": result["answer"],
         "intent": result["intent"]},
    ])

    balasan = {
        "thinking_steps": result["thinking_steps"],
        "answer":         result["answer"],
        "intent":         result["intent"],
    }
    if result.get("saran"):
        balasan["saran"] = result["saran"]
    return jsonify(balasan)


@assistant_bp.route("/assistant/clear", methods=["POST"])
@login_required
def clear_history():
    """Clear server-side conversation history for this session."""
    chat_history.clear(_session_id())
    return jsonify({"success": True})
