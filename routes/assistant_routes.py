"""
routes/assistant_routes.py
────────────────────────────
Security Assistant chat routes.

Conversation history is stored in the Flask session under 'chat_history'.
Each entry: {'role': 'user'|'agent', 'content': str, 'intent': str|None}

The /assistant/chat endpoint returns JSON so the JS frontend can animate
thinking steps before showing the answer.
"""

import os
import sys

from flask import Blueprint, render_template, request, session, jsonify

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from routes.auth_routes import login_required
from modules.assistant.security_agent import process_message, THINKING_STEPS

assistant_bp = Blueprint("assistant", __name__)

# Maximum messages to keep in session history (user + agent messages)
_MAX_HISTORY = 40


@assistant_bp.route("/assistant")
@login_required
def index():
    """Render the chat page with existing history."""
    history = session.get("chat_history", [])
    return render_template("assistant.html", history=history)


@assistant_bp.route("/assistant/chat", methods=["POST"])
@login_required
def chat():
    """
    Process a user message and return the agent response as JSON.

    Request body (JSON): {"message": "..."}

    Response JSON:
    {
      "thinking_steps": [...],
      "answer": "...",
      "intent": "..."
    }
    """
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"error": "Empty message."}), 400

    user_id = session["user_id"]

    # Process through rule-based agent
    result = process_message(message, user_id)

    # Persist history in session (user message + agent answer)
    history = session.get("chat_history", [])
    history.append({"role": "user",  "content": message, "intent": None})
    history.append({"role": "agent", "content": result["answer"],
                    "intent": result["intent"]})

    # Trim to max history
    if len(history) > _MAX_HISTORY:
        history = history[-_MAX_HISTORY:]

    session["chat_history"] = history
    session.modified = True

    return jsonify({
        "thinking_steps": result["thinking_steps"],
        "answer":         result["answer"],
        "intent":         result["intent"],
    })


@assistant_bp.route("/assistant/clear", methods=["POST"])
@login_required
def clear_history():
    """Clear conversation history from session."""
    session.pop("chat_history", None)
    session.modified = True
    return jsonify({"success": True})
