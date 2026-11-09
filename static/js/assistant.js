/* static/js/assistant.js — antarmuka Security Assistant */

(function () {
  'use strict';

  const messagesEl = document.getElementById('chat-messages');
  const inputEl = document.getElementById('user-input');
  const passwordEl = document.getElementById('password-input');
  const thinkingEl = document.getElementById('thinking-indicator');
  const thinkTextEl = document.getElementById('thinking-text');

  if (!messagesEl || !inputEl || !passwordEl || !thinkingEl) {
    return;
  }

  inputEl.addEventListener('input', () => {
    inputEl.style.height = 'auto';
    inputEl.style.height = Math.min(inputEl.scrollHeight, 120) + 'px';
  });

  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  passwordEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      sendPassword();
    }
  });

  function scrollToBottom() {
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function renderMarkdown(text) {
    return text
      .replace(/^## (.+)$/gm, '<h3 class="msg-h3">$1</h3>')
      .replace(/^# (.+)$/gm, '<h2 class="msg-h2">$1</h2>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>')
      .replace(/^> (.+)$/gm, '<blockquote class="bq">$1</blockquote>')
      .replace(/^---$/gm, '<hr class="msg-hr"/>')
      .replace(/^[•\-\*] (.+)$/gm, '<li>$1</li>')
      .replace(/(<li>.*<\/li>(\s*<li>.*<\/li>)*)/gs, '<ul class="msg-ul">$1</ul>')
      .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
      .replace(/\n\n/g, '</p><p class="msg-p">')
      .replace(/\n/g, '<br>');
  }

  function appendMessage(role, content) {
    const row = document.createElement('div');
    row.className = `msg-row msg-${role}`;

    const avatar = document.createElement('div');
    avatar.className = role === 'agent' ? 'msg-avatar' : 'msg-avatar user-avatar';
    avatar.textContent = role === 'agent' ? '🤖' : '👤';

    const bubble = document.createElement('div');
    bubble.className = `msg-bubble ${role === 'agent' ? 'agent-bubble' : 'user-bubble'}`;

    const inner = document.createElement('div');
    inner.className = 'msg-content';
    inner.innerHTML = role === 'agent' ? renderMarkdown(content) : escapeHtml(content);
    bubble.appendChild(inner);

    if (role === 'agent') {
      row.appendChild(avatar);
      row.appendChild(bubble);
    } else {
      row.appendChild(bubble);
      row.appendChild(avatar);
    }

    messagesEl.insertBefore(row, thinkingEl);
    scrollToBottom();
    return bubble;
  }

  function appendSuggestions(saran) {
    if (!Array.isArray(saran) || !saran.length) return;

    const wrap = document.createElement('div');
    wrap.className = 'msg-suggestions';

    saran.forEach((item) => {
      if (!item || !item.judul) return;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'suggestion-btn';
      btn.textContent = item.judul;
      btn.setAttribute('data-pertanyaan', item.judul);
      btn.addEventListener('click', () => sendSuggestion(item.judul));
      wrap.appendChild(btn);
    });

    if (wrap.childElementCount) {
      messagesEl.insertBefore(wrap, thinkingEl);
      scrollToBottom();
    }
  }

  function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  const THINKING_STEPS = [
    'Memahami pertanyaan…',
    'Membaca data aplikasi…',
    'Menyusun jawaban…'
  ];

  async function showThinkingSteps() {
    thinkingEl.style.display = 'flex';
    scrollToBottom();
    for (const step of THINKING_STEPS) {
      thinkTextEl.textContent = step;
      await delay(600);
    }
  }

  function hideThinking() {
    thinkingEl.style.display = 'none';
  }

  function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

  async function sendMessage(abaikanSandi) {
    const message = inputEl.value.trim();
    const password = abaikanSandi ? '' : passwordEl.value;
    if (!message && !password) return;

    const bubbleText = password ? '[password diperiksa]' : message;
    const payload = password ? { password } : { message };

    inputEl.value = '';
    passwordEl.value = '';
    inputEl.style.height = 'auto';
    inputEl.disabled = true;
    passwordEl.disabled = true;
    document.getElementById('send-btn').disabled = true;
    document.getElementById('check-password-btn').disabled = true;

    appendMessage('user', bubbleText);
    await showThinkingSteps();

    try {
      const resp = await apiFetch('/assistant/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!resp.ok) throw new Error('Server error ' + resp.status);
      const data = await resp.json();

      hideThinking();
      appendMessage('agent', data.answer);
      appendSuggestions(data.saran);
    } catch (err) {
      hideThinking();
      appendMessage('agent', '❌ Terjadi kesalahan. Silakan coba lagi.');
    }

    inputEl.disabled = false;
    passwordEl.disabled = false;
    document.getElementById('send-btn').disabled = false;
    document.getElementById('check-password-btn').disabled = false;
    inputEl.focus();
  }

  function sendPassword() {
    if (!passwordEl.value) return;
    sendMessage();
  }

  function sendSuggestion(text) {
    inputEl.value = text;
    sendMessage(true);
  }

  async function clearChat() {
    if (!confirm('Hapus seluruh riwayat percakapan?')) return;
    await apiFetch('/assistant/clear', {
      method: 'POST',
    });
    window.location.reload();
  }

  document.getElementById('send-btn').addEventListener('click', () => sendMessage());
  document.getElementById('check-password-btn').addEventListener('click', sendPassword);

  const clearBtn = document.getElementById('clear-chat-btn');
  if (clearBtn) {
    clearBtn.addEventListener('click', clearChat);
  }

  document.querySelectorAll('.suggestion-btn').forEach((btn) => {
    const pertanyaan = btn.getAttribute('data-pertanyaan') || btn.getAttribute('data-suggestion');
    if (pertanyaan) {
      btn.addEventListener('click', () => sendSuggestion(pertanyaan));
    }
  });

  scrollToBottom();
})();
