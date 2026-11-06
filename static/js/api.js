/**
 * static/js/api.js — pembungkus fetch ber-CSRF.
 *
 * Menambahkan header X-CSRFToken dari <meta name="csrf-token">,
 * menandai permintaan sebagai JSON (Accept) agar kegagalan CSRF dibalas
 * JSON oleh server, dan mengatur Content-Type bila badan berupa string.
 */
async function apiFetch(url, options = {}) {
  const opts = Object.assign({}, options);
  const headers = new Headers(opts.headers || {});

  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta && meta.content) {
    headers.set('X-CSRFToken', meta.content);
  }
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }
  if (typeof opts.body === 'string' && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  opts.headers = headers;
  return fetch(url, opts);
}
