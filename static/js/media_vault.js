/**
 * static/js/media_vault.js
 * ────────────────────────
 * Pemutaran Media Vault setelah autentikasi ulang.
 *
 * Tombol putar memakai data-reauth="media.stream" sehingga modal meminta
 * konfirmasi. Setelah grant diterbitkan, elemen <audio>/<video> diisi URL
 * stream tanpa token; server menemukan grant aktif lewat cookie sesi.
 */
(function () {
  'use strict';

  function mediaUntukResource(resource) {
    var daftar = document.querySelectorAll('[data-stream-resource]');
    for (var i = 0; i < daftar.length; i += 1) {
      if (daftar[i].getAttribute('data-stream-resource') === String(resource)) {
        return daftar[i];
      }
    }
    return null;
  }

  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (form && form.matches && form.matches('[data-confirm]')) {
      if (!window.confirm(form.getAttribute('data-confirm'))) {
        event.preventDefault();
      }
    }
  });

  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detail = event.detail || {};
    if (detail.scope !== 'media.stream') {
      return;
    }

    var media = mediaUntukResource(detail.resource);
    if (!media) {
      return;
    }

    var url = media.getAttribute('data-stream-url');
    if (!url) {
      return;
    }

    if (media.getAttribute('src') !== url) {
      media.setAttribute('src', url);
      media.load();
    }
    var janji = media.play();
    if (janji && typeof janji.catch === 'function') {
      janji.catch(function () {
        /* Pemutaran otomatis dapat ditolak peramban; pengguna menekan play. */
      });
    }
  });
})();
