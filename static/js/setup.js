/* static/js/setup.js — tombol pendaftaran biometrik pada penyiapan */

(function () {
  'use strict';

  const faceBtn = document.getElementById('btn-setup-face');
  const webauthnBtn = document.getElementById('btn-setup-webauthn');

  if (faceBtn) {
    faceBtn.addEventListener('click', function () {
      if (window.CryptixFace) {
        window.CryptixFace.daftar('setup-video', 'setup-canvas', 'setup-face-status');
      }
    });
  }

  if (webauthnBtn) {
    webauthnBtn.addEventListener('click', function () {
      if (typeof window.daftarWebAuthn === 'function') {
        window.daftarWebAuthn('setup-webauthn-status');
      }
    });
  }
})();
