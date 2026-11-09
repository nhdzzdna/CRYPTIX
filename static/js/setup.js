/* static/js/setup.js - tombol pendaftaran biometrik pada penyiapan */

(function () {
  'use strict';

  const faceBtn = document.getElementById('btn-setup-face');
  const webauthnBtn = document.getElementById('btn-setup-webauthn');
  const facePanel = document.getElementById('setup-face-panel');
  const faceStatus = document.getElementById('setup-face-status');

  if (faceBtn) {
    faceBtn.addEventListener('click', function () {
      if (!window.CryptixFace) {
        if (faceStatus) {
          const pesan = facePanel && facePanel.dataset.msgFailed
            ? facePanel.dataset.msgFailed
            : 'Pendaftaran wajah gagal.';
          faceStatus.textContent = pesan;
        }
        return;
      }
      faceBtn.disabled = true;
      window.CryptixFace.daftar(
        'setup-video', 'setup-canvas', 'setup-face-status'
      ).catch(function () {
        // Pesan galat sudah ditampilkan oleh modul wajah.
      }).finally(function () {
        faceBtn.disabled = false;
      });
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
