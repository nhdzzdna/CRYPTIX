/* static/js/recovery.js - salin/unduh kunci pemulihan tanpa pengalihan otomatis */

(function () {
  'use strict';

  const panel = document.getElementById('recovery-panel');
  const kunciEl = document.getElementById('recovery-key');
  const statusEl = document.getElementById('recovery-status');
  const cek = document.getElementById('confirm_saved');
  const lanjut = document.getElementById('btn-recovery-continue');
  const btnSalin = document.getElementById('btn-copy-recovery');
  const btnUnduh = document.getElementById('btn-download-recovery');

  if (!panel || !kunciEl || !cek || !lanjut) {
    return;
  }

  function pesan(teks) {
    if (statusEl) {
      statusEl.textContent = teks || '';
    }
  }

  function kunci() {
    return kunciEl.textContent.trim();
  }

  function salinCadangan(teks) {
    const area = document.createElement('textarea');
    area.value = teks;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    let berhasil = false;
    try {
      berhasil = document.execCommand('copy');
    } catch (_) {
      berhasil = false;
    }
    document.body.removeChild(area);
    return berhasil;
  }

  function salin(teks) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(teks).then(function () {
        return true;
      }).catch(function () {
        return salinCadangan(teks);
      });
    }
    return Promise.resolve(salinCadangan(teks));
  }

  function unduh(teks) {
    const isi = panel.dataset.fileHeader + '\n\n' + teks + '\n\n' +
      panel.dataset.fileHint + '\n';
    const blob = new Blob([isi], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const tautan = document.createElement('a');
    tautan.href = url;
    tautan.download = panel.dataset.filename || 'cryptix-kunci-pemulihan.txt';
    document.body.appendChild(tautan);
    tautan.click();
    document.body.removeChild(tautan);
    URL.revokeObjectURL(url);
  }

  if (btnSalin) {
    btnSalin.addEventListener('click', function () {
      const teks = kunci();
      if (!teks) {
        return;
      }
      salin(teks).then(function (berhasil) {
        pesan(berhasil ? panel.dataset.msgCopyOk : panel.dataset.msgCopyFailed);
      });
    });
  }

  if (btnUnduh) {
    btnUnduh.addEventListener('click', function () {
      const teks = kunci();
      if (!teks) {
        return;
      }
      unduh(teks);
      pesan(panel.dataset.msgDownloadOk);
    });
  }

  function perbaruiTombol() {
    lanjut.disabled = !cek.checked;
  }

  cek.addEventListener('change', perbaruiTombol);
  perbaruiTombol();
})();
