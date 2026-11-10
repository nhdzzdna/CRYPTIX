/* static/js/register.js — pemuatan daftar dongle pada pendaftaran */

(function () {
  'use strict';

  function muatDaftarDongle() {
    const select = document.getElementById('dongle');
    const status = document.getElementById('dongle-status');
    const btn = document.getElementById('reload-dongle-btn');
    if (btn) {
      btn.classList.add('is-loading');
      btn.disabled = true;
    }
    apiFetch('/api/usb_drives')
      .then(r => r.json())
      .then(d => {
        select.innerHTML = '';
        if (!d.drives.length) {
          select.innerHTML = '<option value="" disabled selected>Tidak ada dongle terdeteksi</option>';
          status.textContent = 'Tidak ada dongle terdeteksi. Colokkan lalu muat ulang.';
          status.classList.add('is-warning');
          return;
        }
        d.drives.forEach(item => {
          const opt = document.createElement('option');
          opt.value = item.mountpoint;
          opt.textContent = item.mountpoint;
          select.appendChild(opt);
        });
        status.textContent = '';
        status.classList.remove('is-warning');
      })
      .catch(() => {
        status.textContent = 'Gagal memuat daftar dongle.';
        status.classList.add('is-warning');
      })
      .finally(() => {
        if (btn) {
          btn.classList.remove('is-loading');
          btn.disabled = false;
        }
      });
  }

  const btn = document.getElementById('reload-dongle-btn');
  if (btn) {
    btn.addEventListener('click', muatDaftarDongle);
  }
})();
