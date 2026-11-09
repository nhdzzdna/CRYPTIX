/* static/js/register.js — pemuatan daftar dongle pada pendaftaran */

(function () {
  'use strict';

  function muatDaftarDongle() {
    const select = document.getElementById('dongle');
    const status = document.getElementById('dongle-status');
    apiFetch('/api/usb_drives')
      .then(r => r.json())
      .then(d => {
        select.innerHTML = '';
        if (!d.drives.length) {
          select.innerHTML = '<option value="" disabled selected>Tidak ada dongle terdeteksi</option>';
          status.textContent = 'Tidak ada dongle terdeteksi. Colokkan lalu muat ulang.';
          return;
        }
        d.drives.forEach(item => {
          const opt = document.createElement('option');
          opt.value = item.mountpoint;
          opt.textContent = item.mountpoint;
          select.appendChild(opt);
        });
        status.textContent = '';
      })
      .catch(() => { status.textContent = 'Gagal memuat daftar dongle.'; });
  }

  const btn = document.getElementById('reload-dongle-btn');
  if (btn) {
    btn.addEventListener('click', muatDaftarDongle);
  }
})();
