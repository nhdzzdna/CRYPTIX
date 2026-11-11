/**
 * static/js/documents.js
 * ──────────────────────
 * Skrip pendukung tampilan antarmuka dokumen (kx-doc-*).
 * Tidak inline (CSP ketat).
 * Menghubungkan KX.dropzone, konfirmasi hapus via modal, integrasi dengan
 * collection_folders.js dan dokumen.js.
 */
(function () {
  'use strict';

  // Sinkronisasi data-select-file dengan KX.aksiMengambang
  function sinkronPilihan() {
    var checkboxes = document.querySelectorAll('[data-select-file]');
    checkboxes.forEach(function (cb) {
      if (!cb.hasAttribute('data-kx-pilih')) {
        cb.setAttribute('data-kx-pilih', '');
      }
    });
    if (window.KX && window.KX.aksiMengambang) {
      window.KX.aksiMengambang.segarkan();
    }
  }

  // Intersepsi submit tombol hapus individual untuk menggunakan KX.konfirmasiHapus
  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || !form.action || form.action.indexOf('/vault/delete/') === -1) {
      return;
    }
    // Jika sudah dikonfirmasi secara aman, biarkan lanjut submit
    if (form.getAttribute('data-kx-confirmed') === '1') {
      return;
    }

    event.preventDefault();

    var baris = form.closest('[data-doc-item]');
    var namaItem = baris ? baris.getAttribute('data-name') : 'dokumen ini';
    var pesanPola = document.body.getAttribute('data-msg-delete-confirm-pola') ||
      'Dokumen {nama} akan dipindahkan ke Sampah. Anda masih dapat memulihkannya dari sana.';

    if (window.KX && typeof window.KX.konfirmasiHapus === 'function') {
      window.KX.konfirmasiHapus({
        judul: 'Pindahkan ke Sampah?',
        nama: namaItem,
        pesan: pesanPola,
        labelTombol: 'Pindahkan',
        onKonfirmasi: function () {
          form.setAttribute('data-kx-confirmed', '1');
          form.submit();
        }
      });
    } else {
      // Fallback native confirm jika komponen belum siap
      if (window.confirm('Pindahkan ' + namaItem + ' ke Sampah?')) {
        form.setAttribute('data-kx-confirmed', '1');
        form.submit();
      }
    }
  });

  // Amati penambahan item dinamis dari buka folder agar checkbox terdaftar
  document.addEventListener('collection:items-loaded', function () {
    sinkronPilihan();
  });

  // Inisialisasi awal saat dokumen siap
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', sinkronPilihan);
  } else {
    sinkronPilihan();
  }
})();

