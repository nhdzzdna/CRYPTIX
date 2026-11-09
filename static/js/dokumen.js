/**
 * static/js/dokumen.js
 * ────────────────────
 * Pencarian nama dan pengurutan (nama, tanggal, ukuran) halaman Dokumen
 * di sisi klien dari data yang sudah dirender server.
 */
(function () {
  'use strict';

  var kotakCari = document.getElementById('document-search');
  var pilihUrut = document.getElementById('document-sort');
  if (!kotakCari || !pilihUrut) {
    return;
  }

  function kartuDalam(wadah) {
    return Array.prototype.slice.call(
      wadah.querySelectorAll('[data-doc-item]'));
  }

  function kunci(kartu, jenis) {
    if (jenis === 'size') {
      return Number(kartu.getAttribute('data-size')) || 0;
    }
    if (jenis === 'date') {
      return kartu.getAttribute('data-date') || '';
    }
    return (kartu.getAttribute('data-name') || '').toLowerCase();
  }

  function terapkan(wadah) {
    if (!wadah) {
      return;
    }
    var kueri = kotakCari.value.trim().toLowerCase();
    var urut = pilihUrut.value;
    var kartu = kartuDalam(wadah);

    kartu.sort(function (a, b) {
      var ka = kunci(a, urut);
      var kb = kunci(b, urut);
      if (urutanTurun(urut)) {
        return ka < kb ? 1 : (ka > kb ? -1 : 0);
      }
      return ka > kb ? 1 : (ka < kb ? -1 : 0);
    });

    kartu.forEach(function (kartuItem) {
      var nama = (kartuItem.getAttribute('data-name') || '').toLowerCase();
      var cocok = !kueri || nama.indexOf(kueri) !== -1;
      kartuItem.hidden = !cocok;
      wadah.appendChild(kartuItem);
    });
  }

  function urutanTurun(jenis) {
    return jenis === 'date';
  }

  function semua() {
    Array.prototype.forEach.call(
      document.querySelectorAll('[data-doc-list]'), terapkan);
  }

  kotakCari.addEventListener('input', semua);
  pilihUrut.addEventListener('change', semua);

  document.addEventListener('collection:items-loaded', function (event) {
    var wadah = event.detail && event.detail.container;
    if (wadah && wadah.hasAttribute('data-doc-list')) {
      terapkan(wadah);
    }
  });

  semua();
})();
