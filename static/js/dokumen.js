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

  var pesanKosong = document.getElementById('document-no-results');
  var daftarKosong = document.getElementById('documents-empty');

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
      return { total: 0, tampil: 0 };
    }
    var kueri = kotakCari.value.trim().toLowerCase();
    var urut = pilihUrut.value;
    var kartu = kartuDalam(wadah);
    var tampil = 0;

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
      if (cocok) {
        tampil += 1;
      }
      wadah.appendChild(kartuItem);
    });

    return { total: kartu.length, tampil: tampil };
  }

  function urutanTurun(jenis) {
    return jenis === 'date';
  }

  function semua() {
    var total = 0;
    var tampil = 0;
    Array.prototype.forEach.call(
      document.querySelectorAll('[data-doc-list]'), function (wadah) {
        var hasil = terapkan(wadah);
        total += hasil.total;
        tampil += hasil.tampil;
      });

    var kueri = kotakCari.value.trim();
    if (pesanKosong) {
      pesanKosong.hidden = !(kueri && total > 0 && tampil === 0);
    }
    if (daftarKosong) {
      daftarKosong.hidden = Boolean(kueri) || total > 0;
    }
  }

  kotakCari.addEventListener('input', semua);
  pilihUrut.addEventListener('change', semua);

  document.addEventListener('collection:items-loaded', function (event) {
    var wadah = event.detail && event.detail.container;
    if (wadah && wadah.hasAttribute('data-doc-list')) {
      semua();
    }
  });

  semua();
})();
