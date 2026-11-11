/**
 * static/js/sampah.js
 * ────────────────────
 * Interaksi halaman Sampah: pilihan item, pengisian field ``items``
 * tersembunyi, dialog konfirmasi, dan pengiriman form setelah grant.
 *
 * Tombol Pulihkan mengirim form biasa. Tombol Hapus permanen dan Kosongkan
 * sampah memakai data-reauth="trash.purge": setelah grant diterbitkan,
 * reauth.js memancarkan event cryptix:reauth-grant; form baru dikirim
 * setelah pengguna mengonfirmasi dialog penghapusan.
 */
(function () {
  'use strict';

  var halaman = document.getElementById('trash-page');
  if (!halaman) {
    return;
  }

  var formPulih = document.getElementById('trash-restore-form');
  var formHapus = document.getElementById('trash-purge-form');
  var formKosong = document.getElementById('trash-empty-form');
  var isiPulih = document.getElementById('trash-items-restore');
  var isiPurge = document.getElementById('trash-items-purge');

  function pesan(kunci) {
    return halaman.getAttribute('data-msg-' + kunci) || '';
  }

  function itemTerpilih() {
    var hasil = [];
    var daftar = document.querySelectorAll('[data-trash-select-item]:checked');
    Array.prototype.forEach.call(daftar, function (cek) {
      hasil.push({
        jenis: cek.getAttribute('data-jenis') || '',
        id: cek.value
      });
    });
    return hasil;
  }

  function perbaruiPilihan() {
    var terpilih = itemTerpilih();
    var teks = JSON.stringify(terpilih);
    if (isiPulih) {
      isiPulih.value = teks;
    }
    if (isiPurge) {
      isiPurge.value = teks;
    }
    Array.prototype.forEach.call(
      document.querySelectorAll('[data-trash-select]'),
      function (tombol) {
        tombol.disabled = terpilih.length === 0;
      }
    );
  }

  document.addEventListener('change', function (event) {
    if (event.target.matches('[data-trash-select-item]')) {
      perbaruiPilihan();
    }
  });

  if (formPulih) {
    formPulih.addEventListener('submit', function (event) {
      if (!itemTerpilih().length) {
        event.preventDefault();
        window.alert(pesan('select-required'));
      }
    });
  }

  var aksiTertunda = null;

  function catatIntent(tombol) {
    aksiTertunda = tombol.id === 'trash-purge-button' ? 'hapus' : 'kosongkan';
  }

  function tombolAksi(target) {
    if (!target || !target.closest) {
      return null;
    }
    return target.closest('#trash-purge-button, #trash-empty-button');
  }

  document.addEventListener('pointerdown', function (event) {
    var tombol = tombolAksi(event.target);
    if (tombol) {
      catatIntent(tombol);
    }
  }, true);

  document.addEventListener('keydown', function (event) {
    if (event.key !== 'Enter' && event.key !== ' ') {
      return;
    }
    var tombol = tombolAksi(event.target);
    if (tombol) {
      catatIntent(tombol);
    }
  });

  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detail = event.detail || {};
    if (detail.scope !== 'trash.purge' || !aksiTertunda) {
      return;
    }
    var aksi = aksiTertunda;
    aksiTertunda = null;

    if (aksi === 'hapus' && !itemTerpilih().length) {
      window.alert(pesan('select-required'));
      return;
    }
    var konfirmasi = aksi === 'hapus'
      ? pesan('purge-confirm')
      : pesan('empty-confirm');
    if (!window.confirm(konfirmasi)) {
      return;
    }

    perbaruiPilihan();
    var form = aksi === 'hapus' ? formHapus : formKosong;
    if (!form) {
      return;
    }
    var grant = form.querySelector('input[name="reauth_grant"]');
    if (!grant) {
      grant = document.createElement('input');
      grant.type = 'hidden';
      grant.name = 'reauth_grant';
      form.appendChild(grant);
    }
    grant.value = detail.token || '';
    form.submit();
  });

  perbaruiPilihan();
})();
