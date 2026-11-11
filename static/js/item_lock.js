/**
 * static/js/item_lock.js
 * ────────────────────────
 * Interaksi item terkunci (UB Bagian 2) untuk halaman Media, Musik, dan
 * Dokumen.
 *
 * • Klik item terkunci membuka dialog pilihan: "Lihat sekali" (grant
 *   ``item.view``/``doc.preview`` lalu tampilkan), "Lepas kunci" (grant
 *   sekali pakai ``item.unlock`` untuk koleksi lalu state 'normal'), atau
 *   batal. Dialog tampil lebih dulu supaya hanya satu verifikasi ulang
 *   yang sesuai aksi berlangsung.
 * • Thumbnail item terkunci ditolak server dengan 403; galat pemuatan
 *   gambar ditangkap di fase capture dan diganti placeholder gembok.
 * • Grant diminta lewat tombol sintetis ber-atribut data-reauth sehingga
 *   modal reauth.js dipakai tanpa menyalin logikanya; hasilnya diterima
 *   lewat event ``cryptix:reauth-grant``.
 */
(function () {
  'use strict';

  var IKON_KUNCI =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" ' +
    'stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/>' +
    '<path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15" r="1.2"/></svg>';

  var dialog = null;
  var teksKonteks = null;
  var saatKlik = null;
  var generasi = 0;

  function kotakGalat() {
    return document.getElementById('collection-alert') ||
      document.getElementById('media-alert');
  }

  function tampilkanGalat(teks) {
    var kotak = kotakGalat();
    if (!kotak) {
      return;
    }
    kotak.textContent = teks || 'Tindakan ditolak.';
    kotak.hidden = false;
  }

  /**
   * Minta grant lewat modal reauth (tombol sintetis ber-atribut data-reauth).
   * Tombol diklik secara programatik sehingga reauth.js menangani kedua
   * kasus — grant masih tersimpan klien (event langsung terkirim) atau perlu
   * verifikasi ulang lewat modal. Promise hanya selesai bila grant untuk
   * scope+resource itu diterbitkan; permintaan lama hangus ketika permintaan
   * baru dimulai.
   */
  function mintaGrant(scope, resource) {
    generasi += 1;
    var idKini = generasi;
    return new Promise(function (selesai) {
      var penangan = function (event) {
        var detail = event.detail || {};
        if (detail.scope !== scope ||
            String(detail.resource || '') !== String(resource || '')) {
          return;
        }
        document.removeEventListener('cryptix:reauth-grant', penangan);
        if (idKini === generasi) {
          selesai(detail.token);
        }
      };
      document.addEventListener('cryptix:reauth-grant', penangan);

      var pemicu = document.createElement('button');
      pemicu.type = 'button';
      pemicu.style.display = 'none';
      pemicu.setAttribute('data-reauth', scope);
      pemicu.setAttribute('data-reauth-resource', String(resource || ''));
      document.body.appendChild(pemicu);
      pemicu.click();
      document.body.removeChild(pemicu);
    });
  }

  /** Lepas kunci item: grant item.unlock (kol. id koleksi) → state normal. */
  function lepasKunci(koleksiId, fileIds) {
    return mintaGrant('item.unlock', koleksiId).then(function (token) {
      return apiFetch('/api/collections/' + koleksiId + '/items/state', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Reauth-Grant': token
        },
        credentials: 'same-origin',
        body: JSON.stringify({ file_ids: fileIds, state: 'normal' })
      }).then(function (resp) {
        return resp.json().catch(function () { return {}; }).then(function (data) {
          if (!resp.ok || data.success === false) {
            throw new Error(data.error || 'Lepas kunci gagal.');
          }
          window.location.reload();
        });
      });
    }).catch(function (err) {
      tampilkanGalat(err && err.message ? err.message : 'Lepas kunci gagal.');
    });
  }

  function tutupDialog() {
    if (dialog) {
      dialog.style.display = 'none';
    }
    saatKlik = null;
  }

  function buatDialog() {
    if (dialog) {
      return;
    }
    dialog = document.createElement('div');
    dialog.id = 'item-lock-modal';
    dialog.className = 'modal-overlay';
    dialog.style.display = 'none';
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    dialog.setAttribute('aria-labelledby', 'item-lock-title');

    var kotak = document.createElement('div');
    kotak.className = 'modal-box item-lock-box';

    var judul = document.createElement('h2');
    judul.id = 'item-lock-title';
    judul.className = 'mb-3';
    judul.textContent = 'Item terkunci';
    kotak.appendChild(judul);

    teksKonteks = document.createElement('p');
    teksKonteks.className = 'text-muted mb-3';
    kotak.appendChild(teksKonteks);

    var baris = document.createElement('div');
    baris.className = 'd-flex gap-2 mt-3 item-lock-actions';

    var tombolLihat = document.createElement('button');
    tombolLihat.type = 'button';
    tombolLihat.className = 'btn btn-primary';
    tombolLihat.textContent = 'Lihat sekali';

    var tombolLepas = document.createElement('button');
    tombolLepas.type = 'button';
    tombolLepas.className = 'btn btn-secondary';
    tombolLepas.textContent = 'Lepas kunci';

    var tombolBatal = document.createElement('button');
    tombolBatal.type = 'button';
    tombolBatal.className = 'btn btn-secondary';
    tombolBatal.textContent = 'Batal';

    tombolLihat.addEventListener('click', function () {
      if (saatKlik) {
        saatKlik('lihat');
      }
    });
    tombolLepas.addEventListener('click', function () {
      if (saatKlik) {
        saatKlik('lepas');
      }
    });
    tombolBatal.addEventListener('click', tutupDialog);

    baris.appendChild(tombolLihat);
    baris.appendChild(tombolLepas);
    baris.appendChild(tombolBatal);
    kotak.appendChild(baris);
    dialog.appendChild(kotak);
    document.body.appendChild(dialog);

    dialog.addEventListener('click', function (event) {
      if (event.target === dialog) {
        tutupDialog();
      }
    });
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && dialog.style.display === 'flex') {
        tutupDialog();
      }
    });
  }

  /**
   * Buka dialog pilihan untuk satu item terkunci.
   *
   * @param {Element} kartu       elemen dengan data-file-id/-collection-id
   * @param {Function} [saatLihat] dipanggil dengan kartu setelah grant lihat aktif
   * @param {string} [scopeLihat] scope verifikasi lihat (default item.view;
   *                              halaman Dokumen memakai doc.preview)
   */
  function pilih(kartu, saatLihat, scopeLihat) {
    if (!kartu) {
      return;
    }
    buatDialog();
    var nama = kartu.getAttribute('data-name') || 'berkas ini';
    teksKonteks.textContent = '"' + nama + '" terkunci. Pilih tindakan:';
    dialog.style.display = 'flex';

    var fid = kartu.getAttribute('data-file-id');
    var koleksi = kartu.getAttribute('data-collection-id') || '';

    saatKlik = function (aksi) {
      tutupDialog();
      if (aksi === 'lepas') {
        if (!koleksi) {
          tampilkanGalat('Item di luar album tidak dapat dilepas kuncinya.');
          return;
        }
        lepasKunci(koleksi, [Number(fid)]);
        return;
      }
      mintaGrant(scopeLihat || 'item.view', fid).then(function () {
        if (typeof saatLihat === 'function') {
          saatLihat(kartu);
        }
      });
    };
  }

  // Thumbnail item terkunci dijawab 403 oleh server; ganti placeholder.
  document.addEventListener('error', function (event) {
    var gambar = event.target;
    if (!gambar || !gambar.matches || !gambar.matches('img.media-thumb')) {
      return;
    }
    var kartu = gambar.closest('[data-media-item]');
    if (!kartu || kartu.getAttribute('data-locked') !== '1') {
      return;
    }
    var kotak = document.createElement('span');
    kotak.className = 'media-placeholder media-placeholder-locked';
    var ikon = document.createElement('span');
    ikon.className = 'media-placeholder-icon';
    ikon.setAttribute('aria-hidden', 'true');
    ikon.innerHTML = IKON_KUNCI;
    var label = document.createElement('span');
    label.className = 'media-placeholder-label';
    label.textContent = 'Terkunci';
    kotak.appendChild(ikon);
    kotak.appendChild(label);
    gambar.replaceWith(kotak);
  }, true);

  window.CryptixLock = {
    mintaGrant: mintaGrant,
    lepasKunci: lepasKunci,
    pilih: pilih
  };
})();
