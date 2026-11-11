/**
 * static/js/item_lock.js
 * ────────────────────────
 * Pengunci item generik (U2b P5) untuk Audio, Media, dan Dokumen.
 *
 * Menggunakan dialog modal berbasis KX.modal yang menerima scope
 * (item.view, item.unlock, doc.preview, album.unlock) dan resource id,
 * lalu memicu alur reauth yang sudah ada tanpa JavaScript inline.
 *
 * Kontrak:
 * - window.CryptixLock.mintaGrant(scope, resource) -> Promise<token>
 * - window.CryptixLock.lepasKunci(koleksiId, fileIds) -> Promise
 * - window.CryptixLock.pilih(kartu, saatLihat, scopeLihat) -> void
 */
(function () {
  'use strict';

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
      if (window.KX && window.KX.toast) {
        window.KX.toast(teks || 'Tindakan ditolak.', 'danger');
      }
      return;
    }
    kotak.textContent = teks || 'Tindakan ditolak.';
    kotak.hidden = false;
  }

  /**
   * Minta grant lewat modal reauth (tombol sintetis ber-atribut data-reauth).
   * Menjaga event 'cryptix:reauth-grant' dan mengembalikan Promise token.
   */
  function mintaGrant(scope, resource) {
    generasi += 1;
    var idKini = generasi;
    return new Promise(function (selesai, tolak) {
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
      pemicu.hidden = true;
      pemicu.setAttribute('data-reauth', scope);
      pemicu.setAttribute('data-reauth-resource', String(resource || ''));
      document.body.appendChild(pemicu);
      pemicu.click();
      document.body.removeChild(pemicu);
    });
  }

  /** Lepas kunci item: grant item.unlock (resource = id koleksi) -> state 'normal'. */
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
      if (window.KX && window.KX.modal) {
        window.KX.modal.tutup(dialog);
      } else {
        dialog.classList.remove('is-open');
        dialog.setAttribute('aria-hidden', 'true');
        dialog.style.display = 'none';
      }
    }
    saatKlik = null;
  }

  function buatDialog() {
    if (dialog) {
      return;
    }
    dialog = document.createElement('div');
    dialog.id = 'item-lock-modal';
    dialog.className = 'kx-modal-overlay modal-overlay';
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    dialog.setAttribute('aria-labelledby', 'item-lock-title');
    dialog.setAttribute('aria-hidden', 'true');

    var modal = document.createElement('div');
    modal.className = 'kx-modal item-lock-box';

    var kepala = document.createElement('div');
    kepala.className = 'kx-modal-head';

    var judul = document.createElement('h2');
    judul.id = 'item-lock-title';
    judul.className = 'kx-modal-title';
    judul.textContent = 'Item Terkunci';
    kepala.appendChild(judul);

    var tombolTutup = document.createElement('button');
    tombolTutup.type = 'button';
    tombolTutup.className = 'kx-btn kx-btn-icon';
    tombolTutup.setAttribute('data-kx-tutup', '');
    tombolTutup.setAttribute('aria-label', 'Tutup dialog');
    tombolTutup.textContent = '×';
    kepala.appendChild(tombolTutup);
    modal.appendChild(kepala);

    var badan = document.createElement('div');
    badan.className = 'kx-modal-body';

    teksKonteks = document.createElement('p');
    teksKonteks.className = 'kx-lock-text';
    badan.appendChild(teksKonteks);
    modal.appendChild(badan);

    var kaki = document.createElement('div');
    kaki.className = 'kx-modal-foot item-lock-actions';

    var tombolBatal = document.createElement('button');
    tombolBatal.type = 'button';
    tombolBatal.className = 'kx-btn kx-btn-secondary';
    tombolBatal.textContent = 'Batal';

    var tombolLepas = document.createElement('button');
    tombolLepas.type = 'button';
    tombolLepas.className = 'kx-btn kx-btn-secondary';
    tombolLepas.textContent = 'Lepas Kunci';

    var tombolLihat = document.createElement('button');
    tombolLihat.type = 'button';
    tombolLihat.className = 'kx-btn kx-btn-primary';
    tombolLihat.textContent = 'Buka & Putar Sekali';

    tombolBatal.addEventListener('click', tutupDialog);
    tombolTutup.addEventListener('click', tutupDialog);

    tombolLepas.addEventListener('click', function () {
      if (saatKlik) {
        saatKlik('lepas');
      }
    });

    tombolLihat.addEventListener('click', function () {
      if (saatKlik) {
        saatKlik('lihat');
      }
    });

    kaki.appendChild(tombolBatal);
    kaki.appendChild(tombolLepas);
    kaki.appendChild(tombolLihat);
    modal.appendChild(kaki);

    dialog.appendChild(modal);
    document.body.appendChild(dialog);

    dialog.addEventListener('click', function (event) {
      if (event.target === dialog) {
        tutupDialog();
      }
    });
  }

  /**
   * Buka dialog pilihan untuk item terkunci (generik).
   *
   * @param {Element} kartu - elemen pembawa data-file-id, data-collection-id, dan data-name
   * @param {Function} [saatLihat] - fungsi callback setelah grant aktif
   * @param {string} [scopeLihat] - scope reauth lihat (default item.view; halaman Dokumen memakai doc.preview)
   */
  function pilih(kartu, saatLihat, scopeLihat) {
    if (!kartu) {
      return;
    }
    buatDialog();
    var nama = kartu.getAttribute('data-name') || 'berkas ini';
    teksKonteks.textContent = '"' + nama + '" berstatus terkunci. Pilih tindakan:';

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
      var targetScope = scopeLihat || 'item.view';
      mintaGrant(targetScope, fid).then(function () {
        if (typeof saatLihat === 'function') {
          saatLihat(kartu);
        }
      });
    };

    if (window.KX && window.KX.modal) {
      window.KX.modal.buka(dialog);
    } else {
      dialog.classList.add('is-open');
      dialog.setAttribute('aria-hidden', 'false');
      dialog.style.display = 'flex';
    }
  }

  // Thumbnail gambar media yang 403 terkunci digantikan placeholder gembok
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
    var label = document.createElement('span');
    label.className = 'media-placeholder-label';
    label.textContent = 'Terkunci';
    kotak.appendChild(label);
    gambar.replaceWith(kotak);
  }, true);

  window.CryptixLock = {
    mintaGrant: mintaGrant,
    lepasKunci: lepasKunci,
    pilih: pilih
  };
})();
