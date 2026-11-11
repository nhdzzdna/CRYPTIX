/**
 * static/js/dokumen.js
 * ────────────────────
 * Halaman Dokumen: pencarian nama dan pengurutan (nama, tanggal, ukuran)
 * di sisi klien dari data yang sudah dirender server, plus modal pratinjau
 * (UB Bagian 3).
 *
 * Pratinjau diminta setelah grant ``doc.preview`` aktif — tombol Pratinjau
 * maupun dialog item terkunci keduanya berujung pada event
 * ``cryptix:reauth-grant`` ber-scope doc.preview. Respons teks dikirim
 * server sebagai JSON; gambar dan PDF dimuat sebagai blob di memori.
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

  var modal = document.getElementById('preview-modal');
  var judulModal = document.getElementById('preview-title');
  var panggungModal = document.getElementById('preview-stage');
  var tombolTutup = document.getElementById('preview-close');
  var urlBlob = null;

  function pesanModal(kunci, cadangan) {
    var teks = modal ? (modal.getAttribute('data-msg-' + kunci) || '') : '';
    return teks || cadangan;
  }

  // ── Pencarian dan urutan ─────────────────────────────────────────────

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

  function terapkan(wadah, sudahDilihat) {
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
      // Section "Semua" menduplikasi item "Tanpa folder"; saat mencari,
      // setiap hasil hanya tampil sekali (container lebih dulu menang).
      if (cocok && sudahDilihat) {
        var fid = kartuItem.getAttribute('data-file-id');
        if (fid && sudahDilihat[fid]) {
          cocok = false;
        } else if (fid) {
          sudahDilihat[fid] = true;
        }
      }
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
    var kueri = kotakCari.value.trim();
    var sudahDilihat = kueri ? Object.create(null) : null;
    Array.prototype.forEach.call(
      document.querySelectorAll('[data-doc-list]'), function (wadah) {
        var hasil = terapkan(wadah, sudahDilihat);
        total += hasil.total;
        tampil += hasil.tampil;
      });

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

  // ── Modal pratinjau (UB Bagian 3) ────────────────────────────────────

  if (!modal || !panggungModal) {
    return;
  }

  function tutupPratinjau() {
    modal.style.display = 'none';
    panggungModal.innerHTML = '';
    judulModal.textContent = '';
    if (urlBlob) {
      URL.revokeObjectURL(urlBlob);
      urlBlob = null;
    }
  }

  function galatPratinjau(pesan) {
    tutupPratinjau();
    var kotak = document.getElementById('collection-alert');
    if (kotak) {
      kotak.textContent = pesan || pesanModal('failed', 'Pratinjau gagal dimuat.');
      kotak.hidden = false;
    }
  }

  function pasangPanggung(elemen) {
    panggungModal.innerHTML = '';
    panggungModal.appendChild(elemen);
    modal.style.display = 'flex';
  }

  function tampilkanTeks(data) {
    var kotak = document.createElement('div');
    kotak.className = 'preview-text';
    var label = document.createElement('p');
    label.className = 'preview-text-meta';
    label.textContent = pesanModal('text-label', 'Isi teks') +
      ' · ' + (Number(data.size) || 0) + ' B' +
      (data.truncated ? ' · dipotong' : '');
    var isi = document.createElement('pre');
    isi.textContent = String(data.text || '');
    kotak.appendChild(label);
    kotak.appendChild(isi);
    judulModal.textContent = data.name || '';
    pasangPanggung(kotak);
  }

  function tampilkanBlob(blob, tipe) {
    urlBlob = URL.createObjectURL(blob);
    var elemen;
    if (tipe.indexOf('image/') === 0) {
      elemen = document.createElement('img');
      elemen.alt = judulModal.textContent || '';
    } else {
      elemen = document.createElement('iframe');
      elemen.setAttribute('title', 'Pratinjau dokumen');
    }
    elemen.src = urlBlob;
    pasangPanggung(elemen);
  }

  function bukaPratinjau(fileId, token) {
    var headers = { 'Accept': 'application/json, image/*, application/pdf' };
    if (token) {
      headers['X-Reauth-Grant'] = token;
    }
    apiFetch('/media-vault/preview/' + fileId, {
      method: 'GET',
      headers: headers,
      credentials: 'same-origin'
    }).then(function (resp) {
      var tipe = (resp.headers.get('Content-Type') || '')
        .split(';')[0].trim().toLowerCase();
      if (resp.status === 415) {
        return resp.json().catch(function () { return {}; }).then(function (data) {
          throw new Error(data.error ||
            pesanModal('unsupported', 'Jenis berkas ini tidak dapat dipratinjau.'));
        });
      }
      if (!resp.ok) {
        return resp.json().catch(function () { return {}; }).then(function (data) {
          throw new Error(data.error ||
            pesanModal('failed', 'Pratinjau gagal dimuat.'));
        });
      }
      if (tipe === 'application/json') {
        return resp.json().then(tampilkanTeks);
      }
      judulModal.textContent = '';
      return resp.blob().then(function (blob) {
        tampilkanBlob(blob, tipe);
      });
    }).catch(function (err) {
      galatPratinjau(err && err.message);
    });
  }

  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detail = event.detail || {};
    if (detail.scope !== 'doc.preview' || !detail.resource) {
      return;
    }
    bukaPratinjau(detail.resource, detail.token);
  });

  if (tombolTutup) {
    tombolTutup.addEventListener('click', tutupPratinjau);
  }
  modal.addEventListener('click', function (event) {
    if (event.target === modal) {
      tutupPratinjau();
    }
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && modal.style.display === 'flex') {
      tutupPratinjau();
    }
  });
})();
