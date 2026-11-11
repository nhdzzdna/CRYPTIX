/**
 * static/js/media_albums.js
 * ─────────────────────────
 * Galeri album Media Vault (U2b P6):
 * - Membuka album, memuat isi via API, penampil media (KX.modal) untuk gambar & video
 * - Pemilihan banyak berkas dan sinkronisasi dengan KX.aksiMengambang
 * - Pencarian media lokal di sisi klien
 * - Aksi menu titik tiga (⋯): Lihat, Unduh, Pindahkan, Hapus (ke Sampah via KX.konfirmasiHapus)
 * - Integrasi pengunci item generik item_lock.js (scope item.view)
 */
(function () {
  'use strict';

  var detail = document.getElementById('album-detail');
  if (!detail) {
    return;
  }

  var kotakPesan = document.getElementById('media-messages');
  var kotakGalat = document.getElementById('media-alert');
  var judulAlbum = document.getElementById('album-detail-title');
  var daftarItem = document.getElementById('album-items');
  var tombolKunciAlbum = document.getElementById('album-lock-toggle');
  var tombolKembali = document.getElementById('album-back');
  var tombolGantiNamaAlbum = document.getElementById('album-rename');
  var formGantiNamaAlbum = document.getElementById('album-rename-form');
  var inputGantiNamaAlbum = document.getElementById('album-rename-input');
  var tombolHapusAlbum = document.getElementById('album-delete');
  var bilahPilih = document.getElementById('selection-bar');
  var jumlahPilih = document.getElementById('selection-count');
  var targetPindah = document.getElementById('move-target');
  var tombolPindah = document.getElementById('move-button');
  var tombolKunciItem = document.getElementById('lock-items-button');
  var tombolLepasItem = document.getElementById('unlock-items-button');
  var formBuatAlbum = document.getElementById('album-create-form');
  var inputBuatAlbum = document.getElementById('album-create-name');
  var cekBuatTerkunci = document.getElementById('album-create-locked');
  var pemuatAlbum = document.getElementById('album-loading');
  var kosongAlbum = document.getElementById('album-empty');

  var penampil = document.getElementById('media-viewer');
  var panggung = document.getElementById('viewer-stage');
  var judulPenampil = document.getElementById('viewer-title');
  var tombolTutupPenampil = document.getElementById('viewer-close');
  var tombolSebelum = document.getElementById('viewer-prev');
  var tombolSesudah = document.getElementById('viewer-next');
  var tombolGantiNamaBerkas = document.getElementById('viewer-rename');
  var formGantiNamaBerkas = document.getElementById('viewer-rename-form');
  var inputGantiNamaBerkas = document.getElementById('viewer-rename-input');
  var kotakCariMedia = document.getElementById('media-search');

  var albumAktif = null;
  var albumTerkunci = false;
  var daftarPenampil = [];
  var indeksPenampil = 0;
  var kartuAktif = null;
  var intent = null;

  function pesan(kunci) {
    return kotakPesan ? (kotakPesan.getAttribute('data-msg-' + kunci) || '') : '';
  }

  function tampilkanGalat(teks) {
    if (!kotakGalat) {
      if (window.KX && window.KX.toast) {
        window.KX.toast(teks || pesan('error'), 'danger');
      }
      return;
    }
    kotakGalat.textContent = teks || pesan('error');
    kotakGalat.hidden = false;
  }

  function bersihkanGalat() {
    if (!kotakGalat) return;
    kotakGalat.textContent = '';
    kotakGalat.hidden = true;
  }

  function grantUntuk(scope, resource) {
    if (!window.CryptixReauth || typeof window.CryptixReauth.grantFor !== 'function') {
      return null;
    }
    return window.CryptixReauth.grantFor(scope, resource);
  }

  function urai(resp) {
    return resp.json().catch(function () { return {}; }).then(function (data) {
      if (!resp.ok || data.success === false) {
        throw new Error(data.error || pesan('error'));
      }
      return data;
    });
  }

  function ambil(url, grant) {
    var headers = {};
    if (grant) headers['X-Reauth-Grant'] = grant;
    return apiFetch(url, {
      method: 'GET',
      headers: headers,
      credentials: 'same-origin'
    }).then(urai);
  }

  function kirim(url, data, grant) {
    var headers = { 'Content-Type': 'application/json' };
    if (grant) headers['X-Reauth-Grant'] = grant;
    return apiFetch(url, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(data || {}),
      credentials: 'same-origin'
    }).then(urai);
  }

  function ukuranTeks(bita) {
    var n = Number(bita) || 0;
    if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1024).toFixed(1) + ' KB';
  }

  // ── Buat kartu dinamis untuk isi album ────────────────────────────────────
  function buatKartu(item, albumId) {
    var terkunci = item.state === 'locked';
    var kartu = document.createElement('div');
    kartu.className = 'kx-media-card media-item' + (terkunci ? ' item-terkunci' : '');
    kartu.setAttribute('data-media-item', '');
    kartu.setAttribute('data-file-id', String(item.id));
    kartu.setAttribute('data-kind', item.file_type);
    kartu.setAttribute('data-name', item.name);
    kartu.setAttribute('data-view-url', item.view_url || '');
    kartu.setAttribute('data-thumb-url', item.thumb_url || '');
    kartu.setAttribute('data-locked', terkunci ? '1' : '0');
    kartu.setAttribute('data-collection-id', String(albumId || ''));

    var labelPilih = document.createElement('label');
    labelPilih.className = 'kx-media-card-select media-select';
    labelPilih.title = 'Pilih ' + item.name;
    var inputCek = document.createElement('input');
    inputCek.type = 'checkbox';
    inputCek.className = 'kx-checkbox';
    inputCek.setAttribute('data-select-file', '');
    inputCek.setAttribute('data-kx-pilih', '');
    inputCek.value = String(item.id);
    labelPilih.appendChild(inputCek);
    kartu.appendChild(labelPilih);

    var tombolBuka = document.createElement('button');
    tombolBuka.type = 'button';
    tombolBuka.className = 'kx-media-card-thumb-btn media-open';
    tombolBuka.setAttribute('data-open-media', '');
    tombolBuka.title = 'Buka ' + item.name;

    if (item.thumb_url) {
      var img = document.createElement('img');
      img.className = 'kx-media-card-thumb-img media-thumb';
      img.src = item.thumb_url;
      img.alt = item.name;
      img.loading = 'lazy';
      tombolBuka.appendChild(img);
    } else {
      var ph = document.createElement('span');
      ph.textContent = item.file_type === 'video' ? 'Video' : 'Media';
      tombolBuka.appendChild(ph);
    }

    if (item.file_type === 'video') {
      var vOverlay = document.createElement('span');
      vOverlay.className = 'kx-media-video-overlay';
      vOverlay.textContent = '▶';
      tombolBuka.appendChild(vOverlay);
    }
    if (terkunci) {
      var lOverlay = document.createElement('span');
      lOverlay.className = 'kx-media-lock-overlay item-lock-overlay';
      lOverlay.textContent = '🔒';
      tombolBuka.appendChild(lOverlay);
    }
    kartu.appendChild(tombolBuka);

    var info = document.createElement('div');
    info.className = 'kx-media-card-info';

    var nama = document.createElement('span');
    nama.className = 'kx-media-card-name media-name';
    nama.title = item.name;
    nama.textContent = item.name;
    info.appendChild(nama);

    var meta = document.createElement('div');
    meta.className = 'kx-media-card-meta media-meta';
    meta.textContent = ukuranTeks(item.file_size) + ' · ' + String(item.uploaded_at || '').slice(0, 16);
    if (terkunci) {
      var badgeKunci = document.createElement('span');
      badgeKunci.className = 'kx-badge kx-badge-warn item-lock-note';
      badgeKunci.textContent = 'Terkunci';
      meta.appendChild(badgeKunci);
    }
    info.appendChild(meta);

    var aksiBawah = document.createElement('div');
    aksiBawah.className = 'kx-media-card-actions';

    var btnLihat = document.createElement('button');
    btnLihat.type = 'button';
    btnLihat.className = 'kx-btn kx-btn-secondary kx-btn-sm';
    btnLihat.setAttribute('data-open-media', '');
    btnLihat.textContent = 'Lihat';
    aksiBawah.appendChild(btnLihat);

    info.appendChild(aksiBawah);
    kartu.appendChild(info);
    return kartu;
  }

  function isiDaftar(wadah, daftar, albumId) {
    if (!wadah) return;
    wadah.innerHTML = '';
    (daftar || []).forEach(function (item) {
      wadah.appendChild(buatKartu(item, albumId));
    });
    perbaruiPilihan();
    document.dispatchEvent(new CustomEvent('collection:items-loaded', {
      detail: { container: wadah }
    }));
  }

  function bukaAlbum(id, nama, terkunci) {
    albumAktif = String(id);
    albumTerkunci = Boolean(terkunci);
    detail.hidden = false;
    judulAlbum.textContent = nama || '';
    tombolKunciAlbum.textContent = albumTerkunci ? 'Buka kunci album' : 'Kunci album';
    tombolKunciAlbum.setAttribute('data-reauth-resource', String(id));
    formGantiNamaAlbum.hidden = true;
    daftarItem.innerHTML = '';
    if (pemuatAlbum) pemuatAlbum.hidden = false;
    if (kosongAlbum) kosongAlbum.hidden = true;
    bersihkanGalat();

    var grant = albumTerkunci ? grantUntuk('album.unlock', String(id)) : null;
    if (albumTerkunci && !grant) {
      if (pemuatAlbum) pemuatAlbum.hidden = true;
      tampilkanGalat(pesan('error'));
      return;
    }

    ambil('/api/collections/' + id + '/items', grant).then(function (data) {
      var daftar = data.items || [];
      isiDaftar(daftarItem, daftar, id);
      if (pemuatAlbum) pemuatAlbum.hidden = true;
      if (kosongAlbum) kosongAlbum.hidden = daftar.length > 0;
      detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }).catch(function (err) {
      if (pemuatAlbum) pemuatAlbum.hidden = true;
      tampilkanGalat(err.message);
    });
  }

  function perbaruiPilihan() {
    var terpilih = document.querySelectorAll('[data-select-file]:checked');
    var jumlah = terpilih.length;
    if (bilahPilih) bilahPilih.hidden = jumlah === 0;
    if (jumlahPilih) jumlahPilih.textContent = jumlah + ' dipilih';

    var koleksi = null;
    var sah = jumlah > 0;
    Array.prototype.forEach.call(terpilih, function (cek) {
      var kartu = cek.closest('[data-collection-id]');
      var id = kartu ? kartu.getAttribute('data-collection-id') : '';
      if (!id) {
        sah = false;
        return;
      }
      if (koleksi === null) koleksi = id;
      else if (koleksi !== id) sah = false;
    });

    if (tombolKunciItem) {
      tombolKunciItem.removeAttribute('data-reauth');
      tombolKunciItem.removeAttribute('data-reauth-resource');
    }
    if (tombolLepasItem) {
      if (sah && koleksi) {
        tombolLepasItem.setAttribute('data-reauth', 'item.unlock');
        tombolLepasItem.setAttribute('data-reauth-resource', koleksi);
      } else {
        tombolLepasItem.removeAttribute('data-reauth');
        tombolLepasItem.removeAttribute('data-reauth-resource');
      }
    }

    if (targetPindah && tombolPindah) {
      var opsi = targetPindah.options[targetPindah.selectedIndex];
      var targetTerkunci = opsi && opsi.getAttribute('data-locked') === '1';
      if (targetTerkunci) {
        tombolPindah.setAttribute('data-reauth', 'album.unlock');
        tombolPindah.setAttribute('data-reauth-resource', opsi.value);
      } else {
        tombolPindah.removeAttribute('data-reauth');
        tombolPindah.removeAttribute('data-reauth-resource');
      }
    }

    if (window.KX && window.KX.aksiMengambang) {
      window.KX.aksiMengambang.segarkan();
    }
  }

  function idTerpilih() {
    var hasil = [];
    document.querySelectorAll('[data-select-file]:checked').forEach(function (cek) {
      hasil.push(Number(cek.value));
    });
    return hasil;
  }

  function pindahkan() {
    var ids = idTerpilih();
    if (!ids.length) return;
    var target = targetPindah ? targetPindah.value : '';
    var grant = target ? grantUntuk('album.unlock', target) : null;
    kirim('/api/collections/move', {
      file_ids: ids,
      collection_id: target || null
    }, grant).then(function () {
      window.location.reload();
    }).catch(function (err) {
      tampilkanGalat(err.message);
    });
  }

  function ubahStatus(state, grant) {
    var ids = idTerpilih();
    var cek = document.querySelector('[data-select-file]:checked');
    var kartu = cek ? cek.closest('[data-collection-id]') : null;
    var koleksi = kartu ? kartu.getAttribute('data-collection-id') : '';
    if (!ids.length || !koleksi) {
      tampilkanGalat(pesan('need-collection'));
      return null;
    }
    return kirim('/api/collections/' + koleksi + '/items/state', {
      file_ids: ids,
      state: state
    }, state === 'normal' ? grant : null).then(function () {
      window.location.reload();
    }).catch(function (err) {
      tampilkanGalat(err.message);
    });
  }

  // ── Penampil Media (KX.modal) ─────────────────────────────────────────────
  function tutupPenampil() {
    if (!penampil) return;
    if (window.KX && window.KX.modal) {
      window.KX.modal.tutup(penampil);
    } else {
      penampil.classList.remove('is-open');
      penampil.style.display = 'none';
      penampil.setAttribute('aria-hidden', 'true');
    }
    if (panggung) {
      var v = panggung.querySelector('video');
      if (v) {
        v.pause();
        v.removeAttribute('src');
      }
      panggung.innerHTML = '';
    }
    kartuAktif = null;
  }

  function tampilkanMediaDiPanggung(kartu) {
    if (!panggung || !kartu) return;
    panggung.innerHTML = '';
    var jenis = kartu.getAttribute('data-kind');
    var url = kartu.getAttribute('data-view-url');
    var nama = kartu.getAttribute('data-name');
    if (judulPenampil) judulPenampil.textContent = nama || '';

    if (jenis === 'video') {
      var v = document.createElement('video');
      v.controls = true;
      v.src = url;
      v.autoplay = true;
      panggung.appendChild(v);
    } else {
      var img = document.createElement('img');
      img.src = url;
      img.alt = nama;
      panggung.appendChild(img);
    }
  }

  function bukaPenampil(kartu) {
    if (!kartu || !penampil) return;
    kartuAktif = kartu;
    var wadah = kartu.closest('.kx-media-grid, .media-grid');
    daftarPenampil = wadah
      ? Array.prototype.slice.call(wadah.querySelectorAll('[data-media-item]'))
      : [kartu];
    indeksPenampil = daftarPenampil.indexOf(kartu);

    tampilkanMediaDiPanggung(kartu);

    if (window.KX && window.KX.modal) {
      window.KX.modal.buka(penampil);
    } else {
      penampil.classList.add('is-open');
      penampil.style.display = 'flex';
      penampil.setAttribute('aria-hidden', 'false');
    }
  }

  function geserPenampil(arah) {
    if (!daftarPenampil.length) return;
    indeksPenampil = (indeksPenampil + arah + daftarPenampil.length) % daftarPenampil.length;
    var kartu = daftarPenampil[indeksPenampil];
    if (kartu.getAttribute('data-locked') === '1'
        && !grantUntuk('item.view', kartu.getAttribute('data-file-id'))) {
      if (window.CryptixLock) {
        window.CryptixLock.pilih(kartu, bukaPenampil, 'item.view');
      }
      return;
    }
    bukaPenampil(kartu);
  }

  // ── Event Listener ───────────────────────────────────────────────────────
  document.addEventListener('click', function (event) {
    // Menu titik tiga (⋯)
    var btnMenu = event.target.closest('[data-menu-toggle]');
    var semuaMenu = document.querySelectorAll('[data-menu-dropdown]');
    if (btnMenu) {
      event.stopPropagation();
      var wrap = btnMenu.closest('.kx-media-menu-wrap');
      var dd = wrap ? wrap.querySelector('[data-menu-dropdown]') : null;
      var isOpen = dd && !dd.hidden;
      semuaMenu.forEach(function (m) { m.hidden = true; });
      if (dd) dd.hidden = isOpen;
      return;
    }
    semuaMenu.forEach(function (m) { m.hidden = true; });

    // Buka media penampil
    var buka = event.target.closest('[data-open-media]');
    if (buka) {
      var kartu = buka.closest('[data-media-item]');
      if (kartu && kartu.getAttribute('data-locked') === '1'
          && !grantUntuk('item.view', kartu.getAttribute('data-file-id'))) {
        if (window.CryptixLock) {
          window.CryptixLock.pilih(kartu, bukaPenampil, 'item.view');
        }
        return;
      }
      if (kartu) bukaPenampil(kartu);
      return;
    }

    // Buka album
    var album = event.target.closest('[data-album-open]');
    if (album && album.getAttribute('data-album-locked') !== '1') {
      bukaAlbum(album.getAttribute('data-album-id'), album.getAttribute('data-album-name'), false);
      return;
    }

    if (event.target === tombolKembali) {
      detail.hidden = true;
      albumAktif = null;
      return;
    }

    if (event.target === tombolPindah) {
      pindahkan();
      return;
    }

    if (event.target === tombolKunciItem) {
      ubahStatus('locked');
      return;
    }

    if (event.target === tombolLepasItem) {
      tampilkanGalat(pesan('need-collection'));
      return;
    }

    if (event.target === tombolTutupPenampil) {
      tutupPenampil();
      return;
    }

    if (event.target === tombolSebelum) {
      geserPenampil(-1);
      return;
    }

    if (event.target === tombolSesudah) {
      geserPenampil(1);
      return;
    }

    if (event.target === tombolHapusAlbum && albumAktif) {
      if (!window.confirm(pesan('delete-confirm'))) return;
      kirim('/api/collections/' + albumAktif + '/delete', {}).then(function () {
        window.location.reload();
      }).catch(function (err) {
        tampilkanGalat(err.message);
      });
      return;
    }
  });

  // Hapus via KX.konfirmasiHapus
  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || !form.action || form.action.indexOf('/vault/delete/') === -1) {
      return;
    }
    if (form.getAttribute('data-kx-confirmed') === '1') {
      return;
    }

    event.preventDefault();
    var baris = form.closest('[data-media-item]');
    var namaItem = baris ? baris.getAttribute('data-name') : 'media ini';

    if (window.KX && typeof window.KX.konfirmasiHapus === 'function') {
      window.KX.konfirmasiHapus({
        judul: 'Pindahkan ke Sampah?',
        nama: namaItem,
        pesan: 'Media {nama} akan dipindahkan ke Sampah. Anda masih dapat memulihkannya dari sana.',
        labelTombol: 'Pindahkan',
        onKonfirmasi: function () {
          form.setAttribute('data-kx-confirmed', '1');
          form.submit();
        }
      });
    } else {
      if (window.confirm('Pindahkan ' + namaItem + ' ke Sampah?')) {
        form.setAttribute('data-kx-confirmed', '1');
        form.submit();
      }
    }
  });

  // Pencarian media di sisi klien
  if (kotakCariMedia) {
    kotakCariMedia.addEventListener('input', function () {
      var kueri = kotakCariMedia.value.trim().toLowerCase();
      var kartuList = document.querySelectorAll('[data-media-item]');
      kartuList.forEach(function (card) {
        var nama = (card.getAttribute('data-name') || '').toLowerCase();
        var cocok = !kueri || nama.indexOf(kueri) !== -1;
        card.hidden = !cocok;
      });
      var pesanTakAda = document.getElementById('media-no-results');
      if (pesanTakAda) {
        var adaYangTampil = Array.prototype.some.call(kartuList, function (c) { return !c.hidden; });
        pesanTakAda.hidden = kartuList.length === 0 || adaYangTampil;
      }
    });
  }

  // Checkbox pilihan berkas
  document.addEventListener('change', function (event) {
    if (event.target.matches('[data-select-file]')) {
      perbaruiPilihan();
    } else if (event.target === targetPindah) {
      perbaruiPilihan();
    }
  });

  // Reauth Grant listener
  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detailGrant = event.detail || {};
    var scope = detailGrant.scope;
    if (!intent) return;
    if (scope === 'album.unlock') {
      if (intent.jenis === 'album') {
        bukaAlbum(intent.id, intent.nama, intent.terkunci);
      } else if (intent.jenis === 'pindah') {
        pindahkan();
      }
    } else if (scope === 'item.unlock' && intent.jenis === 'status') {
      ubahStatus(intent.state, detailGrant.token);
    }
    intent = null;
  });

  document.addEventListener('pointerdown', function (event) {
    var pemicu = event.target.closest('[data-reauth], [data-album-open]');
    if (pemicu) {
      intent = null;
      if (pemicu.hasAttribute('data-album-open')) {
        intent = {
          jenis: 'album',
          id: pemicu.getAttribute('data-album-id'),
          nama: pemicu.getAttribute('data-album-name'),
          terkunci: pemicu.getAttribute('data-album-locked') === '1'
        };
      } else if (pemicu.id === 'move-button') {
        intent = { jenis: 'pindah' };
      }
    }
  }, true);

  if (formBuatAlbum) {
    formBuatAlbum.addEventListener('submit', function (event) {
      event.preventDefault();
      var nama = inputBuatAlbum ? inputBuatAlbum.value.trim() : '';
      if (!nama) {
        tampilkanGalat(pesan('error'));
        return;
      }
      kirim('/api/collections', {
        name: nama,
        kind: 'album',
        locked: cekBuatTerkunci && cekBuatTerkunci.checked
      }).then(function () {
        window.location.reload();
      }).catch(function (err) {
        tampilkanGalat(err.message);
      });
    });
  }

  // Sinkronisasi pilihan awal
  function sinkronPilihan() {
    document.querySelectorAll('[data-select-file]').forEach(function (cb) {
      if (!cb.hasAttribute('data-kx-pilih')) {
        cb.setAttribute('data-kx-pilih', '');
      }
    });
    if (window.KX && window.KX.aksiMengambang) {
      window.KX.aksiMengambang.segarkan();
    }
  }

  document.addEventListener('collection:items-loaded', sinkronPilihan);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', sinkronPilihan);
  } else {
    sinkronPilihan();
  }
})();
