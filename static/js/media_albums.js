/**
 * static/js/media_albums.js
 * ─────────────────────────
 * Galeri album Media Vault: daftar isi album, penampil media, pemilihan
 * banyak berkas, serta tindakan yang memerlukan grant album.unlock.
 *
 * Tidak ada data rahasia di DOM: URL pratinjau hanya ada pada album yang
 * boleh dilihat; item terkunci/tersembunyi dimuat setelah grant diterbitkan.
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
  var bagianTersembunyi = document.getElementById('album-hidden');
  var daftarTersembunyi = document.getElementById('album-hidden-items');
  var tombolTersembunyi = document.getElementById('album-hidden-open');
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
  var tombolSembunyiItem = document.getElementById('hide-items-button');
  var formBuatAlbum = document.getElementById('album-create-form');
  var inputBuatAlbum = document.getElementById('album-create-name');
  var cekBuatTerkunci = document.getElementById('album-create-locked');

  var penampil = document.getElementById('media-viewer');
  var panggung = document.getElementById('viewer-stage');
  var judulPenampil = document.getElementById('viewer-title');
  var tombolTutupPenampil = document.getElementById('viewer-close');
  var tombolSebelum = document.getElementById('viewer-prev');
  var tombolSesudah = document.getElementById('viewer-next');
  var tombolGantiNamaBerkas = document.getElementById('viewer-rename');
  var formGantiNamaBerkas = document.getElementById('viewer-rename-form');
  var inputGantiNamaBerkas = document.getElementById('viewer-rename-input');

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
      return;
    }
    kotakGalat.textContent = teks || pesan('error');
    kotakGalat.hidden = false;
  }

  function bersihkanGalat() {
    if (!kotakGalat) {
      return;
    }
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
    return resp.json().catch(function () {
      return {};
    }).then(function (data) {
      if (!resp.ok || data.success === false) {
        throw new Error(data.error || pesan('error'));
      }
      return data;
    });
  }

  function ambil(url, grant) {
    var headers = {};
    if (grant) {
      headers['X-Reauth-Grant'] = grant;
    }
    return apiFetch(url, {
      method: 'GET',
      headers: headers,
      credentials: 'same-origin'
    }).then(urai);
  }

  function kirim(url, data, grant) {
    var headers = { 'Content-Type': 'application/json' };
    if (grant) {
      headers['X-Reauth-Grant'] = grant;
    }
    return apiFetch(url, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(data || {}),
      credentials: 'same-origin'
    }).then(urai);
  }

  function buatKartu(item, albumId) {
    var kartu = document.createElement('div');
    kartu.className = 'media-item';
    kartu.setAttribute('data-media-item', '');
    kartu.setAttribute('data-file-id', String(item.id));
    kartu.setAttribute('data-kind', item.file_type);
    kartu.setAttribute('data-name', item.name);
    kartu.setAttribute('data-view-url', item.view_url);
    kartu.setAttribute('data-thumb-url', item.thumb_url || '');
    kartu.setAttribute('data-locked', item.state === 'locked' ? '1' : '0');
    kartu.setAttribute('data-collection-id', String(albumId || ''));

    var label = document.createElement('label');
    label.className = 'media-select';
    label.title = 'Pilih';
    var cek = document.createElement('input');
    cek.type = 'checkbox';
    cek.setAttribute('data-select-file', '');
    cek.value = String(item.id);
    label.appendChild(cek);
    kartu.appendChild(label);

    var tombol = document.createElement('button');
    tombol.type = 'button';
    tombol.className = 'media-open';
    tombol.setAttribute('data-open-media', '');
    if (item.thumb_url) {
      var gambar = document.createElement('img');
      gambar.className = 'media-thumb';
      gambar.src = item.thumb_url;
      gambar.alt = item.name;
      tombol.appendChild(gambar);
    } else {
      var kotak = document.createElement('span');
      kotak.className = 'media-placeholder';
      kotak.style.background = 'hsl(' + ((item.id * 47) % 360) + ', 45%, 42%)';
      kotak.textContent = item.state === 'locked' ? '🔒' : item.icon;
      tombol.appendChild(kotak);
    }
    kartu.appendChild(tombol);

    var ket = document.createElement('div');
    ket.className = 'media-caption';
    var ikon = document.createElement('span');
    ikon.className = 'media-icon';
    ikon.textContent = item.icon || '';
    var nama = document.createElement('span');
    nama.className = 'media-name';
    nama.textContent = item.name;
    ket.appendChild(ikon);
    ket.appendChild(nama);
    kartu.appendChild(ket);

    if (item.state === 'locked') {
      kartu.setAttribute('data-reauth', 'media.stream');
      kartu.setAttribute('data-reauth-resource', String(item.id));
    }
    return kartu;
  }

  function isiGaleri(wadah, daftar, albumId) {
    wadah.innerHTML = '';
    daftar.forEach(function (item) {
      wadah.appendChild(buatKartu(item, albumId));
    });
    perbaruiPilihan();
  }

  function bukaAlbum(id, nama, terkunci) {
    albumAktif = String(id);
    albumTerkunci = Boolean(terkunci);
    detail.hidden = false;
    judulAlbum.textContent = nama || '';
    tombolKunciAlbum.textContent = albumTerkunci ? 'Buka kunci album' : 'Kunci album';
    tombolKunciAlbum.setAttribute('data-reauth-resource', String(id));
    tombolTersembunyi.setAttribute('data-reauth-resource', String(id));
    formGantiNamaAlbum.hidden = true;
    daftarItem.innerHTML = '';
    daftarTersembunyi.innerHTML = '';
    bagianTersembunyi.hidden = true;
    bersihkanGalat();

    var grant = albumTerkunci ? grantUntuk('album.unlock', String(id)) : null;
    if (albumTerkunci && !grant) {
      tampilkanGalat(pesan('error'));
      return;
    }
    ambil('/api/collections/' + id + '/items', grant).then(function (data) {
      isiGaleri(daftarItem, data.items || [], id);
      bagianTersembunyi.hidden = !(data.hidden_count > 0);
      detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }).catch(function (err) {
      tampilkanGalat(err.message);
    });
  }

  function muatTersembunyi() {
    if (!albumAktif) {
      return;
    }
    var grant = grantUntuk('album.unlock', albumAktif);
    if (!grant) {
      tampilkanGalat(pesan('error'));
      return;
    }
    ambil('/api/collections/' + albumAktif + '/hidden', grant).then(function (data) {
      isiGaleri(daftarTersembunyi, data.items || [], albumAktif);
    }).catch(function (err) {
      tampilkanGalat(err.message);
    });
  }

  function kartuTerlihat() {
    var semua = document.querySelectorAll('[data-media-item]');
    return Array.prototype.filter.call(semua, function (kartu) {
      return kartu.offsetParent !== null;
    });
  }

  function tampilkanKartu(kartu) {
    if (!kartu) {
      return;
    }
    kartuAktif = kartu;
    panggung.innerHTML = '';
    var jenis = kartu.getAttribute('data-kind');
    var url = kartu.getAttribute('data-view-url');
    var elemen;
    if (jenis === 'image') {
      elemen = document.createElement('img');
      elemen.alt = kartu.getAttribute('data-name') || '';
      elemen.src = url;
    } else if (jenis === 'video') {
      elemen = document.createElement('video');
      elemen.controls = true;
      elemen.src = url;
    } else {
      elemen = document.createElement('audio');
      elemen.controls = true;
      elemen.src = url;
    }
    panggung.appendChild(elemen);
    judulPenampil.textContent = kartu.getAttribute('data-name') || '';
    formGantiNamaBerkas.hidden = true;
    penampil.style.display = 'flex';
    if (elemen.play) {
      var janji = elemen.play();
      if (janji && typeof janji.catch === 'function') {
        janji.catch(function () { /* pemutaran otomatis dapat ditolak */ });
      }
    }
  }

  function bukaPenampil(kartu) {
    daftarPenampil = kartuTerlihat();
    indeksPenampil = daftarPenampil.indexOf(kartu);
    if (indeksPenampil < 0) {
      indeksPenampil = 0;
    }
    tampilkanKartu(kartu);
  }

  function geserPenampil(arah) {
    if (!daftarPenampil.length) {
      return;
    }
    indeksPenampil = (indeksPenampil + arah + daftarPenampil.length)
      % daftarPenampil.length;
    tampilkanKartu(daftarPenampil[indeksPenampil]);
  }

  function tutupPenampil() {
    penampil.style.display = 'none';
    panggung.innerHTML = '';
    kartuAktif = null;
  }

  function gantiNamaBerkas(nama) {
    if (!kartuAktif) {
      return;
    }
    var id = kartuAktif.getAttribute('data-file-id');
    kirim('/api/media/' + id + '/rename', { name: nama }).then(function () {
      kartuAktif.setAttribute('data-name', nama);
      var label = kartuAktif.querySelector('.media-name');
      if (label) {
        label.textContent = nama;
      }
      judulPenampil.textContent = nama;
      formGantiNamaBerkas.hidden = true;
    }).catch(function (err) {
      tampilkanGalat(err.message);
    });
  }

  function perbaruiPilihan() {
    var terpilih = document.querySelectorAll('[data-select-file]:checked');
    var jumlah = terpilih.length;
    if (bilahPilih) {
      bilahPilih.hidden = jumlah === 0;
    }
    if (jumlahPilih) {
      jumlahPilih.textContent = jumlah + ' dipilih';
    }

    var koleksi = null;
    var sah = jumlah > 0;
    Array.prototype.forEach.call(terpilih, function (cek) {
      var kartu = cek.closest('[data-media-item]');
      var id = kartu ? kartu.getAttribute('data-collection-id') : '';
      if (!id) {
        sah = false;
        return;
      }
      if (koleksi === null) {
        koleksi = id;
      } else if (koleksi !== id) {
        sah = false;
      }
    });

    [tombolKunciItem, tombolSembunyiItem].forEach(function (tombol) {
      if (!tombol) {
        return;
      }
      if (sah && koleksi) {
        tombol.setAttribute('data-reauth', 'album.unlock');
        tombol.setAttribute('data-reauth-resource', koleksi);
      } else {
        tombol.removeAttribute('data-reauth');
        tombol.removeAttribute('data-reauth-resource');
      }
    });

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
  }

  function idTerpilih() {
    var hasil = [];
    var terpilih = document.querySelectorAll('[data-select-file]:checked');
    Array.prototype.forEach.call(terpilih, function (cek) {
      hasil.push(Number(cek.value));
    });
    return hasil;
  }

  function pindahkan() {
    var ids = idTerpilih();
    if (!ids.length) {
      return;
    }
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

  function ubahStatus(state) {
    var ids = idTerpilih();
    if (!ids.length) {
      tampilkanGalat(pesan('need-collection'));
      return null;
    }
    var cek = document.querySelector('[data-select-file]:checked');
    var kartu = cek ? cek.closest('[data-media-item]') : null;
    var koleksi = kartu ? kartu.getAttribute('data-collection-id') : '';
    if (!koleksi) {
      tampilkanGalat(pesan('need-collection'));
      return null;
    }
    var grant = grantUntuk('album.unlock', koleksi);
    if (!grant) {
      tampilkanGalat(pesan('error'));
      return null;
    }
    return kirim('/api/collections/' + koleksi + '/items/state', {
      file_ids: ids,
      state: state
    }, grant).then(function () {
      window.location.reload();
    }).catch(function (err) {
      tampilkanGalat(err.message);
    });
  }

  function ubahKunciAlbum() {
    if (!albumAktif) {
      return;
    }
    var target = !albumTerkunci;
    var grant = grantUntuk('album.unlock', albumAktif);
    if (!grant) {
      tampilkanGalat(pesan('error'));
      return null;
    }
    return kirim('/api/collections/' + albumAktif + '/lock',
                 { locked: target }, grant).then(function () {
      window.location.reload();
    }).catch(function (err) {
      tampilkanGalat(err.message);
    });
  }

  function simpulkanIntent(pemicu) {
    if (pemicu.hasAttribute('data-album-open')) {
      intent = {
        jenis: 'album',
        id: pemicu.getAttribute('data-album-id'),
        nama: pemicu.getAttribute('data-album-name'),
        terkunci: pemicu.getAttribute('data-album-locked') === '1'
      };
    } else if (pemicu.id === 'album-hidden-open') {
      intent = { jenis: 'tersembunyi' };
    } else if (pemicu.id === 'album-lock-toggle') {
      intent = { jenis: 'kunciAlbum' };
    } else if (pemicu.id === 'lock-items-button') {
      intent = { jenis: 'status', state: 'locked' };
    } else if (pemicu.id === 'hide-items-button') {
      intent = { jenis: 'status', state: 'hidden' };
    } else if (pemicu.id === 'move-button') {
      intent = { jenis: 'pindah' };
    } else if (pemicu.hasAttribute('data-media-item')) {
      intent = { jenis: 'lihat', kartu: pemicu };
    }
  }

  document.addEventListener('pointerdown', function (event) {
    var pemicu = event.target.closest(
      '[data-reauth], [data-album-open], [data-open-media]');
    if (!pemicu) {
      return;
    }
    if (pemicu.hasAttribute('data-open-media')) {
      pemicu = pemicu.closest('[data-media-item]');
    }
    if (pemicu) {
      simpulkanIntent(pemicu);
    }
  }, true);

  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detailGrant = event.detail || {};
    var scope = detailGrant.scope;
    if (scope === 'album.unlock') {
      if (!intent) {
        return;
      }
      if (intent.jenis === 'album') {
        bukaAlbum(intent.id, intent.nama, intent.terkunci);
      } else if (intent.jenis === 'tersembunyi') {
        muatTersembunyi();
      } else if (intent.jenis === 'kunciAlbum') {
        ubahKunciAlbum();
      } else if (intent.jenis === 'status') {
        ubahStatus(intent.state);
      } else if (intent.jenis === 'pindah') {
        pindahkan();
      }
    } else if (scope === 'media.stream' && intent && intent.jenis === 'lihat') {
      bukaPenampil(intent.kartu);
    }
    intent = null;
  });

  document.addEventListener('change', function (event) {
    if (event.target.matches('[data-select-file]')) {
      perbaruiPilihan();
    } else if (event.target === targetPindah) {
      perbaruiPilihan();
    }
  });

  document.addEventListener('click', function (event) {
    var buka = event.target.closest('[data-open-media]');
    if (buka) {
      var kartu = buka.closest('[data-media-item]');
      if (kartu && kartu.getAttribute('data-locked') === '1'
          && !grantUntuk('media.stream', kartu.getAttribute('data-file-id'))) {
        return;
      }
      if (kartu) {
        bukaPenampil(kartu);
      }
      return;
    }

    var album = event.target.closest('[data-album-open]');
    if (album && album.getAttribute('data-album-locked') !== '1') {
      bukaAlbum(album.getAttribute('data-album-id'),
                album.getAttribute('data-album-name'), false);
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
    if (event.target === tombolKunciItem || event.target === tombolSembunyiItem) {
      tampilkanGalat(pesan('need-collection'));
      return;
    }
    if (event.target === tombolGantiNamaAlbum) {
      formGantiNamaAlbum.hidden = !formGantiNamaAlbum.hidden;
      if (!formGantiNamaAlbum.hidden) {
        inputGantiNamaAlbum.value = judulAlbum.textContent;
        inputGantiNamaAlbum.focus();
      }
      return;
    }
    if (event.target === tombolHapusAlbum && albumAktif) {
      if (!window.confirm(pesan('delete-confirm'))) {
        return;
      }
      kirim('/api/collections/' + albumAktif + '/delete', {}).then(function () {
        window.location.reload();
      }).catch(function (err) {
        tampilkanGalat(err.message);
      });
      return;
    }
    if (event.target === tombolGantiNamaBerkas && kartuAktif) {
      formGantiNamaBerkas.hidden = !formGantiNamaBerkas.hidden;
      if (!formGantiNamaBerkas.hidden) {
        inputGantiNamaBerkas.value = kartuAktif.getAttribute('data-name') || '';
        inputGantiNamaBerkas.focus();
      }
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
    }
  });

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

  if (formGantiNamaAlbum) {
    formGantiNamaAlbum.addEventListener('submit', function (event) {
      event.preventDefault();
      if (!albumAktif) {
        return;
      }
      var nama = inputGantiNamaAlbum.value.trim();
      if (!nama) {
        return;
      }
      kirim('/api/collections/' + albumAktif + '/rename',
            { name: nama }).then(function () {
        window.location.reload();
      }).catch(function (err) {
        tampilkanGalat(err.message);
      });
    });
  }

  if (formGantiNamaBerkas) {
    formGantiNamaBerkas.addEventListener('submit', function (event) {
      event.preventDefault();
      var nama = inputGantiNamaBerkas.value.trim();
      if (nama) {
        gantiNamaBerkas(nama);
      }
    });
  }

  if (penampil) {
    penampil.addEventListener('click', function (event) {
      if (event.target === penampil) {
        tutupPenampil();
      }
    });
  }

  document.addEventListener('keydown', function (event) {
    if (penampil && penampil.style.display === 'flex') {
      if (event.key === 'Escape') {
        tutupPenampil();
      } else if (event.key === 'ArrowLeft') {
        geserPenampil(-1);
      } else if (event.key === 'ArrowRight') {
        geserPenampil(1);
      }
    }
  });

  perbaruiPilihan();
})();
