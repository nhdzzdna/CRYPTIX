/**
 * static/js/collection_folders.js
 * ───────────────────────────────
 * Pengelola folder bersama untuk halaman Musik dan Dokumen.
 *
 * Memakai API koleksi yang sama dengan album Media: buat, ganti nama, hapus,
 * kunci, pindahkan banyak berkas, serta kunci/sembunyikan item. Item hanya
 * dimuat setelah grant album.unlock bila folder terkunci.
 */
(function () {
  'use strict';

  var halaman = document.getElementById('collection-page');
  if (!halaman) {
    return;
  }

  var jenisHalaman = halaman.getAttribute('data-page') || 'dokumen';
  var csrf = halaman.getAttribute('data-csrf') || '';

  var kotakPesan = document.getElementById('collection-messages');
  var kotakGalat = document.getElementById('collection-alert');
  var detail = document.getElementById('folder-detail');
  var judul = document.getElementById('folder-detail-title');
  var daftarItem = document.getElementById('folder-items');
  var bagianTersembunyi = document.getElementById('folder-hidden');
  var daftarTersembunyi = document.getElementById('folder-hidden-items');
  var tombolTersembunyi = document.getElementById('folder-hidden-open');
  var tombolKunci = document.getElementById('folder-lock-toggle');
  var tombolKembali = document.getElementById('folder-back');
  var tombolGantiNama = document.getElementById('folder-rename');
  var formGantiNama = document.getElementById('folder-rename-form');
  var inputGantiNama = document.getElementById('folder-rename-input');
  var tombolHapus = document.getElementById('folder-delete');
  var bilahPilih = document.getElementById('selection-bar');
  var jumlahPilih = document.getElementById('selection-count');
  var targetPindah = document.getElementById('move-target');
  var tombolPindah = document.getElementById('move-button');
  var tombolKunciItem = document.getElementById('lock-items-button');
  var tombolSembunyiItem = document.getElementById('hide-items-button');
  var formBuat = document.getElementById('folder-create-form');
  var inputBuat = document.getElementById('folder-create-name');
  var cekBuatTerkunci = document.getElementById('folder-create-locked');
  var folderLoading = document.getElementById('folder-loading');
  var folderEmpty = document.getElementById('folder-empty');

  var IKON_DOKUMEN =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" ' +
    'stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>' +
    '<path d="M14 2v6h6"/><path d="M8 13h8M8 17h5"/></svg>';
  var IKON_KUNCI =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" ' +
    'stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/>' +
    '<path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15" r="1.2"/></svg>';
  var IKON_PUTAR =
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>';
  var IKON_UNDUH =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4v12"/>' +
    '<path d="m7 11 5 5 5-5"/><path d="M4 20h16"/></svg>';
  var IKON_HAPUS =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18"/>' +
    '<path d="M8 6V4h8v2"/><path d="M6 6l1 14h10l1-14"/><path d="M10 11v5M14 11v5"/></svg>';

  var folderAktif = null;
  var folderTerkunci = false;
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

  function ukuranTeks(bita) {
    var n = Number(bita) || 0;
    if (n >= 1048576) {
      return (n / 1048576).toFixed(1) + ' MB';
    }
    return (n / 1024).toFixed(1) + ' KB';
  }

  function buatFormAksi(id, scope, label, kelas) {
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = (scope === 'file.download'
      ? '/vault/decrypt/' : '/vault/delete/') + id;
    form.className = 'd-inline';

    var token = document.createElement('input');
    token.type = 'hidden';
    token.name = 'csrf_token';
    token.value = csrf;
    form.appendChild(token);

    var tombol = document.createElement('button');
    tombol.type = 'submit';
    tombol.className = 'btn btn-sm doc-action ' + kelas;
    tombol.setAttribute('data-reauth', scope);
    tombol.setAttribute('data-reauth-resource', String(id));

    var ikon = document.createElement('span');
    ikon.className = 'doc-action-icon';
    ikon.innerHTML = scope === 'file.download' ? IKON_UNDUH : IKON_HAPUS;
    tombol.appendChild(ikon);

    var teks = document.createElement('span');
    teks.textContent = label;
    tombol.appendChild(teks);

    form.appendChild(tombol);
    return form;
  }

  function buatKartuMusik(item, folderId) {
    var kartu = document.createElement('div');
    kartu.className = 'music-track';
    kartu.setAttribute('data-track', '');
    kartu.setAttribute('data-file-id', String(item.id));
    kartu.setAttribute('data-kind', item.file_type);
    kartu.setAttribute('data-name', item.name);
    kartu.setAttribute('data-view-url', item.view_url);
    kartu.setAttribute('data-locked', item.state === 'locked' ? '1' : '0');
    kartu.setAttribute('data-collection-id', String(folderId || ''));

    var label = document.createElement('label');
    label.className = 'media-select';
    var cek = document.createElement('input');
    cek.type = 'checkbox';
    cek.setAttribute('data-select-file', '');
    cek.value = String(item.id);
    label.appendChild(cek);
    kartu.appendChild(label);

    var tombol = document.createElement('button');
    tombol.type = 'button';
    tombol.className = 'music-track-play';
    tombol.setAttribute('data-track-play', '');
    tombol.innerHTML = item.state === 'locked' ? IKON_KUNCI : IKON_PUTAR;
    kartu.appendChild(tombol);

    var isi = document.createElement('div');
    isi.className = 'music-track-main';
    var nama = document.createElement('span');
    nama.className = 'music-track-name';
    nama.textContent = item.name;
    var meta = document.createElement('span');
    meta.className = 'audio-track-meta';
    meta.textContent = 'Audio' + (item.state === 'locked' ? ' · Terkunci' : '');
    isi.appendChild(nama);
    isi.appendChild(meta);
    kartu.appendChild(isi);

    if (item.state === 'locked') {
      kartu.setAttribute('data-reauth', 'media.stream');
      kartu.setAttribute('data-reauth-resource', String(item.id));
    }
    return kartu;
  }

  function buatKartuDokumen(item, folderId) {
    var kartu = document.createElement('div');
    kartu.className = 'collection-item';
    kartu.setAttribute('data-doc-item', '');
    kartu.setAttribute('data-file-id', String(item.id));
    kartu.setAttribute('data-kind', item.file_type);
    kartu.setAttribute('data-name', item.name);
    kartu.setAttribute('data-size', String(item.file_size || 0));
    kartu.setAttribute('data-date', String(item.uploaded_at || ''));
    kartu.setAttribute('data-collection-id', String(folderId || ''));

    var label = document.createElement('label');
    label.className = 'media-select';
    var cek = document.createElement('input');
    cek.type = 'checkbox';
    cek.setAttribute('data-select-file', '');
    cek.value = String(item.id);
    label.appendChild(cek);
    kartu.appendChild(label);

    var isi = document.createElement('div');
    isi.className = 'collection-item-main';
    var ikon = document.createElement('span');
    ikon.className = 'media-icon doc-file-icon';
    ikon.setAttribute('aria-hidden', 'true');
    ikon.innerHTML = item.state === 'locked' ? IKON_KUNCI : IKON_DOKUMEN;
    var teks = document.createElement('div');
    teks.className = 'doc-file-text';
    var nama = document.createElement('span');
    nama.className = 'collection-item-name';
    nama.textContent = item.name;
    var meta = document.createElement('span');
    meta.className = 'doc-file-meta';
    meta.textContent = ukuranTeks(item.file_size) + ' · ' +
      String(item.uploaded_at || '').slice(0, 16);
    teks.appendChild(nama);
    teks.appendChild(meta);
    isi.appendChild(ikon);
    isi.appendChild(teks);
    kartu.appendChild(isi);

    var aksi = document.createElement('div');
    aksi.className = 'collection-item-actions doc-file-actions';
    aksi.appendChild(buatFormAksi(item.id, 'file.download', 'Unduh', 'btn-success'));
    aksi.appendChild(buatFormAksi(item.id, 'item.delete', 'Hapus', 'btn-danger'));
    kartu.appendChild(aksi);
    return kartu;
  }

  function buatKartu(item, folderId) {
    if (jenisHalaman === 'musik') {
      return buatKartuMusik(item, folderId);
    }
    return buatKartuDokumen(item, folderId);
  }

  function isiDaftar(wadah, daftar, folderId) {
    if (!wadah) {
      return;
    }
    wadah.innerHTML = '';
    (daftar || []).forEach(function (item) {
      wadah.appendChild(buatKartu(item, folderId));
    });
    perbaruiPilihan();
    document.dispatchEvent(new CustomEvent('collection:items-loaded', {
      detail: { container: wadah }
    }));
  }

  function bukaFolder(id, nama, terkunci) {
    folderAktif = String(id);
    folderTerkunci = Boolean(terkunci);
    detail.hidden = false;
    judul.textContent = nama || '';
    tombolKunci.textContent = folderTerkunci
      ? (tombolKunci.getAttribute('data-label-unlock') || 'Buka kunci folder')
      : (tombolKunci.getAttribute('data-label-lock') || 'Kunci folder');
    tombolKunci.setAttribute('data-reauth-resource', String(id));
    tombolTersembunyi.setAttribute('data-reauth-resource', String(id));
    formGantiNama.hidden = true;
    daftarItem.innerHTML = '';
    daftarTersembunyi.innerHTML = '';
    bagianTersembunyi.hidden = true;
    if (folderLoading) {
      folderLoading.hidden = false;
    }
    if (folderEmpty) {
      folderEmpty.hidden = true;
    }
    bersihkanGalat();

    var grant = folderTerkunci ? grantUntuk('album.unlock', String(id)) : null;
    if (folderTerkunci && !grant) {
      if (folderLoading) {
        folderLoading.hidden = true;
      }
      tampilkanGalat(pesan('error'));
      return;
    }
    ambil('/api/collections/' + id + '/items', grant).then(function (data) {
      var daftar = data.items || [];
      isiDaftar(daftarItem, daftar, id);
      if (folderLoading) {
        folderLoading.hidden = true;
      }
      if (folderEmpty) {
        folderEmpty.hidden = daftar.length > 0;
      }
      bagianTersembunyi.hidden = !(data.hidden_count > 0);
      detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }).catch(function (err) {
      if (folderLoading) {
        folderLoading.hidden = true;
      }
      tampilkanGalat(err.message);
    });
  }

  function muatTersembunyi() {
    if (!folderAktif) {
      return;
    }
    var grant = grantUntuk('album.unlock', folderAktif);
    if (!grant) {
      tampilkanGalat(pesan('error'));
      return;
    }
    ambil('/api/collections/' + folderAktif + '/hidden', grant).then(function (data) {
      isiDaftar(daftarTersembunyi, data.items || [], folderAktif);
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
      var kartu = cek.closest('[data-collection-id]');
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
    var cek = document.querySelector('[data-select-file]:checked');
    var kartu = cek ? cek.closest('[data-collection-id]') : null;
    var koleksi = kartu ? kartu.getAttribute('data-collection-id') : '';
    if (!ids.length || !koleksi) {
      tampilkanGalat(pesan('need-folder'));
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

  function ubahKunciFolder() {
    if (!folderAktif) {
      return;
    }
    var grant = grantUntuk('album.unlock', folderAktif);
    if (!grant) {
      tampilkanGalat(pesan('error'));
      return null;
    }
    return kirim('/api/collections/' + folderAktif + '/lock',
                 { locked: !folderTerkunci }, grant).then(function () {
      window.location.reload();
    }).catch(function (err) {
      tampilkanGalat(err.message);
    });
  }

  function simpulkanIntent(pemicu) {
    intent = null;
    if (pemicu.hasAttribute('data-folder-open')) {
      intent = {
        jenis: 'folder',
        id: pemicu.getAttribute('data-folder-id'),
        nama: pemicu.getAttribute('data-folder-name'),
        terkunci: pemicu.getAttribute('data-folder-locked') === '1'
      };
    } else if (pemicu.id === 'folder-hidden-open') {
      intent = { jenis: 'tersembunyi' };
    } else if (pemicu.id === 'folder-lock-toggle') {
      intent = { jenis: 'kunciFolder' };
    } else if (pemicu.id === 'lock-items-button') {
      intent = { jenis: 'status', state: 'locked' };
    } else if (pemicu.id === 'hide-items-button') {
      intent = { jenis: 'status', state: 'hidden' };
    } else if (pemicu.id === 'move-button') {
      intent = { jenis: 'pindah' };
    }
  }

  document.addEventListener('pointerdown', function (event) {
    var pemicu = event.target.closest('[data-reauth], [data-folder-open]');
    if (pemicu) {
      simpulkanIntent(pemicu);
    }
  }, true);

  document.addEventListener('cryptix:reauth-grant', function (event) {
    var grant = event.detail || {};
    if (grant.scope !== 'album.unlock' || !intent) {
      return;
    }
    if (intent.jenis === 'folder') {
      bukaFolder(intent.id, intent.nama, intent.terkunci);
    } else if (intent.jenis === 'tersembunyi') {
      muatTersembunyi();
    } else if (intent.jenis === 'kunciFolder') {
      ubahKunciFolder();
    } else if (intent.jenis === 'status') {
      ubahStatus(intent.state);
    } else if (intent.jenis === 'pindah') {
      pindahkan();
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
    var folder = event.target.closest('[data-folder-open]');
    if (folder && folder.getAttribute('data-folder-locked') !== '1') {
      bukaFolder(folder.getAttribute('data-folder-id'),
                 folder.getAttribute('data-folder-name'), false);
      return;
    }
    if (event.target === tombolKembali) {
      detail.hidden = true;
      folderAktif = null;
      return;
    }
    if (event.target === tombolPindah) {
      pindahkan();
      return;
    }
    if (event.target === tombolKunciItem || event.target === tombolSembunyiItem) {
      tampilkanGalat(pesan('need-folder'));
      return;
    }
    if (event.target === tombolGantiNama) {
      formGantiNama.hidden = !formGantiNama.hidden;
      if (!formGantiNama.hidden) {
        inputGantiNama.value = judul.textContent;
        inputGantiNama.focus();
      }
      return;
    }
    if (event.target === tombolHapus && folderAktif) {
      if (!window.confirm(pesan('delete-confirm'))) {
        return;
      }
      kirim('/api/collections/' + folderAktif + '/delete', {}).then(function () {
        window.location.reload();
      }).catch(function (err) {
        tampilkanGalat(err.message);
      });
    }
  });

  if (formBuat) {
    formBuat.addEventListener('submit', function (event) {
      event.preventDefault();
      var nama = inputBuat ? inputBuat.value.trim() : '';
      if (!nama) {
        tampilkanGalat(pesan('error'));
        return;
      }
      kirim('/api/collections', {
        name: nama,
        kind: jenisHalaman,
        locked: cekBuatTerkunci && cekBuatTerkunci.checked
      }).then(function () {
        window.location.reload();
      }).catch(function (err) {
        tampilkanGalat(err.message);
      });
    });
  }

  if (formGantiNama) {
    formGantiNama.addEventListener('submit', function (event) {
      event.preventDefault();
      if (!folderAktif) {
        return;
      }
      var nama = inputGantiNama.value.trim();
      if (!nama) {
        return;
      }
      kirim('/api/collections/' + folderAktif + '/rename',
            { name: nama }).then(function () {
        window.location.reload();
      }).catch(function (err) {
        tampilkanGalat(err.message);
      });
    });
  }

  window.CryptixCollection = {
    pageKind: jenisHalaman,
    pesan: pesan,
    galat: tampilkanGalat,
    grantUntuk: grantUntuk
  };

  perbaruiPilihan();
})();
