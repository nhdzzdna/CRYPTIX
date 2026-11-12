/**
 * static/js/steganography.js
 * ────────────────────────────
 * Halaman Steganography: pratinjau gambar pembawa, indikator kapasitas,
 * segmented jenis muatan dan kunci, ekstraksi tanpa muat ulang halaman,
 * menu aksi per baris, serta modal ekstrak dengan kolom kunci rahasia.
 *
 * Semua teks pesan dibaca dari atribut data-msg-* pada akar halaman
 * (modules/strings.py), bukan teks JS. Nilai payload_type, key_mode, dan
 * use_encryption disimpan pada input tersembunyi agar kontrak POST tidak
 * berubah; checkbox enkripsi tidak memakai atribut name sehingga tidak
 * pernah terkirim ganda dengan input tersembunyi.
 */
(function () {
  'use strict';

  var akar = document.querySelector('.kx-sg-page');
  if (!akar) {
    return;
  }

  var formSisip = document.getElementById('sg-sisip-form');
  var formEkstrakUnggah = document.getElementById('sg-ekstrak-form');
  var formHapus = document.getElementById('sg-hapus-form');
  var kapasitasTeks = document.getElementById('sg-kapasitas-teks');
  var kotakKapasitas = document.getElementById('sg-kapasitas');
  var inputPembawa = document.getElementById('sg-pembawa');
  var inputPesan = document.getElementById('sg-pesan');
  var inputBerkas = document.getElementById('sg-berkas');
  var checkboxEnkripsi = document.getElementById('sg-enkripsi');
  var inputUseEnc = document.getElementById('sg-use-enc');
  var inputJenis = document.getElementById('sg-jenis');
  var inputKunciMode = document.getElementById('sg-kunci-mode');
  var fieldTeks = document.getElementById('sg-teks-field');
  var fieldBerkas = document.getElementById('sg-berkas-field');
  var infoKunciAkun = document.getElementById('sg-kunci-akun-info');
  var fieldKunciRahasia = document.getElementById('sg-kunci-rahasia-field');
  var inputPassphraseSisip = document.getElementById('sg-passphrase');
  var tombolSisip = document.getElementById('sg-sisip-btn');
  var pratinjau = document.getElementById('sg-pratinjau');
  var pratinjauImg = document.getElementById('sg-pratinjau-img');
  var kotakHasil = document.getElementById('stego-result');
  var kosongHasil = document.getElementById('sg-hasil-kosong');
  var modalEkstrak = document.getElementById('sg-modal-ekstrak');
  var modalNama = document.getElementById('sg-modal-nama');
  var modalPassphrase = document.getElementById('sg-modal-passphrase');
  var modalTombolEkstrak = document.getElementById('sg-modal-ekstrak-btn');

  var kapasitasUrl = formSisip ? formSisip.getAttribute('data-capacity-url') : '';
  var kapasitas = null;
  var urlPratinjau = null;
  var barisModal = null;

  function pesan(kunci, data) {
    var teks = akar.getAttribute('data-msg-' + kunci) || '';
    if (data) {
      Object.keys(data).forEach(function (nama) {
        teks = teks.split('{' + nama + '}').join(String(data[nama]));
      });
    }
    return teks;
  }

  function toast(teks, jenis) {
    if (window.KX && typeof KX.toast === 'function') {
      KX.toast(teks, jenis);
    }
  }

  function ukuran(byte) {
    if (window.KX && KX.dropzone && typeof KX.dropzone.ukuran === 'function') {
      return KX.dropzone.ukuran(byte);
    }
    return String(byte) + ' B';
  }

  function tokenCsrf() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  // ── Segmented jenis muatan ───────────────────────────────────────────
  function jenisBerkas() {
    return inputJenis && inputJenis.value === 'file';
  }

  function aturJenisMuatan() {
    var berkas = jenisBerkas();
    if (fieldTeks) {
      fieldTeks.hidden = berkas;
    }
    if (fieldBerkas) {
      fieldBerkas.hidden = !berkas;
    }
    perbaruiKapasitas();
  }

  document.querySelectorAll('[data-sg-jenis]').forEach(function (tombol) {
    tombol.addEventListener('click', function () {
      var nilai = tombol.getAttribute('data-sg-jenis');
      if (inputJenis) {
        inputJenis.value = nilai;
      }
      document.querySelectorAll('[data-sg-jenis]').forEach(function (el) {
        var aktif = el === tombol;
        el.classList.toggle('is-active', aktif);
        el.setAttribute('aria-pressed', aktif ? 'true' : 'false');
      });
      aturJenisMuatan();
    });
  });

  // ── Segmented kunci muatan ──────────────────────────────────────────
  function aturKunci() {
    var rahasia = inputKunciMode && inputKunciMode.value === 'passphrase';
    if (infoKunciAkun) {
      infoKunciAkun.hidden = rahasia;
    }
    if (fieldKunciRahasia) {
      fieldKunciRahasia.hidden = !rahasia;
    }
    if (inputPassphraseSisip) {
      inputPassphraseSisip.required = rahasia;
      if (!rahasia) {
        inputPassphraseSisip.value = '';
      }
    }
  }

  document.querySelectorAll('[data-sg-kunci]').forEach(function (tombol) {
    tombol.addEventListener('click', function () {
      var nilai = tombol.getAttribute('data-sg-kunci');
      if (inputKunciMode) {
        inputKunciMode.value = nilai;
      }
      document.querySelectorAll('[data-sg-kunci]').forEach(function (el) {
        var aktif = el === tombol;
        el.classList.toggle('is-active', aktif);
        el.setAttribute('aria-pressed', aktif ? 'true' : 'false');
      });
      aturKunci();
    });
  });

  // ── Checkbox enkripsi muatan ─────────────────────────────────────────
  function sinkronEnkripsi() {
    if (inputUseEnc && checkboxEnkripsi) {
      inputUseEnc.value = checkboxEnkripsi.checked ? '1' : '0';
    }
    perbaruiKapasitas();
  }

  if (checkboxEnkripsi) {
    checkboxEnkripsi.addEventListener('change', sinkronEnkripsi);
  }

  // ── Kapasitas ───────────────────────────────────────────────────────
  function perkiraanByte() {
    var overhead = checkboxEnkripsi && checkboxEnkripsi.checked ? 192 : 0;
    if (jenisBerkas()) {
      var berkas = inputBerkas && inputBerkas.files ? inputBerkas.files[0] : null;
      return berkas ? berkas.size + berkas.name.length + 64 + overhead : 0;
    }
    var teks = inputPesan ? inputPesan.value : '';
    return new TextEncoder().encode(teks).length + overhead;
  }

  function tandaiKapasitas(lebih) {
    if (kotakKapasitas) {
      kotakKapasitas.classList.toggle('is-warn', lebih);
    }
    if (tombolSisip) {
      tombolSisip.disabled = Boolean(lebih);
    }
  }

  function perbaruiKapasitas() {
    if (!kapasitasTeks) {
      return;
    }
    if (kapasitas === null) {
      kapasitasTeks.textContent = pesan('capacity-initial');
      tandaiKapasitas(false);
      return;
    }
    var terpakai = perkiraanByte();
    var sisa = kapasitas - terpakai;
    if (sisa >= 0) {
      kapasitasTeks.textContent = pesan('capacity-fmt', {
        terpakai: ukuran(terpakai),
        kapasitas: ukuran(kapasitas)
      }) + ' ' + pesan('capacity-left', { sisa: ukuran(sisa) });
      tandaiKapasitas(false);
    } else {
      kapasitasTeks.textContent = pesan('capacity-fmt', {
        terpakai: ukuran(terpakai),
        kapasitas: ukuran(kapasitas)
      }) + ' ' + pesan('capacity-over', { lebih: ukuran(Math.abs(sisa)) });
      tandaiKapasitas(true);
    }
  }

  if (inputPesan) {
    inputPesan.addEventListener('input', perbaruiKapasitas);
  }
  if (inputBerkas) {
    inputBerkas.addEventListener('change', perbaruiKapasitas);
  }

  function perbaruiPratinjau() {
    var berkas = inputPembawa && inputPembawa.files ? inputPembawa.files[0] : null;
    if (urlPratinjau) {
      URL.revokeObjectURL(urlPratinjau);
      urlPratinjau = null;
    }
    if (!berkas || !pratinjau || !pratinjauImg) {
      if (pratinjau) {
        pratinjau.hidden = true;
      }
      return;
    }
    urlPratinjau = URL.createObjectURL(berkas);
    pratinjauImg.src = urlPratinjau;
    pratinjau.hidden = false;
  }

  if (inputPembawa && kapasitasUrl) {
    inputPembawa.addEventListener('change', function () {
      perbaruiPratinjau();
      var berkas = inputPembawa.files ? inputPembawa.files[0] : null;
      if (!berkas) {
        kapasitas = null;
        perbaruiKapasitas();
        return;
      }
      var data = new FormData();
      data.append('carrier_image', berkas);
      data.append('csrf_token', tokenCsrf());
      apiFetch(kapasitasUrl, { method: 'POST', body: data })
        .then(function (resp) {
          return resp.json().then(function (info) {
            return { ok: resp.ok, info: info };
          });
        })
        .then(function (hasil) {
          if (!hasil.ok || hasil.info.error) {
            kapasitas = null;
            if (kapasitasTeks) {
              kapasitasTeks.textContent = hasil.info.error || pesan('capacity-error');
            }
            tandaiKapasitas(true);
            return;
          }
          kapasitas = hasil.info.capacity;
          perbaruiKapasitas();
        })
        .catch(function () {
          kapasitas = null;
          if (kapasitasTeks) {
            kapasitasTeks.textContent = pesan('capacity-error');
          }
          tandaiKapasitas(true);
        });
    });
  }

  // ── Dropzone: dukungan papan tombol (Enter/Spasi) ───────────────────
  document.addEventListener('keydown', function (event) {
    if (event.key !== 'Enter' && event.key !== ' ') {
      return;
    }
    var zona = event.target.closest ? event.target.closest('[data-kx-dropzone]') : null;
    if (!zona || event.target.tagName === 'INPUT') {
      return;
    }
    event.preventDefault();
    var input = zona.querySelector('input[type="file"]');
    if (input) {
      input.click();
    }
  });

  // ── Hasil ekstraksi ─────────────────────────────────────────────────
  function bersihkanHasil() {
    if (!kotakHasil) {
      return;
    }
    Array.prototype.forEach.call(kotakHasil.children, function (anak) {
      if (anak !== kosongHasil) {
        anak.remove();
      }
    });
  }

  function tampilkanKosongHasil() {
    bersihkanHasil();
    if (kosongHasil) {
      kosongHasil.hidden = false;
    }
  }

  function kotakInfo(jenis, teks) {
    bersihkanHasil();
    if (kosongHasil) {
      kosongHasil.hidden = true;
    }
    if (!kotakHasil) {
      return;
    }
    var kotak = document.createElement('div');
    kotak.className = 'kx-infobox ' + jenis;
    var namaIkon = jenis === 'kx-sg-infobox-danger' ? 'alert-triangle' : 'info';
    kotak.innerHTML =
      '<svg class="kx-icon" width="17" height="17" viewBox="0 0 24 24" aria-hidden="true" focusable="false">' +
      '<use href="' + alamatSprite() + '#' + namaIkon + '"></use></svg>';
    var p = document.createElement('p');
    p.textContent = teks;
    kotak.appendChild(p);
    kotakHasil.appendChild(kotak);
  }

  function alamatSprite() {
    var contoh = document.querySelector('use[href*="sprite.svg"]');
    if (contoh) {
      return (contoh.getAttribute('href') || '').split('#')[0];
    }
    return '/static/icons/sprite.svg';
  }

  function hasilTeks(isi) {
    bersihkanHasil();
    if (kosongHasil) {
      kosongHasil.hidden = true;
    }
    if (!kotakHasil) {
      return;
    }
    var bungkus = document.createElement('div');
    bungkus.className = 'kx-sg-hasil-isi';

    var kepala = document.createElement('div');
    kepala.className = 'kx-sg-hasil-kepala';
    var label = document.createElement('span');
    label.className = 'kx-sg-hasil-label';
    label.textContent = pesan('text-title');
    var tombolSalin = document.createElement('button');
    tombolSalin.type = 'button';
    tombolSalin.className = 'kx-btn kx-btn-sm kx-btn-secondary';
    tombolSalin.textContent = 'Salin';
    tombolSalin.addEventListener('click', function () {
      if (window.KX && typeof KX.salin === 'function') {
        KX.salin(pre.textContent, tombolSalin);
      }
    });
    kepala.appendChild(label);
    kepala.appendChild(tombolSalin);

    var pre = document.createElement('pre');
    pre.className = 'kx-code kx-sg-hasil-teks';
    pre.textContent = isi;

    bungkus.appendChild(kepala);
    bungkus.appendChild(pre);
    kotakHasil.appendChild(bungkus);
  }

  function tampilkanMemuat() {
    bersihkanHasil();
    if (kosongHasil) {
      kosongHasil.hidden = true;
    }
    if (!kotakHasil) {
      return;
    }
    var bungkus = document.createElement('div');
    bungkus.className = 'kx-sg-hasil-muat';
    var label = document.createElement('span');
    label.className = 'kx-sg-sr';
    label.textContent = pesan('processing');
    var baris = document.createElement('div');
    baris.className = 'kx-skeleton kx-sg-baris-muat';
    var blok = document.createElement('div');
    blok.className = 'kx-skeleton kx-sg-blok-muat';
    bungkus.appendChild(label);
    bungkus.appendChild(baris);
    bungkus.appendChild(blok);
    kotakHasil.appendChild(bungkus);
  }

  function namaBerkasDari(header) {
    if (!header) {
      return null;
    }
    var cocok = /filename\*?=(?:UTF-8''|\x22)?([^\x22;]+)/i.exec(header);
    if (!cocok) {
      return null;
    }
    var nama = cocok[1].replace(/^\x22|\x22$/g, '');
    try {
      return decodeURIComponent(nama);
    } catch (err) {
      return nama;
    }
  }

  function unduhBlob(blob, nama) {
    var url = URL.createObjectURL(blob);
    var tautan = document.createElement('a');
    tautan.href = url;
    tautan.download = nama || 'berkas-hasil';
    document.body.appendChild(tautan);
    tautan.click();
    document.body.removeChild(tautan);
    window.setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 1000);
  }

  // ── Pengiriman ekstraksi ────────────────────────────────────────────
  function kirimEkstraksi(url, data, token, dariModal) {
    tampilkanMemuat();

    data.append('csrf_token', tokenCsrf());
    var headers = {};
    if (token) {
      headers['X-Reauth-Grant'] = token;
    }

    apiFetch(url, {
      method: 'POST',
      headers: headers,
      body: data
    })
      .then(function (resp) {
        var tipe = resp.headers.get('Content-Type') || '';
        if (tipe.indexOf('application/json') !== -1) {
          return resp.json().then(function (muatan) {
            return { ok: resp.ok, json: muatan };
          });
        }
        if (!resp.ok) {
          throw new Error(pesan('extract-failed'));
        }
        return resp.blob().then(function (blob) {
          return {
            ok: true,
            blob: blob,
            nama: namaBerkasDari(resp.headers.get('Content-Disposition')) ||
              'berkas-hasil'
          };
        });
      })
      .then(function (hasil) {
        if (dariModal) {
          tutupModalEkstrak();
        }
        if (!hasil.ok || (hasil.json && hasil.json.success === false)) {
          var galat = hasil.json && hasil.json.error
            ? hasil.json.error : pesan('extract-failed');
          kotakInfo('kx-sg-infobox-danger', galat);
          return;
        }
        if (hasil.json) {
          if (hasil.json.type === 'text') {
            hasilTeks(hasil.json.text);
          } else {
            kotakInfo('kx-infobox', hasil.json.message || pesan('file-downloaded'));
          }
          return;
        }
        unduhBlob(hasil.blob, hasil.nama);
        kotakInfo('kx-infobox', pesan('file-downloaded', { nama: hasil.nama }));
        toast(pesan('file-downloaded', { nama: hasil.nama }), 'success');
      })
      .catch(function () {
        if (dariModal) {
          tutupModalEkstrak();
        }
        kotakInfo('kx-sg-infobox-danger', pesan('extract-failed'));
      });
  }

  // ── Menu aksi per baris ──────────────────────────────────────────────
  function tutupSemuaMenu() {
    document.querySelectorAll('.kx-sg-menu').forEach(function (menu) {
      menu.hidden = true;
    });
    document.querySelectorAll('[data-sg-menu]').forEach(function (tombol) {
      tombol.setAttribute('aria-expanded', 'false');
    });
  }

  function toggleMenu(tombol) {
    var wrap = tombol.closest('.kx-sg-menu-wrap');
    var menu = wrap ? wrap.querySelector('.kx-sg-menu') : null;
    if (!menu) {
      return;
    }
    var buka = menu.hidden;
    tutupSemuaMenu();
    menu.hidden = !buka;
    tombol.setAttribute('aria-expanded', buka ? 'true' : 'false');
    if (buka) {
      menu.classList.remove('kx-sg-menu-atas');
      var rect = menu.getBoundingClientRect();
      var batasBawah = (window.innerHeight || document.documentElement.clientHeight) - 16;
      if (rect.bottom > batasBawah) {
        menu.classList.add('kx-sg-menu-atas');
      }
    }
  }

  function tutupModalEkstrak() {
    if (modalEkstrak && window.KX && KX.modal) {
      KX.modal.tutup(modalEkstrak);
    }
  }

  function bukaModalEkstrak(baris) {
    barisModal = baris;
    if (modalNama) {
      modalNama.textContent = baris.getAttribute('data-sg-nama') || '';
    }
    if (modalPassphrase) {
      modalPassphrase.value = '';
    }
    if (modalTombolEkstrak) {
      modalTombolEkstrak.setAttribute(
        'data-reauth-resource', baris.getAttribute('data-sg-id') || ''
      );
    }
    if (modalEkstrak && window.KX && KX.modal) {
      KX.modal.buka(modalEkstrak);
    }
  }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      tutupSemuaMenu();
    }
  });

  document.addEventListener('click', function (event) {
    var tombolMenu = event.target.closest('[data-sg-menu]');
    if (tombolMenu) {
      toggleMenu(tombolMenu);
      return;
    }

    if (!event.target.closest('.kx-sg-menu')) {
      tutupSemuaMenu();
    }

    if (event.target.closest('[data-sg-tutup-modal]')) {
      tutupModalEkstrak();
      return;
    }

    var itemEkstrak = event.target.closest('[data-sg-ekstrak]');
    if (itemEkstrak) {
      tutupSemuaMenu();
      var baris = itemEkstrak.closest('tr[data-sg-id]');
      if (baris) {
        bukaModalEkstrak(baris);
      }
      return;
    }

    var itemHapus = event.target.closest('[data-sg-hapus]');
    if (itemHapus) {
      tutupSemuaMenu();
      var barisHapus = itemHapus.closest('tr[data-sg-id]');
      if (!barisHapus) {
        return;
      }
      var nama = barisHapus.getAttribute('data-sg-nama') || '';
      var urlHapus = barisHapus.getAttribute('data-sg-hapus-url') || '';
      var kirim = function () {
        if (formHapus && urlHapus) {
          formHapus.action = urlHapus;
          formHapus.submit();
        }
      };
      if (window.KX && typeof KX.konfirmasiHapus === 'function') {
        KX.konfirmasiHapus({
          judul: pesan('delete-title'),
          nama: nama,
          pesan: pesan('delete-message', { nama: nama }),
          onKonfirmasi: kirim
        });
      } else {
        kirim();
      }
      return;
    }

    if (event.target.closest('[data-sg-fokus-sisip]')) {
      var target = inputPesan || formSisip;
      if (target && target.scrollIntoView) {
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
      if (inputPesan) {
        inputPesan.focus();
      }
    }
  });

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      tutupSemuaMenu();
    }
    if (event.key === 'Enter' && event.target === modalPassphrase) {
      event.preventDefault();
      if (modalTombolEkstrak) {
        modalTombolEkstrak.click();
      }
    }
  });

  // ── Grant autentikasi ulang ──────────────────────────────────────────
  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detail = event.detail || {};
    if (detail.scope !== 'stego.extract') {
      return;
    }
    if (detail.resource) {
      var baris = document.querySelector(
        'tr[data-sg-id="' + String(detail.resource) + '"]'
      );
      if (!baris) {
        return;
      }
      var data = new FormData();
      if (modalPassphrase && modalPassphrase.value) {
        data.append('passphrase', modalPassphrase.value);
      }
      kirimEkstraksi(
        baris.getAttribute('data-sg-ekstrak-url'), data, detail.token, true
      );
      return;
    }
    if (formEkstrakUnggah) {
      kirimEkstraksi(
        formEkstrakUnggah.action,
        new FormData(formEkstrakUnggah),
        detail.token,
        false
      );
    }
  });

  // Enter di dalam formulir ekstrak unggahan harus melewati tombol grant,
  // bukan mengirim POST langsung tanpa verifikasi ulang.
  document.addEventListener('submit', function (event) {
    if (!formEkstrakUnggah || event.target !== formEkstrakUnggah) {
      return;
    }
    event.preventDefault();
    var tombol = formEkstrakUnggah.querySelector('[data-reauth="stego.extract"]');
    if (tombol) {
      tombol.click();
    }
  }, true);

  // ── Keadaan awal ─────────────────────────────────────────────────────
  aturJenisMuatan();
  aturKunci();
  sinkronEnkripsi();
})();
