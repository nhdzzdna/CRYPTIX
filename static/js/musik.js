/**
 * static/js/musik.js
 * ─────────────────
 * Pemutar audio kustom halaman Audio (U2b P5):
 * - Memutar audio HTML5 untuk trek terenkripsi (stream/view URL)
 * - Pemutar kustom di bagian bawah layar: cover placeholder, judul, folder,
 *   prev/next, play toggle (lingkaran teal), waktu berjalan, progress bar teal, total durasi.
 * - Tombol play bulat di setiap baris tabel.
 * - Pencarian trek lokal di sisi klien (memfilter baris tabel).
 * - Checkbox pilih semua dan sinkronisasi dengan KX.aksiMengambang.
 * - Menu ⋯ per baris: Buka di Winamp, Pindahkan, Kunci/Lepas Kunci, Hapus (ke Sampah via KX.konfirmasiHapus).
 * - Integrasi dengan CryptixLock untuk trek terkunci.
 */
(function () {
  'use strict';

  var audio = document.getElementById('music-audio');
  var judulBawah = document.getElementById('music-now-playing');
  var subBawah = document.getElementById('music-now-sub');
  var tombolPutar = document.getElementById('music-play-toggle');
  var tombolSebelum = document.getElementById('music-prev');
  var tombolSesudah = document.getElementById('music-next');
  var formWinamp = document.getElementById('music-winamp-form');
  var tombolWinamp = document.getElementById('music-winamp');
  var waktuKini = document.getElementById('music-time-cur');
  var waktuTotal = document.getElementById('music-time-total');
  var barKemajuan = document.getElementById('music-progress-bar');
  var isiKemajuan = document.getElementById('music-progress-fill');
  var kotakCari = document.getElementById('audio-search');
  var pilihSemua = document.getElementById('audio-select-all');

  if (!audio) {
    return;
  }

  var daftar = [];
  var indeks = -1;
  var trekAktif = null;

  function formatWaktu(detik) {
    if (isNaN(detik) || detik < 0) return '0:00';
    var m = Math.floor(detik / 60);
    var s = Math.floor(detik % 60);
    return m + ':' + (s < 10 ? '0' : '') + s;
  }

  function pesan(kunci) {
    var kotak = document.getElementById('collection-messages');
    return kotak ? (kotak.getAttribute('data-msg-' + kunci) || '') : '';
  }

  function teksPutar(aktif) {
    if (!tombolPutar) {
      return;
    }
    var ikonPlay = tombolPutar.querySelector('.audio-icon-play');
    var ikonPause = tombolPutar.querySelector('.audio-icon-pause');
    if (ikonPlay && ikonPause) {
      ikonPlay.hidden = aktif;
      ikonPause.hidden = !aktif;
    }
    tombolPutar.setAttribute('data-playing', aktif ? 'true' : 'false');
  }

  function siapkanWinamp(kartu) {
    if (!formWinamp || !tombolWinamp) {
      return;
    }
    if (!kartu) {
      tombolWinamp.hidden = true;
      tombolWinamp.setAttribute('data-reauth-resource', '');
      return;
    }
    var id = kartu.getAttribute('data-file-id');
    formWinamp.action = '/media-vault/play/' + id;
    tombolWinamp.setAttribute('data-reauth-resource', id);
    tombolWinamp.hidden = false;
  }

  function putarKartu(kartu) {
    if (!kartu) {
      return;
    }
    var wadah = kartu.closest('[data-track-list]') || kartu.closest('tbody');
    daftar = wadah
      ? Array.prototype.slice.call(wadah.querySelectorAll('[data-track]:not([hidden])'))
      : [kartu];
    indeks = daftar.indexOf(kartu);

    if (trekAktif && trekAktif !== kartu) {
      trekAktif.classList.remove('is-playing');
    }
    trekAktif = kartu;
    kartu.classList.add('is-playing');

    var url = kartu.getAttribute('data-view-url');
    var nama = kartu.getAttribute('data-name') || pesan('no-track');
    var folderNama = kartu.getAttribute('data-folder-name') || 'Audio';

    if (judulBawah) judulBawah.textContent = nama;
    if (subBawah) subBawah.textContent = folderNama;

    siapkanWinamp(kartu);
    if (!url) {
      return;
    }

    audio.src = url;
    audio.load();
    var janji = audio.play();
    if (janji && typeof janji.catch === 'function') {
      janji.catch(function () {});
    }
  }

  function geser(arah) {
    if (!daftar.length) {
      return;
    }
    indeks = (indeks + arah + daftar.length) % daftar.length;
    putarKartu(daftar[indeks]);
  }

  function bolehDiputar(kartu) {
    if (!kartu) {
      return false;
    }
    if (kartu.getAttribute('data-locked') !== '1') {
      return true;
    }
    return Boolean(window.CryptixReauth &&
      window.CryptixReauth.grantFor('item.view', kartu.getAttribute('data-file-id')));
  }

  // Klik putar pada tabel
  document.addEventListener('click', function (event) {
    var pemicu = event.target.closest('[data-track-play], .music-track-name, .kx-audio-track-title');
    if (!pemicu) {
      return;
    }
    var kartu = pemicu.closest('[data-track]');
    if (!kartu) {
      return;
    }
    if (!bolehDiputar(kartu)) {
      if (window.CryptixLock) {
        window.CryptixLock.pilih(kartu, putarKartu, 'item.view');
      }
      return;
    }
    putarKartu(kartu);
  });

  // Kontrol tombol bar bawah
  if (tombolPutar) {
    tombolPutar.addEventListener('click', function () {
      if (!audio.src) {
        var pertama = document.querySelector('[data-track]:not([hidden])');
        if (pertama) putarKartu(pertama);
        return;
      }
      if (audio.paused) {
        audio.play().catch(function () {});
      } else {
        audio.pause();
      }
    });
  }

  if (tombolSebelum) {
    tombolSebelum.addEventListener('click', function () { geser(-1); });
  }
  if (tombolSesudah) {
    tombolSesudah.addEventListener('click', function () { geser(1); });
  }

  // Waktu dan progress bar
  audio.addEventListener('play', function () { teksPutar(true); });
  audio.addEventListener('pause', function () { teksPutar(false); });
  audio.addEventListener('ended', function () { geser(1); });
  audio.addEventListener('error', function () {
    if (audio.src) teksPutar(false);
  });

  audio.addEventListener('timeupdate', function () {
    if (waktuKini) waktuKini.textContent = formatWaktu(audio.currentTime);
    if (audio.duration && !isNaN(audio.duration)) {
      if (waktuTotal) waktuTotal.textContent = formatWaktu(audio.duration);
      if (isiKemajuan) {
        var pct = (audio.currentTime / audio.duration) * 100;
        isiKemajuan.style.width = pct + '%';
      }
    }
  });

  if (barKemajuan) {
    barKemajuan.addEventListener('click', function (e) {
      if (!audio.duration || isNaN(audio.duration)) return;
      var rect = barKemajuan.getBoundingClientRect();
      var rasio = (e.clientX - rect.left) / rect.width;
      audio.currentTime = rasio * audio.duration;
    });
  }

  // ── Pencarian trek di sisi klien ─────────────────────────────────────────
  if (kotakCari) {
    kotakCari.addEventListener('input', function () {
      var kueri = kotakCari.value.trim().toLowerCase();
      var barisList = document.querySelectorAll('[data-track]');
      barisList.forEach(function (tr) {
        var nama = (tr.getAttribute('data-name') || '').toLowerCase();
        var cocok = !kueri || nama.indexOf(kueri) !== -1;
        tr.hidden = !cocok;
      });
      var pesanTakAda = document.getElementById('audio-no-results');
      if (pesanTakAda) {
        var adaYangTampil = Array.prototype.some.call(barisList, function (tr) { return !tr.hidden; });
        pesanTakAda.hidden = barisList.length === 0 || adaYangTampil;
      }
    });
  }

  // ── Checkbox pilih semua & sinkronisasi ──────────────────────────────────
  if (pilihSemua) {
    pilihSemua.addEventListener('change', function () {
      var cek = pilihSemua.checked;
      document.querySelectorAll('[data-select-file]').forEach(function (cb) {
        var tr = cb.closest('[data-track]');
        if (tr && !tr.hidden) {
          cb.checked = cek;
          cb.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
    });
  }

  // ── Menu titik tiga (⋯) ──────────────────────────────────────────────────
  document.addEventListener('click', function (event) {
    var tombolMenu = event.target.closest('[data-menu-toggle]');
    var semuaMenu = document.querySelectorAll('[data-menu-dropdown]');

    if (tombolMenu) {
      event.stopPropagation();
      var wrap = tombolMenu.closest('.kx-audio-menu-wrap');
      var dropdown = wrap ? wrap.querySelector('[data-menu-dropdown]') : null;
      var isOpen = dropdown && !dropdown.hidden;
      semuaMenu.forEach(function (d) { d.hidden = true; });
      if (dropdown) dropdown.hidden = isOpen;
      return;
    }

    semuaMenu.forEach(function (d) { d.hidden = true; });
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
    var baris = form.closest('[data-track]');
    var namaItem = baris ? baris.getAttribute('data-name') : 'trek audio ini';

    if (window.KX && typeof window.KX.konfirmasiHapus === 'function') {
      window.KX.konfirmasiHapus({
        judul: 'Pindahkan ke Sampah?',
        nama: namaItem,
        pesan: 'Trek {nama} akan dipindahkan ke Sampah. Anda masih dapat memulihkannya dari sana.',
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

  // Sinkronisasi checkbox data-kx-pilih
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

  teksPutar(false);
})();
