/**
 * static/js/musik.js
 * ─────────────────
 * Pemutar HTML5 halaman Musik: putar, jeda, trek sebelumnya/berikutnya
 * dalam folder yang sama, serta pemilihan trek dengan klik.
 */
(function () {
  'use strict';

  var audio = document.getElementById('music-audio');
  var judul = document.getElementById('music-now-playing');
  var tombolPutar = document.getElementById('music-play-toggle');
  var tombolSebelum = document.getElementById('music-prev');
  var tombolSesudah = document.getElementById('music-next');
  var formWinamp = document.getElementById('music-winamp-form');
  var tombolWinamp = document.getElementById('music-winamp');
  if (!audio) {
    return;
  }

  var daftar = [];
  var indeks = -1;
  var trekAktif = null;

  function pesan(kunci) {
    var kotak = document.getElementById('collection-messages');
    return kotak ? (kotak.getAttribute('data-msg-' + kunci) || '') : '';
  }

  function teksPutar(aktif) {
    if (!tombolPutar) {
      return;
    }
    var label = aktif ? pesan('pause') : pesan('play');
    var teks = tombolPutar.querySelector('[data-play-label]');
    if (teks) {
      teks.textContent = label;
    } else {
      tombolPutar.textContent = label;
    }
    tombolPutar.setAttribute('data-playing', aktif ? 'true' : 'false');
  }

  function labelTrek(kartu) {
    return kartu ? (kartu.getAttribute('data-name') || '') : pesan('no-track');
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
    var wadah = kartu.closest('[data-track-list]');
    daftar = wadah
      ? Array.prototype.slice.call(wadah.querySelectorAll('[data-track]'))
      : [kartu];
    indeks = daftar.indexOf(kartu);
    if (trekAktif && trekAktif !== kartu) {
      trekAktif.classList.remove('is-playing');
    }
    trekAktif = kartu;
    kartu.classList.add('is-playing');
    var url = kartu.getAttribute('data-view-url');
    judul.textContent = labelTrek(kartu);
    siapkanWinamp(kartu);
    if (!url) {
      return;
    }
    audio.src = url;
    audio.load();
    var janji = audio.play();
    if (janji && typeof janji.catch === 'function') {
      janji.catch(function () { /* pemutaran otomatis dapat ditolak */ });
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
      window.CryptixReauth.grantFor('item.view',
        kartu.getAttribute('data-file-id')));
  }

  document.addEventListener('click', function (event) {
    var pemicu = event.target.closest('[data-track-play], .music-track-name');
    if (!pemicu) {
      return;
    }
    var kartu = pemicu.closest('[data-track]');
    if (!kartu) {
      return;
    }
    if (!bolehDiputar(kartu)) {
      // Trek terkunci: dialog pilihan lihat sekali / lepas kunci.
      if (window.CryptixLock) {
        window.CryptixLock.pilih(kartu, putarKartu);
      }
      return;
    }
    putarKartu(kartu);
  });

  if (tombolPutar) {
    tombolPutar.addEventListener('click', function () {
      if (!audio.src) {
        if (daftar.length) {
          putarKartu(daftar[0]);
        }
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

  audio.addEventListener('play', function () { teksPutar(true); });
  audio.addEventListener('pause', function () { teksPutar(false); });
  audio.addEventListener('ended', function () { geser(1); });
  audio.addEventListener('error', function () {
    if (audio.src) {
      teksPutar(false);
    }
  });

  teksPutar(false);
})();
