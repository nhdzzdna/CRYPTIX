/**
 * static/js/crypto_tools.js
 * ──────────────────────────
 * Formulir Crypto Tools: kartu algoritma, segmented Enkripsi/Dekripsi,
 * penyaringan kunci Vigenere, salin hasil, dan status tombol Proses.
 *
 * Nilai cipher dan action disimpan pada input tersembunyi agar alur POST
 * tidak berubah. Semua teks pesan dibaca dari atribut data-msg-* pada akar
 * halaman (modules/strings.py), bukan teks JS.
 */
(function () {
  'use strict';

  var akar = document.querySelector('.kx-ct-page');
  if (!akar) {
    return;
  }

  var form = document.getElementById('crypto-form');
  var inputCipher = document.getElementById('ct-cipher');
  var inputAksi = document.getElementById('ct-aksi');
  var fieldKunci = document.getElementById('ct-kunci-field');
  var fieldPassphrase = document.getElementById('ct-passphrase-field');
  var fieldSteps = document.getElementById('ct-steps-field');
  var inputKunci = document.getElementById('ct-kunci');
  var hintKunci = document.querySelector('[data-hint-kunci]');
  var hintVigenere = document.querySelector('[data-hint-vigenere]');
  var tombolProses = document.getElementById('ct-proses');
  var labelProses = document.getElementById('ct-proses-label');
  var tombolSalin = document.getElementById('ct-salin');
  var hasil = document.getElementById('ct-hasil');

  function pesan(kunci) {
    return akar.getAttribute('data-msg-' + kunci) || '';
  }

  function toast(teks, jenis) {
    if (window.KX && typeof KX.toast === 'function') {
      KX.toast(teks, jenis);
    }
  }

  function filterVigenereKey() {
    if (!inputKunci || inputCipher.value !== 'vigenere') {
      return;
    }
    const cleaned = inputKunci.value.replace(/[^A-Za-z]/g, '');
    if (cleaned !== inputKunci.value) {
      inputKunci.value = cleaned;
    }
  }

  function perbaruiForm() {
    var cipher = inputCipher.value;
    var aksi = inputAksi.value;
    var isSuper = cipher === 'super';
    var isVigenere = cipher === 'vigenere';

    if (fieldKunci) {
      fieldKunci.hidden = isSuper;
    }
    if (fieldPassphrase) {
      fieldPassphrase.hidden = !isSuper;
    }
    if (fieldSteps) {
      fieldSteps.hidden = !(isSuper && aksi === 'encrypt');
    }
    if (hintKunci) {
      hintKunci.hidden = isVigenere || isSuper;
    }
    if (hintVigenere) {
      hintVigenere.hidden = !isVigenere;
    }
    filterVigenereKey();
  }

  function pilihAlgoritma(nilai) {
    if (inputCipher) {
      inputCipher.value = nilai;
    }
    document.querySelectorAll('.kx-ct-algo').forEach(function (kartu) {
      var aktif = kartu.getAttribute('data-cipher') === nilai;
      kartu.classList.toggle('is-aktif', aktif);
      kartu.setAttribute('aria-pressed', aktif ? 'true' : 'false');
    });
    document.querySelectorAll('[data-deskripsi]').forEach(function (el) {
      el.hidden = el.getAttribute('data-deskripsi') !== nilai;
    });
    perbaruiForm();
  }

  function pilihAksi(nilai) {
    if (inputAksi) {
      inputAksi.value = nilai;
    }
    document.querySelectorAll('[data-aksi]').forEach(function (tombol) {
      var aktif = tombol.getAttribute('data-aksi') === nilai;
      tombol.classList.toggle('is-active', aktif);
      tombol.setAttribute('aria-pressed', aktif ? 'true' : 'false');
    });
    perbaruiForm();
  }

  function salinHasil() {
    if (!hasil || !navigator.clipboard) {
      toast(pesan('copy-failed'), 'danger');
      return;
    }
    navigator.clipboard.writeText(hasil.textContent).then(function () {
      toast(pesan('copy-done'), 'success');
    }).catch(function () {
      toast(pesan('copy-failed'), 'danger');
    });
  }

  document.querySelectorAll('.kx-ct-algo').forEach(function (kartu) {
    kartu.addEventListener('click', function () {
      pilihAlgoritma(kartu.getAttribute('data-cipher'));
    });
  });

  document.querySelectorAll('[data-aksi]').forEach(function (tombol) {
    tombol.addEventListener('click', function () {
      pilihAksi(tombol.getAttribute('data-aksi'));
    });
  });

  document.addEventListener('click', function (event) {
    if (event.target.closest('#ct-salin')) {
      salinHasil();
      return;
    }
    var fokus = event.target.closest('[data-ct-fokus]');
    if (fokus) {
      var teks = document.getElementById('ct-teks');
      if (teks) {
        teks.scrollIntoView({ behavior: 'smooth', block: 'center' });
        teks.focus();
      }
    }
  });

  if (inputKunci) {
    inputKunci.addEventListener('input', filterVigenereKey);
  }

  if (form) {
    form.addEventListener('submit', function () {
      if (tombolProses) {
        tombolProses.disabled = true;
      }
      if (labelProses) {
        labelProses.textContent = pesan('processing');
      }
    });
  }

  // Sinkronkan tampilan awal dengan nilai input tersembunyi dari server.
  if (inputCipher) {
    pilihAlgoritma(inputCipher.value);
  }
  if (inputAksi) {
    pilihAksi(inputAksi.value);
  }
})();
