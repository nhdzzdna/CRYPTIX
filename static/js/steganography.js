/**
 * static/js/steganography.js
 * ──────────────────────────
 * Interaksi halaman Steganography: indikator kapasitas, pilihan kunci,
 * serta ekstraksi teks/berkas tanpa memuat ulang halaman.
 */
(function () {
  'use strict';

  var form = document.getElementById('stego-embed-form');
  if (!form) {
    return;
  }

  var capacityUrl = form.getAttribute('data-capacity-url');
  var csrfInput = form.querySelector('input[name="csrf_token"]');
  var capacityBox = document.getElementById('stego-capacity');
  var carrierInput = document.getElementById('carrier-image');
  var messageInput = document.getElementById('stego-message');
  var fileInput = document.getElementById('payload-file');
  var typeText = document.getElementById('type-text');
  var typeFile = document.getElementById('type-file');
  var messageGroup = document.getElementById('message-group');
  var fileGroup = document.getElementById('payload-file-group');
  var useEnc = document.getElementById('use-enc');
  var keyPassphrase = document.getElementById('key-passphrase');
  var passphraseGroup = document.getElementById('passphrase-group');
  var passphraseInput = document.getElementById('embed-passphrase');
  var submitButton = form.querySelector('button[type="submit"]');
  var capacity = null;

  function isFilePayload() {
    return typeFile.checked;
  }

  function perkiraanByte() {
    var overhead = useEnc && useEnc.checked ? 192 : 0;
    if (isFilePayload()) {
      var berkas = fileInput.files[0];
      return berkas ? berkas.size + berkas.name.length + 64 + overhead : 0;
    }
    var teks = messageInput.value || '';
    return new TextEncoder().encode(teks).length + overhead;
  }

  function perbaruiKapasitas() {
    if (!capacityBox) {
      return;
    }
    var used = perkiraanByte();
    if (capacity === null) {
      capacityBox.className = 'alert alert-info py-2';
      capacityBox.textContent =
        'Perkiraan terpakai: ' + used +
        ' byte (pilih gambar pembawa untuk melihat kapasitas).';
      if (submitButton) {
        submitButton.disabled = false;
      }
      return;
    }

    var sisa = capacity - used;
    capacityBox.className = sisa >= 0
      ? 'alert alert-info py-2'
      : 'alert alert-danger py-2';
    capacityBox.textContent =
      'Kapasitas: ' + capacity + ' byte · ' +
      'Perkiraan terpakai: ' + used + ' byte · ' +
      (sisa >= 0
        ? 'Sisa: ' + sisa + ' byte.'
        : 'Melebihi kapasitas sebanyak ' + Math.abs(sisa) + ' byte.');
    if (submitButton) {
      submitButton.disabled = sisa < 0;
    }
  }

  function aturJenisMuatan() {
    var fileMode = isFilePayload();
    messageGroup.style.display = fileMode ? 'none' : '';
    fileGroup.style.display = fileMode ? '' : 'none';
    perbaruiKapasitas();
  }

  function aturPilihanKunci() {
    var passphraseMode = keyPassphrase.checked;
    passphraseGroup.style.display = passphraseMode ? '' : 'none';
    if (!passphraseMode && passphraseInput) {
      passphraseInput.value = '';
    }
  }

  if (typeText) {
    typeText.addEventListener('change', aturJenisMuatan);
  }
  if (typeFile) {
    typeFile.addEventListener('change', aturJenisMuatan);
  }
  if (keyPassphrase) {
    keyPassphrase.addEventListener('change', aturPilihanKunci);
  }
  var keyAccount = document.getElementById('key-account');
  if (keyAccount) {
    keyAccount.addEventListener('change', aturPilihanKunci);
  }
  if (messageInput) {
    messageInput.addEventListener('input', perbaruiKapasitas);
  }
  if (fileInput) {
    fileInput.addEventListener('change', perbaruiKapasitas);
  }
  if (useEnc) {
    useEnc.addEventListener('change', perbaruiKapasitas);
  }

  if (carrierInput && capacityUrl) {
    carrierInput.addEventListener('change', function () {
      var berkas = carrierInput.files[0];
      if (!berkas) {
        capacity = null;
        perbaruiKapasitas();
        return;
      }

      var data = new FormData();
      data.append('carrier_image', berkas);
      if (csrfInput) {
        data.append('csrf_token', csrfInput.value);
      }

      apiFetch(capacityUrl, { method: 'POST', body: data })
        .then(function (resp) {
          return resp.json().then(function (info) {
            return { ok: resp.ok, info: info };
          });
        })
        .then(function (hasil) {
          if (!hasil.ok || hasil.info.error) {
            capacity = null;
            capacityBox.className = 'alert alert-danger py-2';
            capacityBox.textContent = hasil.info.error ||
              'Kapasitas gambar tidak dapat dibaca.';
            perbaruiKapasitas();
            return;
          }
          capacity = hasil.info.capacity;
          perbaruiKapasitas();
        })
        .catch(function () {
          capacity = null;
          capacityBox.className = 'alert alert-danger py-2';
          capacityBox.textContent = 'Kapasitas gambar tidak dapat dibaca.';
          perbaruiKapasitas();
        });
    });
  }

  // ── Tampilan hasil ekstraksi di dalam halaman ─────────────────────────────
  var resultBox = document.getElementById('stego-result');

  function tampilkanHasil(kelas, judul, isi) {
    if (!resultBox) {
      return;
    }
    resultBox.textContent = '';
    var kotak = document.createElement('div');
    kotak.className = 'alert ' + kelas;
    var heading = document.createElement('strong');
    heading.textContent = judul;
    kotak.appendChild(heading);
    if (isi) {
      var isiNode = document.createElement('pre');
      isiNode.className = 'mb-0 mt-2';
      isiNode.style.whiteSpace = 'pre-wrap';
      isiNode.textContent = isi;
      kotak.appendChild(isiNode);
    }
    resultBox.appendChild(kotak);
  }

  function namaBerkasDari(header) {
    if (!header) {
      return null;
    }
    var match = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(header);
    if (!match) {
      return null;
    }
    var nama = match[1].replace(/^"|"$/g, '');
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

  function kirimEkstraksi(formEkstrak, token) {
    tampilkanHasil('alert-info', 'Memproses ekstraksi…', null);

    var data = new FormData(formEkstrak);
    var csrf = formEkstrak.querySelector('input[name="csrf_token"]');
    if (csrf && !data.get('csrf_token')) {
      data.append('csrf_token', csrf.value);
    }

    var headers = {};
    if (token) {
      headers['X-Reauth-Grant'] = token;
    }

    apiFetch(formEkstrak.action, {
      method: 'POST',
      headers: headers,
      body: data
    })
      .then(function (resp) {
        var tipe = resp.headers.get('Content-Type') || '';
        if (tipe.indexOf('application/json') !== -1) {
          return resp.json().then(function (payload) {
            if (!resp.ok || !payload.success) {
              throw new Error(payload.error || 'Ekstraksi gagal.');
            }
            if (payload.type === 'text') {
              tampilkanHasil('alert-success', 'Pesan hasil ekstraksi:', payload.text);
            } else {
              tampilkanHasil('alert-success', payload.message || 'Ekstraksi berhasil.', null);
            }
          });
        }

        if (!resp.ok) {
          throw new Error('Ekstraksi gagal.');
        }
        return resp.blob().then(function (blob) {
          var nama = namaBerkasDari(resp.headers.get('Content-Disposition')) ||
            'berkas-hasil';
          unduhBlob(blob, nama);
          tampilkanHasil('alert-success',
            'Berkas berhasil diekstrak dan diunduh: ' + nama, null);
        });
      })
      .catch(function (err) {
        tampilkanHasil('alert-danger', 'Ekstraksi gagal.', err.message);
      });
  }

  function formUntukResource(resource) {
    var daftar = document.querySelectorAll('.stego-extract-form');
    for (var i = 0; i < daftar.length; i += 1) {
      if (daftar[i].getAttribute('data-reauth-resource') === String(resource)) {
        return daftar[i];
      }
    }
    return null;
  }

  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detail = event.detail || {};
    if (detail.scope !== 'stego.extract') {
      return;
    }
    var formEkstrak;
    if (detail.resource) {
      formEkstrak = formUntukResource(detail.resource);
    } else {
      formEkstrak = document.querySelector(
        '.stego-extract-form[data-stego-upload="1"]'
      );
    }
    if (formEkstrak) {
      kirimEkstraksi(formEkstrak, detail.token);
    }
  });

  document.querySelectorAll('.stego-extract-form').forEach(function (formEkstrak) {
    formEkstrak.addEventListener('submit', function (event) {
      event.preventDefault();
      var tombol = formEkstrak.querySelector('[data-reauth="stego.extract"]');
      if (tombol) {
        tombol.click();
      }
    });
  });

  document.querySelectorAll('.stego-delete-form').forEach(function (formHapus) {
    formHapus.addEventListener('submit', function (event) {
      if (!window.confirm('Hapus gambar stego ini?')) {
        event.preventDefault();
      }
    });
  });

  aturJenisMuatan();
  aturPilihanKunci();
})();
