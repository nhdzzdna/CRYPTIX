/**
 * static/js/account_vault.js
 * ───────────────────────────
 * Menampilkan kredensial Account Vault hanya setelah grant account.reveal.
 *
 * Data yang ditampilkan tidak pernah ada di HTML awal; isinya diambil lewat
 * POST /account-vault/reveal/<id> dengan header X-Reauth-Grant. Tampilan
 * dibersihkan dari DOM setelah 15 detik dan clipboard dikosongkan setelah
 * 20 detik sebagai upaya terbaik.
 */
(function () {
  'use strict';

  var TAMPIL_MS = 15000;
  var CLIPBOARD_MS = 20000;
  var timerTampil = new Map();

  function kartu(id) {
    return document.querySelector('[data-entry="' + id + '"]');
  }

  function status(id, teks) {
    var el = document.querySelector('[data-reveal-status="' + id + '"]');
    if (el) {
      el.textContent = teks || '';
    }
  }

  function isiKotak(id, namaField, nilai) {
    var kartuEl = kartu(id);
    if (!kartuEl) {
      return;
    }
    var el = kartuEl.querySelector('[data-field="' + namaField + '"]');
    if (el) {
      el.textContent = nilai == null ? '' : String(nilai);
    }
  }

  function isiForm(id, data) {
    var kartuEl = kartu(id);
    if (!kartuEl) {
      return;
    }
    var form = kartuEl.querySelector('[data-edit-form]');
    if (!form) {
      return;
    }
    var nilai = {
      site_name: data.site_name,
      username: data.username,
      password: data.password,
      url: data.url,
      notes: data.notes
    };
    Object.keys(nilai).forEach(function (nama) {
      var input = form.querySelector('[name="' + nama + '"]');
      if (input) {
        input.value = nilai[nama] == null ? '' : String(nilai[nama]);
      }
    });
    form.hidden = false;
  }

  function bersihkan(id) {
    var kartuEl = kartu(id);
    if (!kartuEl) {
      return;
    }
    kartuEl.querySelectorAll('[data-field]').forEach(function (el) {
      el.textContent = '';
    });
    var kotak = kartuEl.querySelector('[data-reveal-box]');
    if (kotak) {
      kotak.hidden = true;
    }
    var form = kartuEl.querySelector('[data-edit-form]');
    if (form) {
      form.querySelectorAll('input, textarea').forEach(function (el) {
        if (el.type !== 'hidden') {
          el.value = '';
        }
      });
      form.hidden = true;
    }
    var hitung = kartuEl.querySelector('[data-countdown]');
    if (hitung) {
      hitung.textContent = '';
    }
    var t = timerTampil.get(String(id));
    if (t) {
      clearInterval(t);
      timerTampil.delete(String(id));
    }
    status(id, 'Data telah disembunyikan.');
  }

  function mulaiHitung(id) {
    var kunci = String(id);
    var sisa = Math.floor(TAMPIL_MS / 1000);
    var lama = timerTampil.get(kunci);
    if (lama) {
      clearInterval(lama);
    }
    status(id, '');
    var hitung = document.querySelector('[data-countdown="' + id + '"]');
    if (hitung) {
      hitung.textContent = 'Data disembunyikan otomatis dalam ' + sisa + ' detik.';
    }
    var timer = window.setInterval(function () {
      sisa -= 1;
      if (sisa <= 0) {
        bersihkan(id);
        return;
      }
      if (hitung) {
        hitung.textContent = 'Data disembunyikan otomatis dalam ' + sisa + ' detik.';
      }
    }, 1000);
    timerTampil.set(kunci, timer);
  }

  function tampilkan(id, data) {
    isiKotak(id, 'username', data.username);
    isiKotak(id, 'password', data.password);
    isiKotak(id, 'url', data.url);
    isiKotak(id, 'notes', data.notes);
    isiForm(id, data);

    var kartuEl = kartu(id);
    var kotak = kartuEl ? kartuEl.querySelector('[data-reveal-box]') : null;
    if (kotak) {
      kotak.hidden = false;
    }
    mulaiHitung(id);
  }

  function ambilData(id, grant) {
    var tombol = document.querySelector('[data-reveal-id="' + id + '"]');
    if (!tombol) {
      return;
    }
    var url = tombol.getAttribute('data-reveal-url');

    status(id, 'Memuat…');
    apiFetch(url, {
      method: 'POST',
      headers: grant ? { 'X-Reauth-Grant': grant } : {},
      credentials: 'same-origin'
    }).then(function (resp) {
      return resp.json().then(function (data) {
        if (!resp.ok || !data.success) {
          throw new Error(data.error || 'Gagal menampilkan kredensial.');
        }
        return data;
      });
    }).then(function (data) {
      tampilkan(id, data);
    }).catch(function (err) {
      status(id, err.message);
    });
  }

  function salin(teks, id) {
    if (!teks || !navigator.clipboard) {
      status(id, 'Clipboard tidak tersedia.');
      return;
    }
    navigator.clipboard.writeText(teks).then(function () {
      status(id, 'Disalin. Clipboard dikosongkan dalam 20 detik.');
      window.setTimeout(function () {
        navigator.clipboard.writeText('').catch(function () {
          // Upaya terbaik: peramban dapat menolak penulisan tanpa fokus.
        });
      }, CLIPBOARD_MS);
    }).catch(function () {
      status(id, 'Gagal menyalin ke clipboard.');
    });
  }

  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detail = event.detail || {};
    if (detail.scope !== 'account.reveal' || !detail.resource) {
      return;
    }
    ambilData(String(detail.resource), detail.token);
  });

  document.addEventListener('submit', function (event) {
    var form = event.target.closest('[data-edit-form]');
    if (!form) {
      return;
    }
    event.preventDefault();
    var tombol = form.querySelector('button[type="submit"]');
    if (tombol) {
      tombol.click();
    }
  }, true);

  document.addEventListener('click', function (event) {
    var batal = event.target.closest('[data-edit-cancel]');
    if (batal) {
      var form = kartu(batal.getAttribute('data-edit-cancel'));
      form = form ? form.querySelector('[data-edit-form]') : null;
      if (form) {
        form.hidden = true;
      }
      return;
    }

    var tombolSalin = event.target.closest('[data-copy-field]');
    if (!tombolSalin) {
      return;
    }
    var kartuEl = tombolSalin.closest('[data-entry]');
    if (!kartuEl) {
      return;
    }
    var id = kartuEl.getAttribute('data-entry');
    var field = tombolSalin.getAttribute('data-copy-field');
    var el = kartuEl.querySelector('[data-field="' + field + '"]');
    salin(el ? el.textContent : '', id);
  });
})();
