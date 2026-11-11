/**
 * static/js/account_vault.js
 * ───────────────────────────
 * Menampilkan kredensial Account Vault hanya setelah grant account.reveal.
 *
 * Data yang ditampilkan tidak pernah ada di HTML awal; isinya diambil lewat
 * POST /account-vault/reveal/<id> dengan header X-Reauth-Grant. Tampilan
 * dibersihkan dari DOM setelah 15 detik dan clipboard dikosongkan setelah
 * 30 detik sebagai upaya terbaik. Semua teks antarmuka dibaca dari atribut
 * data-msg-* pada akar halaman (modules/strings.py), bukan teks JS.
 */
(function () {
  'use strict';

  var TAMPIL_MS = 15000;
  var CLIPBOARD_MS = 30000;
  var PANJANG_ACAK = 16;
  var HIMPUNAN_ACAK = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_-+=';

  var akar = document.querySelector('.kx-av-page');
  if (!akar) {
    return;
  }

  // Niat aksi setelah grant terbit: 'salin' menyalin kata sandi segera
  // setelah data tampil. Direset setiap kali modal reauth ditutup supaya
  // tidak ada niat basi yang terbawa ke aksi berikutnya.
  var niat = null;
  var timerTampil = new Map();
  var kataSandi = new Map();

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

  function baris(id) {
    return document.querySelector('[data-entry="' + id + '"]');
  }

  function pemicu(id) {
    return document.querySelector('[data-reveal-id="' + id + '"]');
  }

  function setLabelPemicu(id, memuat) {
    var tombol = pemicu(id);
    if (!tombol) {
      return;
    }
    var span = tombol.querySelector('span');
    if (!span) {
      return;
    }
    if (memuat) {
      if (!tombol.getAttribute('data-label-asli')) {
        tombol.setAttribute('data-label-asli', span.textContent);
      }
      tombol.disabled = true;
      span.textContent = pesan('reveal-loading');
    } else {
      tombol.disabled = false;
      span.textContent = tombol.getAttribute('data-label-asli') || span.textContent;
    }
  }

  function isiKotak(id, data) {
    var barisEl = baris(id);
    if (!barisEl) {
      return;
    }
    ['username', 'url', 'notes'].forEach(function (nama) {
      var el = barisEl.querySelector('[data-field="' + nama + '"]');
      if (el) {
        el.textContent = data[nama] == null ? '' : String(data[nama]);
      }
    });
    var sandi = barisEl.querySelector('[data-field-password]');
    if (sandi) {
      sandi.type = 'password';
      sandi.value = data.password == null ? '' : String(data.password);
    }
    kataSandi.set(String(id), data.password == null ? '' : String(data.password));
  }

  function isiForm(id, data) {
    var barisEl = baris(id);
    if (!barisEl) {
      return;
    }
    var form = barisEl.querySelector('[data-edit-form]');
    if (!form) {
      return;
    }
    ['site_name', 'username', 'password', 'url', 'notes'].forEach(function (nama) {
      var input = form.querySelector('[name="' + nama + '"]');
      if (input) {
        input.value = data[nama] == null ? '' : String(data[nama]);
      }
    });
  }

  function hentikanHitung(id) {
    var timer = timerTampil.get(String(id));
    if (timer) {
      window.clearInterval(timer);
      timerTampil.delete(String(id));
    }
  }

  function bersihkan(id, otomatis) {
    var barisEl = baris(id);
    if (!barisEl) {
      return;
    }
    var kotak = barisEl.querySelector('[data-reveal-box]');
    if (kotak) {
      kotak.querySelectorAll('[data-field]').forEach(function (el) {
        el.textContent = '';
      });
      var sandi = kotak.querySelector('[data-field-password]');
      if (sandi) {
        sandi.value = '';
      }
      kotak.hidden = true;
    }
    var form = barisEl.querySelector('[data-edit-form]');
    if (form) {
      form.querySelectorAll('input, textarea').forEach(function (el) {
        if (el.type !== 'hidden') {
          el.value = '';
        }
      });
      form.hidden = true;
    }
    var hitung = barisEl.querySelector('[data-countdown]');
    if (hitung) {
      hitung.textContent = '';
    }
    kataSandi.delete(String(id));
    hentikanHitung(id);
    if (otomatis) {
      toast(pesan('reveal-hidden'), 'info');
    }
  }

  function mulaiHitung(id) {
    var barisEl = baris(id);
    if (!barisEl) {
      return;
    }
    var hitung = barisEl.querySelector('[data-countdown]');
    hentikanHitung(id);
    var sisa = Math.floor(TAMPIL_MS / 1000);
    function perbarui() {
      if (hitung) {
        hitung.textContent = pesan('reveal-countdown', { detik: sisa });
      }
    }
    perbarui();
    var timer = window.setInterval(function () {
      sisa -= 1;
      if (sisa <= 0) {
        hentikanHitung(id);
        bersihkan(id, true);
        return;
      }
      perbarui();
    }, 1000);
    timerTampil.set(String(id), timer);
  }

  function tampilkan(id, data) {
    var barisEl = baris(id);
    if (!barisEl) {
      return;
    }
    isiKotak(id, data);
    isiForm(id, data);
    var kotak = barisEl.querySelector('[data-reveal-box]');
    var form = barisEl.querySelector('[data-edit-form]');
    if (kotak) {
      kotak.hidden = false;
    }
    if (form) {
      form.hidden = true;
    }
    mulaiHitung(id);
  }

  function salinKeClipboard(teks) {
    if (!teks || !navigator.clipboard) {
      toast(pesan('copy-failed'), 'danger');
      return;
    }
    navigator.clipboard.writeText(teks).then(function () {
      toast(pesan('copy-done'), 'success');
      window.setTimeout(function () {
        navigator.clipboard.writeText('').catch(function () {
          // Upaya terbaik: peramban dapat menolak penulisan tanpa fokus.
        });
      }, CLIPBOARD_MS);
    }).catch(function () {
      toast(pesan('copy-failed'), 'danger');
    });
  }

  function salinKataSandi(id) {
    var nilai = kataSandi.get(String(id));
    if (nilai == null) {
      // Belum pernah tampil: minta verifikasi ulang lewat tombol Tampilkan.
      niat = 'salin';
      var tombol = pemicu(id);
      if (tombol) {
        tombol.click();
      }
      return;
    }
    salinKeClipboard(nilai);
  }

  function ambilData(id, grant, niatGunakan) {
    var tombol = pemicu(id);
    if (!tombol) {
      return;
    }
    var url = tombol.getAttribute('data-reveal-url');
    setLabelPemicu(id, true);

    apiFetch(url, {
      method: 'POST',
      headers: grant ? { 'X-Reauth-Grant': grant } : {},
      credentials: 'same-origin'
    }).then(function (resp) {
      return resp.json().then(function (data) {
        if (!resp.ok || !data.success) {
          throw new Error(data.error || pesan('reveal-failed'));
        }
        return data;
      });
    }).then(function (data) {
      setLabelPemicu(id, false);
      tampilkan(id, data);
      if (niatGunakan === 'salin') {
        salinKeClipboard(kataSandi.get(String(id)) || '');
      }
    }).catch(function (err) {
      setLabelPemicu(id, false);
      toast(err && err.message ? err.message : pesan('reveal-failed'), 'danger');
    });
  }

  function acakIndeks(maks) {
    // Penolakan nilai di luar batas agar tidak ada bias modulo.
    var batas = Math.floor(4294967296 / maks) * maks;
    var penyangga = new Uint32Array(1);
    var nilai;
    do {
      window.crypto.getRandomValues(penyangga);
      nilai = penyangga[0];
    } while (nilai >= batas);
    return nilai % maks;
  }

  function buatOtomatis(input) {
    if (!window.crypto || !window.crypto.getRandomValues) {
      return;
    }
    var hasil = '';
    for (var i = 0; i < PANJANG_ACAK; i += 1) {
      hasil += HIMPUNAN_ACAK.charAt(acakIndeks(HIMPUNAN_ACAK.length));
    }
    input.value = hasil;
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }

  // ── Aksi klik ────────────────────────────────────────────────────────
  document.addEventListener('click', function (event) {
    var el = event.target.closest('[data-av-tutup]');
    if (el) {
      bersihkan(el.getAttribute('data-av-tutup'), false);
      return;
    }

    el = event.target.closest('[data-av-edit]');
    if (el) {
      var id = el.getAttribute('data-av-edit');
      var barisEl = baris(id);
      if (!barisEl || !kataSandi.has(String(id))) {
        return;
      }
      var kotak = barisEl.querySelector('[data-reveal-box]');
      var form = barisEl.querySelector('[data-edit-form]');
      if (kotak && form) {
        kotak.hidden = true;
        form.hidden = false;
        mulaiHitung(id);
        var fokus = form.querySelector('input:not([type=hidden])');
        if (fokus) {
          fokus.focus();
        }
      }
      return;
    }

    el = event.target.closest('[data-edit-cancel]');
    if (el) {
      var idBatal = el.getAttribute('data-edit-cancel');
      var barisBatal = baris(idBatal);
      var formBatal = barisBatal ? barisBatal.querySelector('[data-edit-form]') : null;
      var kotakBatal = barisBatal ? barisBatal.querySelector('[data-reveal-box]') : null;
      if (formBatal) {
        formBatal.hidden = true;
      }
      if (kotakBatal && kataSandi.has(String(idBatal))) {
        kotakBatal.hidden = false;
        mulaiHitung(idBatal);
      }
      return;
    }

    el = event.target.closest('[data-av-salin]');
    if (el) {
      salinKataSandi(el.getAttribute('data-av-salin'));
      return;
    }

    el = event.target.closest('[data-copy-field]');
    if (el) {
      var barisSalin = el.closest('[data-entry]');
      if (barisSalin) {
        var idSalin = barisSalin.getAttribute('data-entry');
        var medan = el.getAttribute('data-copy-field');
        var sumber = '';
        if (medan === 'password') {
          sumber = kataSandi.get(String(idSalin)) || '';
        } else {
          var elMedan = barisSalin.querySelector('[data-field="' + medan + '"]');
          sumber = elMedan ? elMedan.textContent : '';
        }
        salinKeClipboard(sumber);
      }
      return;
    }

    el = event.target.closest('[data-av-hapus]');
    if (el) {
      var nama = el.getAttribute('data-av-nama') || '';
      var urlHapus = el.getAttribute('data-av-url') || '';
      var formHapus = document.getElementById('av-hapus-form');
      if (!window.KX || typeof KX.konfirmasiHapus !== 'function') {
        if (formHapus && urlHapus) {
          formHapus.action = urlHapus;
          formHapus.submit();
        }
        return;
      }
      KX.konfirmasiHapus({
        judul: pesan('delete-title'),
        nama: nama,
        pesan: pesan('delete-message'),
        onKonfirmasi: function () {
          if (formHapus && urlHapus) {
            formHapus.action = urlHapus;
            formHapus.submit();
          }
        }
      });
      return;
    }

    el = event.target.closest('[data-av-fokus]');
    if (el) {
      var tujuan = document.getElementById('av-add-site');
      if (tujuan) {
        tujuan.scrollIntoView({ behavior: 'smooth', block: 'center' });
        tujuan.focus();
      }
    }
  });

  // Enter di dalam formulir edit harus melewati tombol ber-data-reauth,
  // bukan mengirim POST langsung tanpa grant.
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

  // ── Grant reauth ────────────────────────────────────────────────────
  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detail = event.detail || {};
    if (detail.scope !== 'account.reveal' || !detail.resource) {
      return;
    }
    var gunakan = niat;
    niat = null;
    ambilData(String(detail.resource), detail.token, gunakan);
  });

  var modalReauth = document.getElementById('reauth-modal');
  if (modalReauth && 'MutationObserver' in window) {
    new MutationObserver(function () {
      if (modalReauth.style.display !== 'flex') {
        niat = null;
      }
    }).observe(modalReauth, { attributes: true, attributeFilter: ['style'] });
  }

  // ── Pembuat kata sandi acak ─────────────────────────────────────────
  var tombolAcak = document.getElementById('av-buat-otomatis');
  var inputSandi = document.getElementById('av-add-password');
  if (tombolAcak && inputSandi) {
    tombolAcak.addEventListener('click', function () {
      buatOtomatis(inputSandi);
    });
  }
})();
