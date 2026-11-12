/**
 * static/js/sampah.js
 * ────────────────────
 * Interaksi halaman Sampah (U2c):
 * - Filter jenis item sampah via chip.
 * - Pilihan checkbox tunggal & semua (select-all).
 * - Integrasi KX.aksiMengambang untuk bar aksi massal.
 * - Pemulihan cepat via fetch + KX.toast.
 * - Hapus permanen ber-grant trash.purge dengan dialog KX.konfirmasiHapus (bebas window.confirm).
 * - Pengosongan seluruh sampah ber-grant trash.purge.
 * - Mendukung alur fallback pengiriman form tradisional dan integrasi event cryptix:reauth-grant.
 */
(function () {
  'use strict';

  var halaman = document.getElementById('trash-page');
  if (!halaman) {
    return;
  }

  var csrfToken = halaman.getAttribute('data-csrf') || '';
  var formPulih = document.getElementById('trash-restore-form');
  var formHapus = document.getElementById('trash-purge-form');
  var formKosong = document.getElementById('trash-empty-form');
  var isiPulih = document.getElementById('trash-items-restore');
  var isiPurge = document.getElementById('trash-items-purge');
  var selectAll = document.getElementById('trash-select-all');

  function pesan(kunci, cadangan) {
    return halaman.getAttribute('data-msg-' + kunci) || cadangan || '';
  }

  function itemTerpilih() {
    var hasil = [];
    var daftar = document.querySelectorAll('[data-trash-select-item]:checked');
    Array.prototype.forEach.call(daftar, function (cek) {
      hasil.push({
        jenis: cek.getAttribute('data-jenis') || '',
        id: parseInt(cek.value, 10),
        nama: cek.getAttribute('data-nama') || ''
      });
    });
    return hasil;
  }

  function perbaruiPilihan() {
    var terpilih = itemTerpilih();
    var teks = JSON.stringify(terpilih.map(function (it) {
      return { jenis: it.jenis, id: it.id };
    }));

    if (isiPulih) {
      isiPulih.value = teks;
    }
    if (isiPurge) {
      isiPurge.value = teks;
    }

    var tombolTradisional = document.querySelectorAll('[data-trash-select]');
    Array.prototype.forEach.call(tombolTradisional, function (tombol) {
      tombol.disabled = terpilih.length === 0;
    });

    if (window.KX && window.KX.aksiMengambang) {
      window.KX.aksiMengambang.segarkan();
    }

    if (selectAll) {
      var semuaKotak = document.querySelectorAll('.kx-trash-row:not([hidden]) [data-trash-select-item]');
      var semuaCentang = document.querySelectorAll('.kx-trash-row:not([hidden]) [data-trash-select-item]:checked');
      if (semuaKotak.length === 0) {
        selectAll.checked = false;
        selectAll.indeterminate = false;
      } else if (semuaCentang.length === semuaKotak.length) {
        selectAll.checked = true;
        selectAll.indeterminate = false;
      } else if (semuaCentang.length > 0) {
        selectAll.checked = false;
        selectAll.indeterminate = true;
      } else {
        selectAll.checked = false;
        selectAll.indeterminate = false;
      }
    }
  }

  // ── 1. Filter Jenis Item ──
  var chips = document.querySelectorAll('[data-trash-filter]');
  Array.prototype.forEach.call(chips, function (chip) {
    chip.addEventListener('click', function () {
      var jenis = chip.getAttribute('data-trash-filter');
      Array.prototype.forEach.call(chips, function (c) {
        c.classList.remove('is-active');
        c.setAttribute('aria-pressed', 'false');
      });
      chip.classList.add('is-active');
      chip.setAttribute('aria-pressed', 'true');

      var baris = document.querySelectorAll('.kx-trash-row');
      Array.prototype.forEach.call(baris, function (tr) {
        var barisJenis = tr.getAttribute('data-jenis');
        if (jenis === 'all' || barisJenis === jenis) {
          tr.hidden = false;
        } else {
          tr.hidden = true;
          var kotak = tr.querySelector('[data-trash-select-item]');
          if (kotak) {
            kotak.checked = false;
          }
        }
      });
      perbaruiPilihan();
    });
  });

  // ── 2. Checkbox Pilihan ──
  if (selectAll) {
    selectAll.addEventListener('change', function () {
      var visibleCheckboxes = document.querySelectorAll('.kx-trash-row:not([hidden]) [data-trash-select-item]');
      Array.prototype.forEach.call(visibleCheckboxes, function (kotak) {
        kotak.checked = selectAll.checked;
      });
      perbaruiPilihan();
    });
  }

  document.addEventListener('change', function (event) {
    if (event.target.matches('[data-trash-select-item]')) {
      perbaruiPilihan();
    }
  });

  // ── 3. Aksi Pulihkan (Ajax / JSON dengan Toast) ──
  function eksekusiPulihkan(items) {
    if (!items || !items.length) {
      if (window.KX && window.KX.toast) {
        window.KX.toast(pesan('select-required', 'Pilih minimal satu item.'), 'error');
      }
      return;
    }

    var payload = {
      items: items.map(function (it) {
        return { jenis: it.jenis, id: it.id };
      })
    };

    fetch('/api/sampah/pulihkan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken,
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify(payload)
    })
      .then(function (res) {
        return res.json().then(function (data) {
          return { ok: res.ok, data: data };
        });
      })
      .then(function (res) {
        if (!res.ok) {
          var err = (res.data && res.data.error) || 'Gagal memulihkan item.';
          if (window.KX && window.KX.toast) {
            window.KX.toast(err, 'error');
          }
          return;
        }
        if (window.KX && window.KX.toast) {
          window.KX.toast(res.data.message || 'Item berhasil dipulihkan.', 'success');
        }
        setTimeout(function () {
          window.location.reload();
        }, 600);
      })
      .catch(function () {
        if (window.KX && window.KX.toast) {
          window.KX.toast('Terjadi kesalahan jaringan.', 'error');
        }
      });
  }

  // Baris tunggal Pulihkan
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.kx-trash-row-restore');
    if (btn) {
      var id = parseInt(btn.getAttribute('data-id'), 10);
      var jenis = btn.getAttribute('data-jenis');
      var nama = btn.getAttribute('data-nama') || '';
      eksekusiPulihkan([{ id: id, jenis: jenis, nama: nama }]);
    }
  });

  // Bulk Pulihkan
  var bulkRestoreBtn = document.getElementById('trash-bulk-restore');
  if (bulkRestoreBtn) {
    bulkRestoreBtn.addEventListener('click', function () {
      eksekusiPulihkan(itemTerpilih());
    });
  }

  // ── 4. Alur Grant Hapus Permanen & Kosongkan Sampah ──
  var aksiTertunda = null; // { tipe: 'purge'|'empty', items: [...] }

  function mintaGrant(aksi, items) {
    aksiTertunda = { tipe: aksi, items: items || [] };
    // Memicu modal reauth dengan scope trash.purge
    var dummyBtn = document.createElement('button');
    dummyBtn.type = 'button';
    dummyBtn.setAttribute('data-reauth', 'trash.purge');
    dummyBtn.hidden = true;
    document.body.appendChild(dummyBtn);
    dummyBtn.click();
    dummyBtn.remove();
  }

  function eksekusiPurge(items, grantToken) {
    var payload = {
      items: items.map(function (it) {
        return { jenis: it.jenis, id: it.id };
      })
    };

    fetch('/api/sampah/hapus-permanen', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken,
        'X-Reauth-Grant': grantToken,
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify(payload)
    })
      .then(function (res) {
        return res.json().then(function (data) {
          return { ok: res.ok, data: data };
        });
      })
      .then(function (res) {
        if (!res.ok) {
          var err = (res.data && res.data.error) || 'Gagal menghapus item.';
          if (window.KX && window.KX.toast) {
            window.KX.toast(err, 'error');
          }
          return;
        }
        if (window.KX && window.KX.toast) {
          window.KX.toast(res.data.message || 'Item dihapus permanen.', 'info');
        }
        setTimeout(function () {
          window.location.reload();
        }, 600);
      })
      .catch(function () {
        if (window.KX && window.KX.toast) {
          window.KX.toast('Terjadi kesalahan jaringan.', 'error');
        }
      });
  }

  function eksekusiEmpty(grantToken) {
    fetch('/api/sampah/kosongkan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken,
        'X-Reauth-Grant': grantToken,
        'X-Requested-With': 'XMLHttpRequest'
      }
    })
      .then(function (res) {
        return res.json().then(function (data) {
          return { ok: res.ok, data: data };
        });
      })
      .then(function (res) {
        if (!res.ok) {
          var err = (res.data && res.data.error) || 'Gagal mengosongkan sampah.';
          if (window.KX && window.KX.toast) {
            window.KX.toast(err, 'error');
          }
          return;
        }
        if (window.KX && window.KX.toast) {
          window.KX.toast(res.data.message || 'Sampah dikosongkan.', 'info');
        }
        setTimeout(function () {
          window.location.reload();
        }, 600);
      })
      .catch(function () {
        if (window.KX && window.KX.toast) {
          window.KX.toast('Terjadi kesalahan jaringan.', 'error');
        }
      });
  }

  // Baris tunggal Hapus Permanen
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.kx-trash-row-purge');
    if (btn) {
      var id = parseInt(btn.getAttribute('data-id'), 10);
      var jenis = btn.getAttribute('data-jenis');
      var nama = btn.getAttribute('data-nama') || 'ini';

      if (window.KX && window.KX.konfirmasiHapus) {
        window.KX.konfirmasiHapus({
          judul: pesan('purge-title', 'Hapus permanen item?'),
          nama: nama,
          pesan: pesan('purge-msg', 'Item {nama} akan dimusnahkan secara permanen. Tindakan ini tidak dapat dibatalkan.'),
          labelTombol: 'Hapus Permanen',
          onKonfirmasi: function () {
            mintaGrant('purge', [{ id: id, jenis: jenis, nama: nama }]);
          }
        });
      } else {
        mintaGrant('purge', [{ id: id, jenis: jenis, nama: nama }]);
      }
    }
  });

  // Bulk Hapus Permanen
  var bulkPurgeBtn = document.getElementById('trash-bulk-purge');
  if (bulkPurgeBtn) {
    bulkPurgeBtn.addEventListener('click', function () {
      var terpilih = itemTerpilih();
      if (!terpilih.length) {
        if (window.KX && window.KX.toast) {
          window.KX.toast(pesan('select-required', 'Pilih minimal satu item.'), 'error');
        }
        return;
      }
      if (window.KX && window.KX.konfirmasiHapus) {
        window.KX.konfirmasiHapus({
          judul: pesan('purge-title', 'Hapus permanen item?'),
          nama: terpilih.length + ' item terpilih',
          pesan: pesan('purge-msg', 'Item {nama} akan dimusnahkan secara permanen. Tindakan ini tidak dapat dibatalkan.'),
          labelTombol: 'Hapus Permanen',
          onKonfirmasi: function () {
            mintaGrant('purge', terpilih);
          }
        });
      } else {
        mintaGrant('purge', terpilih);
      }
    });
  }

  // Tombol Kosongkan Sampah
  var emptyBtn = document.getElementById('trash-empty-button');
  if (emptyBtn) {
    emptyBtn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      if (window.KX && window.KX.konfirmasiHapus) {
        window.KX.konfirmasiHapus({
          judul: pesan('empty-title', 'Kosongkan seluruh sampah?'),
          nama: 'seluruh sampah',
          pesan: pesan('empty-msg', 'Seluruh item di dalam Sampah akan dimusnahkan secara permanen. Tindakan ini tidak dapat dibatalkan.'),
          labelTombol: 'Kosongkan Sampah',
          onKonfirmasi: function () {
            mintaGrant('empty', []);
          }
        });
      } else {
        mintaGrant('empty', []);
      }
    });
  }

  // ── 5. Penerima Grant Token dari reauth.js ──
  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detail = event.detail || {};
    if (detail.scope !== 'trash.purge') {
      return;
    }

    if (!aksiTertunda) {
      // Jika dipicu secara tradisional lewat form button
      var terpilih = itemTerpilih();
      if (isiPurge) isiPurge.value = JSON.stringify(terpilih);
      if (formHapus) {
        var grantInput = formHapus.querySelector('input[name="reauth_grant"]');
        if (!grantInput) {
          grantInput = document.createElement('input');
          grantInput.type = 'hidden';
          grantInput.name = 'reauth_grant';
          formHapus.appendChild(grantInput);
        }
        grantInput.value = detail.token || '';
        formHapus.submit();
      }
      return;
    }

    var intent = aksiTertunda;
    aksiTertunda = null;

    if (intent.tipe === 'purge') {
      eksekusiPurge(intent.items, detail.token || '');
    } else if (intent.tipe === 'empty') {
      eksekusiEmpty(detail.token || '');
    }
  });

  perbaruiPilihan();
})();
