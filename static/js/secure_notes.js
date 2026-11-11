/**
 * static/js/secure_notes.js
 * ───────────────────────────
 * Membuka isi Secure Notes hanya setelah grant note.open. Isi catatan tidak
 * pernah ditulis ke HTML awal; diambil lewat POST dengan header X-Reauth-Grant.
 *
 * Panel kanan berbagi satu formulir untuk mode "Catatan baru" (POST add, tanpa
 * verifikasi ulang) dan mode edit (POST edit, tombol simpan diberi
 * data-reauth note.edit). Semua teks antarmuka dibaca dari atribut data-msg-*
 * pada akar halaman (modules/strings.py), bukan teks JS.
 */
(function () {
  'use strict';

  var akar = document.querySelector('.kx-sn-page');
  if (!akar) {
    return;
  }

  var kotakKosong = document.getElementById('sn-kosong');
  var editorIsi = document.getElementById('sn-editor-isi');
  var editorJudul = document.getElementById('sn-editor-judul');
  var editorMeta = document.getElementById('sn-editor-meta');
  var editorTanggal = document.getElementById('sn-editor-tanggal');
  var tombolHapus = document.getElementById('sn-hapus');
  var kotakBuka = document.getElementById('sn-buka-kotak');
  var tombolBuka = document.getElementById('sn-buka');
  var form = document.getElementById('sn-form');
  var inputJudul = document.getElementById('sn-judul');
  var inputIsi = document.getElementById('sn-isi');
  var tombolSimpan = document.getElementById('sn-simpan');
  var tombolTutup = document.getElementById('sn-tutup');
  var tombolBatal = document.getElementById('sn-batal');
  var formHapus = document.getElementById('sn-hapus-form');
  var cari = document.getElementById('sn-cari');
  var takCocok = document.getElementById('sn-tak-cocok');
  var daftar = document.getElementById('sn-daftar');

  var tambahUrl = form ? form.getAttribute('action') : '';
  var elemenAktif = null;

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

  function barisById(id) {
    return daftar
      ? daftar.querySelector('[data-sn-id="' + String(id) + '"]')
      : null;
  }

  function setLabelBuka(memuat) {
    if (!tombolBuka) {
      return;
    }
    var span = tombolBuka.querySelector('span');
    if (!span) {
      return;
    }
    if (memuat) {
      if (!tombolBuka.getAttribute('data-label-asli')) {
        tombolBuka.setAttribute('data-label-asli', span.textContent);
      }
      tombolBuka.disabled = true;
      span.textContent = pesan('open-loading');
    } else {
      tombolBuka.disabled = false;
      span.textContent = tombolBuka.getAttribute('data-label-asli') || span.textContent;
    }
  }

  function bersihkanForm() {
    if (inputJudul) {
      inputJudul.value = '';
    }
    if (inputIsi) {
      inputIsi.value = '';
    }
  }

  function lepasReauthSimpan() {
    if (!tombolSimpan) {
      return;
    }
    tombolSimpan.removeAttribute('data-reauth');
    tombolSimpan.removeAttribute('data-reauth-resource');
  }

  function lepasPilihan() {
    if (elemenAktif) {
      elemenAktif.classList.remove('is-aktif');
      elemenAktif = null;
    }
  }

  // Empty state: belum ada catatan dipilih.
  function tampilkanKosong() {
    lepasPilihan();
    if (kotakKosong) {
      kotakKosong.hidden = false;
    }
    if (editorIsi) {
      editorIsi.hidden = true;
    }
    if (form) {
      form.action = tambahUrl;
      form.hidden = true;
    }
    if (kotakBuka) {
      kotakBuka.hidden = true;
    }
    if (tombolHapus) {
      tombolHapus.hidden = true;
    }
    if (tombolTutup) {
      tombolTutup.hidden = true;
    }
    if (tombolBatal) {
      tombolBatal.hidden = true;
    }
    lepasReauthSimpan();
    bersihkanForm();
  }

  // Mode catatan baru: formulir langsung aktif tanpa verifikasi ulang.
  function tampilkanBaru() {
    lepasPilihan();
    if (kotakKosong) {
      kotakKosong.hidden = true;
    }
    if (editorIsi) {
      editorIsi.hidden = false;
    }
    if (editorJudul) {
      editorJudul.textContent = pesan('new-title');
    }
    if (editorMeta) {
      editorMeta.hidden = true;
    }
    if (tombolHapus) {
      tombolHapus.hidden = true;
    }
    if (kotakBuka) {
      kotakBuka.hidden = true;
    }
    if (form) {
      form.action = tambahUrl;
      form.hidden = false;
    }
    lepasReauthSimpan();
    bersihkanForm();
    if (tombolTutup) {
      tombolTutup.hidden = true;
    }
    if (tombolBatal) {
      tombolBatal.hidden = false;
    }
    if (inputJudul) {
      inputJudul.focus();
    }
  }

  // Mode catatan terpilih: editor menunggu "Buka" sebelum isi ditampilkan.
  function pilihCatatan(el) {
    lepasPilihan();
    elemenAktif = el;
    el.classList.add('is-aktif');

    if (kotakKosong) {
      kotakKosong.hidden = true;
    }
    if (editorIsi) {
      editorIsi.hidden = false;
    }
    if (editorJudul) {
      editorJudul.textContent = el.getAttribute('data-sn-judul') || '';
    }
    if (editorTanggal) {
      editorTanggal.textContent = el.getAttribute('data-sn-tanggal') || '';
    }
    if (editorMeta) {
      editorMeta.hidden = false;
    }
    if (tombolHapus) {
      tombolHapus.setAttribute('data-sn-nama', el.getAttribute('data-sn-judul') || '');
      tombolHapus.setAttribute('data-sn-hapus-url', el.getAttribute('data-sn-hapus-url') || '');
      tombolHapus.hidden = false;
    }
    if (tombolBuka) {
      tombolBuka.setAttribute('data-reauth-resource', el.getAttribute('data-sn-id') || '');
    }
    if (kotakBuka) {
      kotakBuka.hidden = false;
    }
    if (form) {
      form.hidden = true;
    }
    lepasReauthSimpan();
    bersihkanForm();
    if (tombolTutup) {
      tombolTutup.hidden = true;
    }
    if (tombolBatal) {
      tombolBatal.hidden = true;
    }
  }

  // Setelah "Tutup": isi dikeluarkan dari DOM, editor kembali menunggu Buka.
  function tutupKonten() {
    bersihkanForm();
    lepasReauthSimpan();
    if (form) {
      form.hidden = true;
    }
    if (kotakBuka) {
      kotakBuka.hidden = false;
    }
    if (tombolTutup) {
      tombolTutup.hidden = true;
    }
  }

  function buka(id, grant) {
    var el = barisById(id);
    if (!el) {
      return;
    }
    var url = el.getAttribute('data-sn-open-url');
    var urlEdit = el.getAttribute('data-sn-edit-url');
    if (!url || !urlEdit) {
      return;
    }
    setLabelBuka(true);

    apiFetch(url, {
      method: 'POST',
      headers: { 'X-Reauth-Grant': grant },
      credentials: 'same-origin'
    }).then(function (resp) {
      return resp.json().then(function (data) {
        if (!resp.ok || !data.success) {
          throw new Error(data.error || pesan('open-failed'));
        }
        return data;
      });
    }).then(function (data) {
      setLabelBuka(false);
      if (inputJudul) {
        inputJudul.value = data.title == null ? '' : String(data.title);
      }
      if (inputIsi) {
        inputIsi.value = data.content == null ? '' : String(data.content);
      }
      if (kotakBuka) {
        kotakBuka.hidden = true;
      }
      if (form) {
        form.action = urlEdit;
        form.hidden = false;
      }
      if (tombolSimpan) {
        tombolSimpan.setAttribute('data-reauth', 'note.edit');
        tombolSimpan.setAttribute('data-reauth-resource', String(id));
      }
      if (tombolTutup) {
        tombolTutup.hidden = false;
      }
      if (inputIsi) {
        inputIsi.focus();
      }
    }).catch(function (err) {
      setLabelBuka(false);
      toast(err && err.message ? err.message : pesan('open-failed'), 'danger');
    });
  }

  // ── Aksi klik ────────────────────────────────────────────────────────
  document.addEventListener('click', function (event) {
    var el = event.target.closest('[data-sn-baru]');
    if (el) {
      tampilkanBaru();
      return;
    }

    if (daftar) {
      el = event.target.closest('[data-sn-id]');
      if (el && daftar.contains(el)) {
        pilihCatatan(el);
        return;
      }
    }

    if (event.target.closest('#sn-batal')) {
      tampilkanKosong();
      return;
    }

    if (event.target.closest('#sn-tutup')) {
      tutupKonten();
      return;
    }

    el = event.target.closest('#sn-hapus');
    if (el) {
      var nama = el.getAttribute('data-sn-nama') || '';
      var urlHapus = el.getAttribute('data-sn-hapus-url') || '';
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
          pesan: pesan('delete-message'),
          onKonfirmasi: kirim
        });
      } else {
        kirim();
      }
    }
  });

  // Enter di dalam formulir edit harus melewati tombol ber-data-reauth,
  // bukan mengirim POST langsung tanpa grant.
  document.addEventListener('submit', function (event) {
    if (!form || event.target !== form) {
      return;
    }
    if (!tombolSimpan || !tombolSimpan.hasAttribute('data-reauth')) {
      return;
    }
    event.preventDefault();
    tombolSimpan.click();
  }, true);

  // ── Grant reauth ─────────────────────────────────────────────────────
  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detail = event.detail || {};
    if (detail.scope !== 'note.open' || !detail.resource) {
      return;
    }
    buka(String(detail.resource), detail.token);
  });

  // ── Pencarian daftar ─────────────────────────────────────────────────
  function saring() {
    if (!daftar) {
      return;
    }
    var kata = (cari && cari.value ? cari.value : '').trim().toLowerCase();
    var cocok = 0;
    daftar.querySelectorAll('[data-sn-id]').forEach(function (el) {
      var judul = (el.getAttribute('data-sn-judul') || '').toLowerCase();
      var kena = !kata || judul.indexOf(kata) !== -1;
      el.hidden = !kena;
      if (kena) {
        cocok += 1;
      }
    });
    if (takCocok) {
      takCocok.hidden = cocok > 0;
    }
  }

  if (cari) {
    cari.addEventListener('input', saring);
  }
})();
