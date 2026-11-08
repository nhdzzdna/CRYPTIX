/**
 * static/js/secure_notes.js
 * ─────────────────────────
 * Membuka isi Secure Notes hanya setelah grant note.open. Isi catatan tidak
 * pernah ditulis ke HTML awal; diambil lewat POST dengan header X-Reauth-Grant.
 */
(function () {
  'use strict';

  function kartu(id) {
    return document.querySelector('[data-note="' + id + '"]');
  }

  function status(id, teks) {
    var el = document.querySelector('[data-note-status="' + id + '"]');
    if (el) {
      el.textContent = teks || '';
    }
  }

  function tutup(id) {
    var kartuEl = kartu(id);
    if (!kartuEl) {
      return;
    }
    var isi = kartuEl.querySelector('[data-note-content]');
    if (isi) {
      isi.textContent = '';
    }
    var kotak = kartuEl.querySelector('[data-note-box]');
    if (kotak) {
      kotak.hidden = true;
    }
    var form = kartuEl.querySelector('[data-note-edit]');
    if (form) {
      form.querySelectorAll('input, textarea').forEach(function (el) {
        if (el.type !== 'hidden') {
          el.value = '';
        }
      });
      form.hidden = true;
    }
    status(id, '');
  }

  function tampilkan(id, data) {
    var kartuEl = kartu(id);
    if (!kartuEl) {
      return;
    }
    var isi = kartuEl.querySelector('[data-note-content]');
    if (isi) {
      isi.textContent = data.content == null ? '' : String(data.content);
    }
    var kotak = kartuEl.querySelector('[data-note-box]');
    if (kotak) {
      kotak.hidden = false;
    }
    var form = kartuEl.querySelector('[data-note-edit]');
    if (form) {
      var judul = form.querySelector('[name="title"]');
      var isiForm = form.querySelector('[name="content"]');
      if (judul) {
        judul.value = data.title == null ? '' : String(data.title);
      }
      if (isiForm) {
        isiForm.value = data.content == null ? '' : String(data.content);
      }
      form.hidden = false;
    }
    status(id, '');
  }

  function buka(id, grant) {
    var tombol = document.querySelector('[data-note-open-id="' + id + '"]');
    if (!tombol) {
      return;
    }
    var url = tombol.getAttribute('data-note-open-url');
    status(id, 'Membuka…');
    apiFetch(url, {
      method: 'POST',
      headers: { 'X-Reauth-Grant': grant },
      credentials: 'same-origin'
    }).then(function (resp) {
      return resp.json().then(function (data) {
        if (!resp.ok || !data.success) {
          throw new Error(data.error || 'Gagal membuka catatan.');
        }
        return data;
      });
    }).then(function (data) {
      tampilkan(id, data);
    }).catch(function (err) {
      status(id, err.message);
    });
  }

  document.addEventListener('cryptix:reauth-grant', function (event) {
    var detail = event.detail || {};
    if (detail.scope !== 'note.open' || !detail.resource) {
      return;
    }
    buka(String(detail.resource), detail.token);
  });

  document.addEventListener('submit', function (event) {
    var form = event.target.closest('[data-note-edit]');
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
    var tutupBtn = event.target.closest('[data-note-close]');
    if (tutupBtn) {
      tutup(tutupBtn.getAttribute('data-note-close'));
      return;
    }
    var batal = event.target.closest('[data-note-cancel]');
    if (batal) {
      var id = batal.getAttribute('data-note-cancel');
      var kartuEl = kartu(id);
      var form = kartuEl ? kartuEl.querySelector('[data-note-edit]') : null;
      if (form) {
        form.hidden = true;
      }
    }
  });
})();
