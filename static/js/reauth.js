/**
 * static/js/reauth.js
 * ───────────────────
 * Alur autentikasi ulang (step-up) di sisi klien.
 *
 * Elemen dengan atribut berikut membuka modal dan melanjutkan aksi setelah
 * grant diterbitkan:
 *   data-reauth="file.download"      → scope yang diminta
 *   data-reauth-resource="12"        → resource id (opsional)
 *
 * Grant hanya disimpan di memori (Map) dan dikirim lewat header
 * X-Reauth-Grant atau field form reauth_grant. Kata sandi hanya berada di
 * input selama permintaan dan tidak pernah masuk URL, cookie, atau storage.
 */
(function () {
  'use strict';

  var modal = document.getElementById('reauth-modal');
  if (!modal) {
    return;
  }

  var form = document.getElementById('reauth-form');
  var konteks = document.getElementById('reauth-context');
  var inputPassword = document.getElementById('reauth-password');
  var kotakGalat = document.getElementById('reauth-error');
  var tombolSubmit = document.getElementById('reauth-submit');
  var tombolWebauthn = document.getElementById('reauth-webauthn');
  var tombolBatal = document.getElementById('reauth-cancel');

  var grants = new Map();
  var tertunda = null;
  var sedangProses = false;

  function kunciGrant(scope, resource) {
    return scope + '\u0000' + (resource || '');
  }

  function simpanGrant(scope, resource, payload) {
    grants.set(kunciGrant(scope, resource), {
      token: payload.grant,
      reusable: Boolean(payload.reusable),
      expiresAt: Date.now() + (Number(payload.expires_in) || 0) * 1000
    });
  }

  function ambilGrant(scope, resource) {
    var kunci = kunciGrant(scope, resource);
    var entri = grants.get(kunci);
    if (!entri) {
      return null;
    }
    if (Date.now() >= entri.expiresAt) {
      grants.delete(kunci);
      return null;
    }
    return entri;
  }

  function buangGrant(scope, resource) {
    grants.delete(kunciGrant(scope, resource));
  }

  function tampilkanGalat(pesan) {
    if (!kotakGalat) {
      return;
    }
    kotakGalat.className = 'alert alert-danger mt-3';
    kotakGalat.textContent = pesan || 'Autentikasi ulang gagal.';
    kotakGalat.style.display = '';
  }

  function sembunyikanGalat() {
    if (!kotakGalat) {
      return;
    }
    kotakGalat.className = 'mt-3';
    kotakGalat.textContent = '';
    kotakGalat.style.display = 'none';
  }

  function setProses(aktif) {
    sedangProses = aktif;
    if (tombolSubmit) {
      tombolSubmit.disabled = aktif;
    }
    if (tombolWebauthn) {
      tombolWebauthn.disabled = aktif;
    }
  }

  function tutupModal() {
    modal.style.display = 'none';
    tertunda = null;
    if (inputPassword) {
      inputPassword.value = '';
    }
    sembunyikanGalat();
  }

  function bukaModal(scope, resource) {
    sembunyikanGalat();
    if (konteks) {
      konteks.textContent = 'Tindakan "' + scope + '"' +
        (resource ? ' pada sumber daya ' + resource : '') +
        ' memerlukan konfirmasi kata sandi atau biometrik.';
    }
    modal.style.display = 'flex';
    if (inputPassword) {
      inputPassword.value = '';
      inputPassword.focus();
    }
  }

  function atribut(pemicu) {
    var scope = pemicu.getAttribute('data-reauth') || '';
    var resource = pemicu.getAttribute('data-reauth-resource');
    return { scope: scope.trim(), resource: resource };
  }

  function namaBerkas(header) {
    if (!header) {
      return null;
    }
    var cocok = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(header);
    if (!cocok) {
      return null;
    }
    var nama = cocok[1].replace(/^"|"$/g, '');
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
    tautan.download = nama || 'berkas';
    document.body.appendChild(tautan);
    tautan.click();
    document.body.removeChild(tautan);
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function gantiHalamanDariTeks(html) {
    document.open();
    document.write(html);
    document.close();
  }

  function lanjutkanForm(pemicu, entri) {
    var formulir = pemicu.tagName === 'FORM' ? pemicu : pemicu.form;
    if (!formulir) {
      return false;
    }
    var tersembunyi = formulir.querySelector('input[name="reauth_grant"]');
    if (!tersembunyi) {
      tersembunyi = document.createElement('input');
      tersembunyi.type = 'hidden';
      tersembunyi.name = 'reauth_grant';
      formulir.appendChild(tersembunyi);
    }
    tersembunyi.value = entri.token;
    formulir.submit();
    return true;
  }

  function lanjutkanTautan(pemicu, entri) {
    var url = pemicu.getAttribute('href');
    if (!url) {
      return false;
    }
    var metode = (pemicu.getAttribute('data-reauth-method') || 'GET').toUpperCase();

    apiFetch(url, {
      method: metode,
      headers: { 'X-Reauth-Grant': entri.token },
      credentials: 'same-origin'
    }).then(function (resp) {
      if (!resp.ok) {
        throw new Error('Tindakan ditolak oleh server.');
      }
      var disposisi = resp.headers.get('Content-Disposition') || '';
      if (disposisi.toLowerCase().indexOf('attachment') !== -1) {
        return resp.blob().then(function (blob) {
          unduhBlob(blob, namaBerkas(disposisi));
        });
      }
      if (resp.redirected) {
        window.location.assign(resp.url);
        return null;
      }
      return resp.text().then(gantiHalamanDariTeks);
    }).catch(function (err) {
      tampilkanGalat(err.message);
      modal.style.display = 'flex';
    });
    return true;
  }

  function kirimAksiKhusus(pemicu, entri) {
    var url = pemicu.getAttribute('data-reauth-url');
    var detail = {
      scope: atribut(pemicu).scope,
      resource: atribut(pemicu).resource,
      token: entri.token
    };

    document.dispatchEvent(new CustomEvent('cryptix:reauth-grant', { detail: detail }));

    if (!url) {
      return true;
    }

    var metode = (pemicu.getAttribute('data-reauth-method') || 'POST').toUpperCase();
    apiFetch(url, {
      method: metode,
      headers: { 'X-Reauth-Grant': entri.token },
      credentials: 'same-origin'
    }).then(function (resp) {
      if (resp.redirected) {
        window.location.assign(resp.url);
      } else if (!resp.ok) {
        throw new Error('Tindakan ditolak oleh server.');
      }
    }).catch(function (err) {
      tampilkanGalat(err.message);
      modal.style.display = 'flex';
    });
    return true;
  }

  function lanjutkan(pemicu, entri) {
    var berhasil = false;

    if (pemicu.tagName === 'FORM' ||
        (pemicu.tagName === 'BUTTON' && pemicu.type === 'submit' && pemicu.form)) {
      berhasil = lanjutkanForm(pemicu, entri);
    } else if (pemicu.tagName === 'A') {
      berhasil = lanjutkanTautan(pemicu, entri);
    } else {
      berhasil = kirimAksiKhusus(pemicu, entri);
    }

    if (berhasil && !entri.reusable) {
      buangGrant(atribut(pemicu).scope, atribut(pemicu).resource);
    }
  }

  function mintaGrant(scope, resource, metode, payload) {
    setProses(true);
    sembunyikanGalat();

    var badan = {
      method: metode,
      scope: scope,
      resource_id: resource || null
    };
    if (payload) {
      Object.keys(payload).forEach(function (kunci) {
        badan[kunci] = payload[kunci];
      });
    }

    return apiFetch('/api/reauth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(badan),
      credentials: 'same-origin'
    }).then(function (resp) {
      return resp.json().then(function (data) {
        if (!resp.ok || !data.success) {
          throw new Error(data.error || 'Autentikasi ulang gagal.');
        }
        simpanGrant(scope, resource, data);
        return ambilGrant(scope, resource);
      });
    }).finally(function () {
      setProses(false);
    });
  }

  function mulaiDariPemicu(pemicu, metode, payload) {
    var info = atribut(pemicu);
    if (!info.scope) {
      return;
    }
    tertunda = { pemicu: pemicu, scope: info.scope, resource: info.resource };

    mintaGrant(info.scope, info.resource, metode, payload).then(function (entri) {
      var target = tertunda;
      tutupModal();
      if (target) {
        lanjutkan(target.pemicu, entri);
      }
    }).catch(function (err) {
      tampilkanGalat(err.message);
    });
  }

  document.addEventListener('click', function (event) {
    var pemicu = event.target.closest('[data-reauth]');
    if (!pemicu || modal.style.display === 'flex') {
      return;
    }

    var info = atribut(pemicu);
    if (!info.scope) {
      return;
    }

    var entri = ambilGrant(info.scope, info.resource);
    if (entri) {
      event.preventDefault();
      event.stopImmediatePropagation();
      lanjutkan(pemicu, entri);
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();
    tertunda = { pemicu: pemicu, scope: info.scope, resource: info.resource };
    bukaModal(info.scope, info.resource);
  }, true);

  function mulaiBiometrik(target) {
    if (!target) {
      return;
    }
    if (!window.CryptixWebAuthn ||
        typeof window.CryptixWebAuthn.masukDenganOpsi !== 'function') {
      tampilkanGalat('Perangkat ini tidak mendukung WebAuthn.');
      return;
    }
    setProses(true);
    sembunyikanGalat();

    apiFetch('/api/reauth/webauthn/options', {
      method: 'POST',
      body: '{}',
      credentials: 'same-origin'
    }).then(function (resp) {
      return resp.json().then(function (data) {
        if (!resp.ok || !data.success) {
          throw new Error(data.error || 'Autentikasi ulang gagal.');
        }
        return data.options;
      });
    }).then(function (opsi) {
      return window.CryptixWebAuthn.masukDenganOpsi(opsi);
    }).then(function (respons) {
      setProses(false);
      mulaiDariPemicu(target.pemicu, 'webauthn', { response: respons });
    }).catch(function (err) {
      setProses(false);
      tampilkanGalat(err && err.message ? err.message
        : 'Autentikasi ulang gagal.');
    });
  }

  if (form) {
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      if (sedangProses || !tertunda) {
        return;
      }
      var password = inputPassword ? inputPassword.value : '';
      if (!password) {
        tampilkanGalat('Kata sandi wajib diisi.');
        return;
      }
      mulaiDariPemicu(tertunda.pemicu, 'password', { password: password });
      if (inputPassword) {
        inputPassword.value = '';
      }
    });
  }

  if (tombolWebauthn) {
    tombolWebauthn.addEventListener('click', function () {
      if (sedangProses || !tertunda) {
        return;
      }
      mulaiBiometrik(tertunda);
    });
  }

  if (tombolBatal) {
    tombolBatal.addEventListener('click', tutupModal);
  }

  modal.addEventListener('click', function (event) {
    if (event.target === modal) {
      tutupModal();
    }
  });

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && modal.style.display === 'flex') {
      tutupModal();
    }
  });

  window.CryptixReauth = {
    /** Ambil token grant yang masih berlaku, atau null. */
    grantFor: function (scope, resource) {
      var entri = ambilGrant(scope, resource);
      return entri ? entri.token : null;
    },
    /** Hapus grant lokal setelah dipakai sendiri. */
    forget: function (scope, resource) {
      buangGrant(scope, resource);
    }
  };
})();
