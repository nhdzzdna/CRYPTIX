/**
 * static/js/webauthn.js — WebAuthn CRYPTIX (butir 2.5).
 *
 * Berisi tiga hal:
 *   1. konversi base64url dan penyusunan objek respons kredensial;
 *   2. pendaftaran kredensial platform (navigator.credentials.create)
 *      lewat POST /api/webauthn/register/options dan /complete;
 *   3. penangan tahap 2 login (navigator.credentials.get) yang
 *      didaftarkan ke window.CryptixBiometrik.penangan.webauthn.
 *
 * Pengenalan wajah disediakan pada sesi G sebagai metode terpisah sehingga
 * berkas ini tidak perlu diubah.
 */
"use strict";

window.CryptixBiometrik = window.CryptixBiometrik || { penangan: {} };

function _base64url(bytes) {
  let bin = "";
  const u8 = new Uint8Array(bytes);
  for (let i = 0; i < u8.length; i++) {
    bin += String.fromCharCode(u8[i]);
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function _objekRespons(kredensial) {
  if (typeof kredensial.toJSON === "function") {
    return kredensial.toJSON();
  }
  const dasar = {
    id: kredensial.id,
    rawId: _base64url(kredensial.rawId),
    type: kredensial.type,
    clientExtensionResults: kredensial.getClientExtensionResults
      ? kredensial.getClientExtensionResults()
      : {},
  };
  if (kredensial.response.attestationObject !== undefined) {
    // respons pendaftaran
    dasar.response = {
      clientDataJSON: _base64url(kredensial.response.clientDataJSON),
      attestationObject: _base64url(kredensial.response.attestationObject),
      transports: kredensial.response.getTransports
        ? kredensial.response.getTransports()
        : undefined,
    };
  } else {
    // respons masuk
    dasar.response = {
      clientDataJSON: _base64url(kredensial.response.clientDataJSON),
      authenticatorData: _base64url(kredensial.response.authenticatorData),
      signature: _base64url(kredensial.response.signature),
      userHandle: kredensial.response.userHandle
        ? _base64url(kredensial.response.userHandle)
        : null,
    };
  }
  return dasar;
}

const CryptixWebAuthn = {
  /** Minta opsi pendaftaran ke server. */
  async _opsiDaftar() {
    const resp = await apiFetch("/api/webauthn/register/options", {
      method: "POST",
      body: "{}",
    });
    const data = await resp.json();
    if (!data.success) {
      throw new Error(data.error || "Pendaftaran WebAuthn gagal.");
    }
    return data.options;
  },

  /**
   * Daftarkan autentikator platform untuk pengguna sesi ini.
   * @param {string} idStatus id elemen paragraf status (boleh kosong)
   */
  async daftar(idStatus) {
    const st = idStatus ? document.getElementById(idStatus) : null;
    const set = function (pesan, warna) {
      if (st) {
        st.textContent = pesan;
        st.style.color = warna || "";
      }
    };
    set("Menyiapkan pendaftaran WebAuthn…");
    try {
      if (!window.PublicKeyCredential) {
        throw new Error("Perangkat ini tidak mendukung WebAuthn.");
      }
      const opsi = await this._opsiDaftar();
      const kredensial = await navigator.credentials.create({ publicKey: opsi });
      set("Memverifikasi kredensial…");
      const resp = await apiFetch("/api/webauthn/register/complete", {
        method: "POST",
        body: JSON.stringify({ response: _objekRespons(kredensial) }),
      });
      const data = await resp.json();
      if (!data.success) {
        throw new Error(data.error || "Pendaftaran WebAuthn gagal.");
      }
      set("Kredensial WebAuthn tersimpan.", "#22c55e");
      if (data.setup_done) {
        setTimeout(function () {
          window.location.href = "/login";
        }, 800);
      }
      return data;
    } catch (err) {
      const pesan = err && err.message ? err.message : "Pendaftaran WebAuthn gagal.";
      set(pesan, "#ef4444");
      throw err;
    }
  },
};

window.CryptixWebAuthn = CryptixWebAuthn;

/** Dipanggil tombol pada halaman penyiapan dan Settings. */
function daftarWebAuthn(idStatus) {
  return window.CryptixWebAuthn.daftar(idStatus);
}

// ── Penangan tahap 2 login ───────────────────────────────────────────────────
// Tantangan diisi login.js pada respons tahap 1 (data.webauthn_options).
window.CryptixBiometrik.penangan.webauthn = async function () {
  const opsi = window.CryptixBiometrik.opsiMasuk;
  if (!opsi) {
    throw new Error("Tantangan WebAuthn tidak tersedia. Muat ulang halaman lalu coba lagi.");
  }
  if (!window.PublicKeyCredential) {
    throw new Error("Perangkat ini tidak mendukung WebAuthn.");
  }
  const kredensial = await navigator.credentials.get({ publicKey: opsi });
  return _objekRespons(kredensial);
};
