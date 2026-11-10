/**
 * static/js/login.js — alur login dua tahap (butir 2.4).
 *
 * Tahap 1: username dan password dikirim ke POST /login; server menahan
 *   DEK di sisi server dan membalas daftar metode biometrik.
 * Tahap 2: bukti tiap metode dikirim ke POST /login/biometric, lalu
 *   halaman diarahkan ke dasbor.
 *
 * Penangan metode biometrik didaftarkan lewat window.CryptixBiometrik
 * (lihat webauthn.js atau modul metode lain) sehingga metode baru cukup
 * menambahkan penangan tanpa mengubah berkas ini.
 */
"use strict";

window.CryptixBiometrik = window.CryptixBiometrik || { penangan: {} };

document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("login-form");
  const stage2 = document.getElementById("stage2");
  const daftarMetode = document.getElementById("metode-list");
  const galat1 = document.getElementById("login-error");
  const galat2 = document.getElementById("stage2-error");
  const btnVerifikasi = document.getElementById("btn-verifikasi");
  let tahap = null;   // hasil tahap 1: {pending, metode}

  function tampilkanGalat(el, pesan) {
    el.textContent = pesan || "";
    el.classList.toggle("visible", Boolean(pesan));
  }

  // ── Status dongle pada mesin ini (tanpa username) ─────────────────────────
  // Badge hijau bila terdeteksi, kuning bila tidak (warna via class CSS).
  const statusDongle = document.getElementById("dongle-status");
  const statusDongleTeks = document.getElementById("dongle-status-text");
  function aturStatusDongle(pesan, kelas) {
    if (statusDongleTeks) {
      statusDongleTeks.textContent = pesan;
    } else if (statusDongle) {
      statusDongle.textContent = pesan;
    }
    if (statusDongle) {
      statusDongle.classList.remove("is-ok", "is-off");
      if (kelas) {
        statusDongle.classList.add(kelas);
      }
    }
  }
  apiFetch("/api/dongle/status")
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.detected) {
        aturStatusDongle("Dongle terdeteksi.", "is-ok");
      } else {
        aturStatusDongle(
          "Dongle tidak terdeteksi — colokkan dongle lalu muat ulang halaman.",
          "is-off"
        );
      }
    })
    .catch(function () {
      aturStatusDongle("Status dongle tidak dapat diperiksa.", null);
    });

  // ── Tahap 1 ───────────────────────────────────────────────────────────────
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    tampilkanGalat(galat1, "");
    const isi = {
      username: document.getElementById("username").value,
      password: document.getElementById("password").value,
    };
    apiFetch("/login", {
      method: "POST",
      body: JSON.stringify(isi),
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        document.getElementById("password").value = "";
        if (!data.success) {
          tampilkanGalat(galat1, data.error || "Login gagal.");
          return;
        }
        tahap = data;
        // Tantangan WebAuthn tahap 2 (ada bila metode ini terdaftar).
        window.CryptixBiometrik.opsiMasuk = data.webauthn_options || null;
        form.hidden = true;
        stage2.hidden = false;
        daftarMetode.innerHTML = "";
        (data.metode || []).forEach(function (m) {
          const item = document.createElement("li");
          item.textContent = m.label;
          item.dataset.metode = m.nama;
          daftarMetode.appendChild(item);
        });
        if (!(data.metode || []).length) {
          tampilkanGalat(
            galat2,
            "Belum ada metode biometrik terdaftar untuk akun ini."
          );
          btnVerifikasi.disabled = true;
        }
      })
      .catch(function () {
        tampilkanGalat(galat1, "Permintaan gagal dikirim. Coba lagi.");
      });
  });

  // ── Tahap 2 ───────────────────────────────────────────────────────────────
  btnVerifikasi.addEventListener("click", function () {
    if (!tahap) return;
    tampilkanGalat(galat2, "");
    btnVerifikasi.disabled = true;

    Promise.all(
      (tahap.metode || []).map(function (m) {
        const penangan = window.CryptixBiometrik.penangan[m.nama];
        if (!penangan) {
          return Promise.reject(new Error("Metode belum didukung."));
        }
        return Promise.resolve(penangan()).then(function (bukti) {
          return [m.nama, bukti];
        });
      })
    )
      .then(function (pasangan) {
        const bukti = {};
        pasangan.forEach(function (p) { bukti[p[0]] = p[1]; });
        return apiFetch("/login/biometric", {
          method: "POST",
          body: JSON.stringify({ pending: tahap.pending, bukti: bukti }),
        }).then(function (r) { return r.json(); });
      })
      .then(function (data) {
        if (!data.success) {
          tampilkanGalat(galat2, data.error || "Verifikasi biometrik gagal.");
          btnVerifikasi.disabled = false;
          return;
        }
        window.location.href = data.redirect || "/dashboard";
      })
      .catch(function (err) {
        tampilkanGalat(galat2, err.message || "Verifikasi biometrik gagal.");
        btnVerifikasi.disabled = false;
      });
  });
});
