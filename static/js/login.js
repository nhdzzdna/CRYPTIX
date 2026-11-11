/**
 * static/js/login.js — alur login dua tahap (butir 2.4).
 *
 * Tahap 1: username dan password dikirim ke POST /login; server menahan
 *   DEK di sisi server dan membalas daftar metode biometrik.
 * Tahap 2: pengguna memilih satu metode (otomatis bila hanya satu), bukti
 *   metode itu dikirim ke POST /login/biometric, lalu halaman diarahkan
 *   ke dasbor.
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
  const hint2 = document.getElementById("stage2-hint");
  const status2 = document.getElementById("stage2-status");
  const galat1 = document.getElementById("login-error");
  const galat2 = document.getElementById("stage2-error");
  let tahap = null;   // hasil tahap 1: {pending, metode}
  let sedangVerifikasi = false;

  function teksPanel(nama, cadangan) {
    if (stage2 && stage2.dataset && stage2.dataset[nama]) {
      return stage2.dataset[nama];
    }
    return cadangan;
  }

  function tampilkanGalat(el, pesan) {
    el.textContent = pesan || "";
    el.classList.toggle("visible", Boolean(pesan));
  }

  function aturStatus(pesan) {
    if (status2) {
      status2.textContent = pesan || "";
    }
  }

  function nonaktifkanTombol(aktif) {
    daftarMetode.querySelectorAll("button").forEach(function (tombol) {
      tombol.disabled = aktif;
    });
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
        aturStatus("");
        const metode = data.metode || [];
        if (!metode.length) {
          if (hint2) {
            hint2.textContent = "";
          }
          tampilkanGalat(
            galat2,
            teksPanel(
              "msgNone",
              "Belum ada metode biometrik terdaftar untuk akun ini."
            )
          );
          return;
        }
        metode.forEach(function (m) {
          const tombol = document.createElement("button");
          tombol.type = "button";
          tombol.className = "btn btn-primary btn-full";
          tombol.textContent = m.label;
          tombol.dataset.metode = m.nama;
          tombol.addEventListener("click", function () {
            jalankanMetode(m);
          });
          daftarMetode.appendChild(tombol);
        });
        if (hint2) {
          hint2.textContent = teksPanel(
            "msgChoose",
            "Pilih satu metode biometrik untuk melanjutkan."
          );
        }
        // Satu metode langsung dijalankan; dua metode atau lebih menunggu
        // pilihan pengguna lewat tombol.
        if (metode.length === 1) {
          jalankanMetode(metode[0]);
        }
      })
      .catch(function () {
        tampilkanGalat(galat1, "Permintaan gagal dikirim. Coba lagi.");
      });
  });

  // ── Tahap 2: satu metode pilihan ──────────────────────────────────────────
  function jalankanMetode(metode) {
    if (!tahap || sedangVerifikasi) {
      return;
    }
    const penangan = window.CryptixBiometrik.penangan[metode.nama];
    if (!penangan) {
      tampilkanGalat(
        galat2,
        teksPanel(
          "msgUnsupported",
          "Metode biometrik ini belum didukung peramban. Pilih metode lain."
        )
      );
      return;
    }

    tampilkanGalat(galat2, "");
    aturStatus(
      teksPanel("msgVerifying", "Memverifikasi {metode}...")
        .replace("{metode}", metode.label)
    );
    sedangVerifikasi = true;
    nonaktifkanTombol(true);

    Promise.resolve()
      .then(function () {
        return penangan();
      })
      .then(function (bukti) {
        const isiBukti = {};
        isiBukti[metode.nama] = bukti;
        return apiFetch("/login/biometric", {
          method: "POST",
          body: JSON.stringify({
            pending: tahap.pending,
            metode: metode.nama,
            bukti: isiBukti,
          }),
        }).then(function (r) { return r.json(); });
      })
      .then(function (data) {
        if (!data.success) {
          tampilkanGalat(galat2, data.error || "Verifikasi biometrik gagal.");
          aturStatus("");
          sedangVerifikasi = false;
          nonaktifkanTombol(false);
          return;
        }
        window.location.href = data.redirect || "/dashboard";
      })
      .catch(function (err) {
        tampilkanGalat(galat2, err.message || "Verifikasi biometrik gagal.");
        aturStatus("");
        sedangVerifikasi = false;
        nonaktifkanTombol(false);
      });
  }
});
