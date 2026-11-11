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

  function teksDongle(nama) {
    return statusDongle && statusDongle.dataset ? statusDongle.dataset[nama] : "";
  }

  function alamatSprite() {
    var contoh = document.querySelector("use[href*='sprite.svg']");
    if (contoh) {
      return (contoh.getAttribute("href") || "").split("#")[0];
    }
    return "/static/icons/sprite.svg";
  }

  function labelMetode(metode) {
    if (metode.nama === "wajah") {
      return teksPanel("labelFace", metode.label);
    }
    if (metode.nama === "webauthn") {
      return teksPanel("labelWebauthn", metode.label);
    }
    return metode.label;
  }

  function ikonMetode(nama) {
    if (nama === "wajah") return "scan-face";
    if (nama === "webauthn") return "fingerprint";
    return "shield";
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
      if (statusDongle) {
        statusDongle.hidden = false;
      }
      if (data.detected) {
        aturStatusDongle(teksDongle("msgOk"), "is-ok");
      } else {
        aturStatusDongle(
          teksDongle("msgOff") + " — " + teksDongle("msgOffHint"),
          "is-off"
        );
      }
    })
    .catch(function () {
      if (statusDongle) {
        statusDongle.hidden = true;
      }
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
          tampilkanGalat(galat1, data.error || teksPanel("msgRequestFailed", ""));
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
            teksPanel("msgNone", "")
          );
          return;
        }
        metode.forEach(function (m) {
          const tombol = document.createElement("button");
          tombol.type = "button";
          tombol.className = "kx-btn kx-btn-secondary kx-btn-block";
          tombol.innerHTML =
            '<svg class="kx-icon" width="18" height="18" aria-hidden="true" focusable="false">' +
            '<use href="' + alamatSprite() + "#" + ikonMetode(m.nama) +
            '"></use></svg><span></span>';
          tombol.querySelector("span").textContent = labelMetode(m);
          tombol.dataset.metode = m.nama;
          tombol.addEventListener("click", function () {
            jalankanMetode(m);
          });
          daftarMetode.appendChild(tombol);
        });
        if (hint2) {
          hint2.textContent = teksPanel("msgChoose", "");
        }
        // Satu metode langsung dijalankan; dua metode atau lebih menunggu
        // pilihan pengguna lewat tombol.
        if (metode.length === 1) {
          jalankanMetode(metode[0]);
        }
      })
      .catch(function () {
        tampilkanGalat(galat1, teksPanel("msgRequestFailed", ""));
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
        teksPanel("msgUnsupported", "")
      );
      return;
    }

    tampilkanGalat(galat2, "");
    aturStatus(
      teksPanel("msgVerifying", "")
        .replace("{metode}", labelMetode(metode))
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
          tampilkanGalat(galat2, data.error || teksPanel("msgFailed", ""));
          aturStatus("");
          sedangVerifikasi = false;
          nonaktifkanTombol(false);
          return;
        }
        window.location.href = data.redirect || "/dashboard";
      })
      .catch(function (err) {
        tampilkanGalat(galat2, err.message || teksPanel("msgFailed", ""));
        aturStatus("");
        sedangVerifikasi = false;
        nonaktifkanTombol(false);
      });
  }
});
