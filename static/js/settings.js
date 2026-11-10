/**
 * static/js/settings.js — aksi biometrik di halaman Settings (butir 4.8).
 *
 * Tombol tambah WebAuthn dan daftar ulang wajah memakai data-reauth
 * "biometric.manage". reauth.js menangani modal autentikasi ulang lalu
 * memancarkan peristiwa cryptix:reauth-grant; skrip ini mengingat aksi yang
 * ditekan dan menjalankannya dengan grant tersebut.
 *
 * Grant hanya hidup di memori dan langsung dipakai sekali oleh permintaan
 * API; tidak ada kata sandi atau grant yang disimpan di storage.
 */
"use strict";

(function () {
  var tertunda = null;

  function catatAksi(target) {
    if (!target || typeof target.closest !== "function") {
      return;
    }
    var pemicu = target.closest("[data-settings-action]");
    if (pemicu) {
      tertunda = {
        aksi: pemicu.getAttribute("data-settings-action"),
        pemicu: pemicu
      };
    }
  }

  document.addEventListener("pointerdown", function (event) {
    catatAksi(event.target);
  }, true);

  document.addEventListener("focusin", function (event) {
    catatAksi(event.target);
  }, true);

  document.addEventListener("keydown", function (event) {
    if (event.key === "Enter" || event.key === " ") {
      catatAksi(event.target);
    }
  }, true);

  function muatUlangSetelah(pesan) {
    window.setTimeout(function () {
      window.location.reload();
    }, pesan || 1000);
  }

  function jalankanWebAuthn(grant) {
    var inputNama = document.getElementById("webauthn-nama");
    var nama = inputNama ? inputNama.value.trim() : "";
    return window.CryptixWebAuthn.daftar("settings-webauthn-status", {
      nama: nama,
      grant: grant
    }).then(function (data) {
      if (data && !data.setup_done) {
        muatUlangSetelah(900);
      }
      return data;
    });
  }

  function jalankanWajah(grant) {
    return window.CryptixFace.daftar(
      "settings-video", "settings-canvas", "settings-face-status",
      { grant: grant }
    ).then(function (data) {
      muatUlangSetelah(1200);
      return data;
    });
  }

  document.addEventListener("cryptix:reauth-grant", function (event) {
    var detail = event.detail || {};
    if (detail.scope !== "biometric.manage" || !tertunda) {
      return;
    }

    var aksi = tertunda.aksi;
    tertunda = null;
    var grant = detail.token || "";

    try {
      if (aksi === "webauthn-add") {
        jalankanWebAuthn(grant).catch(function () {});
      } else if (aksi === "face-enroll") {
        jalankanWajah(grant).catch(function () {});
      }
    } catch (err) {
      // Pesan galat sudah ditampilkan oleh modul WebAuthn/wajah.
    }
  });
})();

(function () {
  var tautan = Array.prototype.slice.call(
    document.querySelectorAll("[data-settings-nav]")
  );
  if (!tautan.length) {
    return;
  }

  var bagian = [];
  tautan.forEach(function (item) {
    var id = item.getAttribute("data-settings-nav");
    var target = id ? document.getElementById(id) : null;
    if (target) {
      bagian.push({ tautan: item, target: target });
    }
  });
  if (!bagian.length) {
    return;
  }

  function tandai(id) {
    bagian.forEach(function (pasangan) {
      var aktif = pasangan.target.id === id;
      pasangan.tautan.classList.toggle("is-active", aktif);
      if (aktif) {
        pasangan.tautan.setAttribute("aria-current", "true");
      } else {
        pasangan.tautan.removeAttribute("aria-current");
      }
    });
  }

  tautan.forEach(function (item) {
    item.addEventListener("click", function () {
      var id = item.getAttribute("data-settings-nav");
      if (id) {
        tandai(id);
      }
    });
  });

  if (!("IntersectionObserver" in window)) {
    return;
  }

  var pengamat = new IntersectionObserver(function (entri) {
    var terlihat = entri.filter(function (item) {
      return item.isIntersecting;
    });
    if (terlihat.length) {
      tandai(terlihat[0].target.id);
    }
  }, { rootMargin: "-25% 0px -60% 0px", threshold: 0 });

  bagian.forEach(function (pasangan) {
    pengamat.observe(pasangan.target);
  });
})();
