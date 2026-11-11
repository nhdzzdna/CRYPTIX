/**
 * static/js/settings.js — interaksi antarmuka halaman Settings KOSYAK.
 *
 * Menangani:
 * 1. Pindah tab pill tanpa reload dengan sinkronisasi hash URL (#profil, dll).
 * 2. Pemicu modal dialog via KX.modal.
 * 3. Verifikasi ketik nama pengguna pada zona bahaya (Reset Data & Hapus Akun).
 * 4. Konfirmasi hapus kredensial WebAuthn via KX.konfirmasiHapus.
 * 5. Unduh kunci pemulihan baru ke format berkas teks (.txt).
 * 6. Alur autentikasi ulang dan pendaftaran biometrik (WebAuthn & Face Recognition).
 */
"use strict";

(function () {
  var DAFTAR_TAB = ["profil", "keamanan", "biometrik", "sesi", "akun"];

  /* ── 1. Tab Pill Navigation ────────────────────────────────────────────── */
  function getTabDariHash() {
    var hash = (window.location.hash || "").replace(/^#/, "").toLowerCase();
    if (DAFTAR_TAB.indexOf(hash) !== -1) {
      return hash;
    }
    return null;
  }

  function aktifkanTab(namaTab, perbaruiHash) {
    if (DAFTAR_TAB.indexOf(namaTab) === -1) {
      namaTab = "profil";
    }

    var tabs = document.querySelectorAll(".kx-settings-tabs .kx-tab");
    Array.prototype.forEach.call(tabs, function (tab) {
      var target = tab.getAttribute("data-tab-target");
      var cocok = target === namaTab;
      tab.classList.toggle("is-active", cocok);
      tab.setAttribute("aria-selected", cocok ? "true" : "false");
    });

    var panes = document.querySelectorAll(".kx-tab-pane");
    Array.prototype.forEach.call(panes, function (pane) {
      var idTarget = "pane-" + namaTab;
      var cocok = pane.id === idTarget;
      if (cocok) {
        pane.removeAttribute("hidden");
      } else {
        pane.setAttribute("hidden", "true");
      }
    });

    if (perbaruiHash) {
      if (window.location.hash !== "#" + namaTab) {
        if (window.history && window.history.replaceState) {
          window.history.replaceState(null, "", "#" + namaTab);
        } else {
          window.location.hash = "#" + namaTab;
        }
      }
    }
  }

  function inisialisasiTab() {
    var recoveryBaru = document.getElementById("box-recovery-key-baru");
    var tabAwal = null;

    if (recoveryBaru) {
      tabAwal = "keamanan";
    } else {
      tabAwal = getTabDariHash() || "profil";
    }

    aktifkanTab(tabAwal, false);
  }

  window.addEventListener("hashchange", function () {
    var tab = getTabDariHash();
    if (tab) {
      aktifkanTab(tab, false);
    }
  });

  document.addEventListener("click", function (event) {
    var tabBtn = event.target.closest("[data-tab-target]");
    if (tabBtn) {
      event.preventDefault();
      var target = tabBtn.getAttribute("data-tab-target");
      aktifkanTab(target, true);
      return;
    }

    var gotoBtn = event.target.closest("[data-goto-tab]");
    if (gotoBtn) {
      event.preventDefault();
      var gotoTarget = gotoBtn.getAttribute("data-goto-tab");
      aktifkanTab(gotoTarget, true);
      return;
    }
  });

  /* ── 2. Modal Dialog Pemicu ────────────────────────────────────────────── */
  document.addEventListener("click", function (event) {
    var bukaBtn = event.target.closest("[data-buka-modal]");
    if (!bukaBtn) {
      return;
    }
    var targetId = bukaBtn.getAttribute("data-buka-modal");
    var modalEl = targetId ? document.querySelector(targetId) : null;
    if (modalEl && window.KX && window.KX.modal) {
      window.KX.modal.buka(modalEl);
    }
  });

  /* ── 3. Zona Bahaya: Verifikasi Ketik Username ─────────────────────────── */
  document.addEventListener("input", function (event) {
    var input = event.target;
    if (!input || !input.classList.contains("js-confirm-username")) {
      return;
    }
    var targetUser = input.getAttribute("data-target-username") || "";
    var submitSel = input.getAttribute("data-submit-target");
    var submitBtn = submitSel ? document.querySelector(submitSel) : null;
    if (!submitBtn) {
      return;
    }
    var cocok = input.value.trim() === targetUser.trim();
    submitBtn.disabled = !cocok;
  });

  /* ── 4. WebAuthn: Konfirmasi Hapus via KX.konfirmasiHapus ───────────────── */
  document.addEventListener("click", function (event) {
    var btn = event.target.closest(".js-hapus-kredensial");
    if (!btn) {
      return;
    }
    if (btn.dataset.confirmed === "true") {
      btn.dataset.confirmed = "";
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === "function") {
      event.stopImmediatePropagation();
    }

    var nama = btn.getAttribute("data-cred-name") || "kredensial ini";
    if (window.KX && typeof window.KX.konfirmasiHapus === "function") {
      window.KX.konfirmasiHapus({
        nama: nama,
        judul: "Hapus Kredensial?",
        pesan: "Kredensial {nama} akan dihapus permanen. Lanjutkan?",
        labelTombol: "Hapus",
        onKonfirmasi: function () {
          btn.dataset.confirmed = "true";
          btn.click();
        }
      });
    } else {
      btn.dataset.confirmed = "true";
      btn.click();
    }
  }, true);

  /* ── 5. Unduh Kunci Pemulihan Baru (.txt) ───────────────────────────────── */
  document.addEventListener("click", function (event) {
    var btn = event.target.closest("#btn-download-settings-recovery");
    if (!btn) {
      return;
    }
    var codeEl = document.getElementById("settings-recovery-val");
    var kunci = codeEl ? codeEl.textContent.trim() : "";
    if (!kunci) {
      return;
    }

    var konten = "KOSYAK - Kunci Pemulihan\r\n\r\n" +
      "Simpan berkas ini di tempat aman. Kunci tidak dapat ditampilkan lagi.\r\n\r\n" +
      kunci + "\r\n";

    var blob = new Blob([konten], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var tautan = document.createElement("a");
    tautan.href = url;
    tautan.download = "cryptix-kunci-pemulihan.txt";
    document.body.appendChild(tautan);
    tautan.click();
    document.body.removeChild(tautan);
    window.setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 1000);

    if (window.KX && typeof window.KX.toast === "function") {
      window.KX.toast("Berkas kunci pemulihan diunduh.", "success");
    }
  });

  /* ── 6. Alur Autentikasi Ulang & Aksi Biometrik ────────────────────────── */
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

  function muatUlangSetelah(ms) {
    window.setTimeout(function () {
      window.location.reload();
    }, ms || 1000);
  }

  function jalankanWebAuthn(grant) {
    var inputNama = document.getElementById("webauthn-nama");
    var nama = inputNama ? inputNama.value.trim() : "";
    if (!window.CryptixWebAuthn || typeof window.CryptixWebAuthn.daftar !== "function") {
      return Promise.reject(new Error("Modul WebAuthn tidak tersedia."));
    }
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
    if (!window.CryptixFace || typeof window.CryptixFace.daftar !== "function") {
      return Promise.reject(new Error("Modul Face Recognition tidak tersedia."));
    }
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
      // Pesan galat sudah ditampilkan oleh modul biometrik.
    }
  });

  /* Inisialisasi awal saat DOM siap */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", inisialisasiTab);
  } else {
    inisialisasiTab();
  }
})();
