/**
 * static/js/account_recovery.js — Interaksi antarmuka halaman pemulihan akun KOSYAK.
 *
 * Menangani:
 * 1. Pemicu modal dialog konfirmasi reset akun tanpa masuk via KX.modal.
 * 2. Inisialisasi komponen sandi jika diperlukan.
 */
"use strict";

(function () {
  document.addEventListener("click", function (event) {
    var btn = event.target.closest("[data-buka-modal]");
    if (!btn) {
      return;
    }
    var targetId = btn.getAttribute("data-buka-modal");
    var modalEl = targetId ? document.querySelector(targetId) : null;
    if (modalEl && window.KX && window.KX.modal) {
      window.KX.modal.buka(modalEl);
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      if (window.KX && window.KX.sandi) {
        window.KX.sandi.init();
      }
    });
  } else if (window.KX && window.KX.sandi) {
    window.KX.sandi.init();
  }
})();
