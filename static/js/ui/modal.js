/* static/js/ui/modal.js - Modal dan drawer dengan Esc serta jebakan fokus */
(function () {
  "use strict";

  var KX = (window.KX = window.KX || {});
  var tumpukan = [];
  var fokusSebelum = null;

  var PILIH_FOKUS = [
    "a[href]",
    "button:not([disabled])",
    "input:not([disabled])",
    "select:not([disabled])",
    "textarea:not([disabled])",
    "[tabindex]:not([tabindex='-1'])"
  ].join(",");

  function daftarFokus(el) {
    return Array.prototype.filter.call(
      el.querySelectorAll(PILIH_FOKUS),
      function (n) { return n.offsetParent !== null; }
    );
  }

  function buka(target) {
    var el = typeof target === "string" ? document.querySelector(target) : target;
    if (!el) return null;
    if (tumpukan.indexOf(el) === -1) tumpukan.push(el);
    if (!fokusSebelum) fokusSebelum = document.activeElement;
    el.classList.add("is-open");
    el.setAttribute("aria-hidden", "false");
    var fokusable = daftarFokus(el);
    if (fokusable.length) fokusable[0].focus();
    return el;
  }

  function tutup(target) {
    var el = target
      ? (typeof target === "string" ? document.querySelector(target) : target)
      : tumpukan[tumpukan.length - 1];
    if (!el) return;
    el.classList.remove("is-open");
    el.setAttribute("aria-hidden", "true");
    var i = tumpukan.indexOf(el);
    if (i !== -1) tumpukan.splice(i, 1);
    if (tumpukan.length === 0 && fokusSebelum && fokusSebelum.focus) {
      fokusSebelum.focus();
      fokusSebelum = null;
    }
  }

  document.addEventListener("keydown", function (e) {
    if (tumpukan.length === 0) return;
    var aktif = tumpukan[tumpukan.length - 1];
    if (e.key === "Escape") {
      e.preventDefault();
      tutup(aktif);
      return;
    }
    if (e.key !== "Tab") return;
    var fokusable = daftarFokus(aktif);
    if (fokusable.length === 0) return;
    var pertama = fokusable[0];
    var terakhir = fokusable[fokusable.length - 1];
    if (e.shiftKey && document.activeElement === pertama) {
      e.preventDefault();
      terakhir.focus();
    } else if (!e.shiftKey && document.activeElement === terakhir) {
      e.preventDefault();
      pertama.focus();
    }
  });

  document.addEventListener("click", function (e) {
    var penutup = e.target.closest("[data-kx-tutup]");
    if (penutup) {
      var isi = penutup.closest(".kx-modal, .kx-drawer");
      if (isi) {
        var wadah = isi.parentElement;
        if (wadah && (wadah.classList.contains("kx-modal-overlay") ||
                      wadah.classList.contains("kx-drawer-overlay"))) {
          tutup(wadah);
          return;
        }
      }
    }
    if (e.target.classList.contains("kx-modal-overlay") ||
        e.target.classList.contains("kx-drawer-overlay")) {
      tutup(e.target);
    }
  });

  KX.modal = { buka: buka, tutup: tutup };
})();
