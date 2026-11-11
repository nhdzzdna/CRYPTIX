/* static/js/ui/aksi-mengambang.js - Bar aksi saat ada item terpilih */
(function () {
  "use strict";

  var KX = (window.KX = window.KX || {});

  function pilihan() {
    return Array.prototype.slice.call(
      document.querySelectorAll("[data-kx-pilih]:checked")
    );
  }

  function segarkan() {
    var terpilih = pilihan();
    document.querySelectorAll(".kx-aksi-mengambang").forEach(function (bar) {
      bar.classList.toggle("is-visible", terpilih.length > 0);
      var hitung = bar.querySelector("[data-kx-jumlah]");
      if (hitung) hitung.textContent = String(terpilih.length);
    });
    document.querySelectorAll("[data-kx-pilih]").forEach(function (kotak) {
      var baris = kotak.closest("tr, .kx-list-row, .kx-card");
      if (baris) baris.classList.toggle("is-selected", kotak.checked);
    });
  }

  function init() {
    document.addEventListener("change", function (e) {
      if (e.target.matches("[data-kx-pilih]")) segarkan();
    });
    segarkan();
  }

  KX.aksiMengambang = { segarkan: segarkan, terpilih: pilihan, init: init };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
