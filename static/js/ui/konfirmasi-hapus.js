/* static/js/ui/konfirmasi-hapus.js - Dialog konfirmasi hapus */
(function () {
  "use strict";

  var KX = (window.KX = window.KX || {});

  function teks(nilai, cadangan) {
    return nilai === undefined || nilai === null || nilai === "" ? cadangan : String(nilai);
  }

  function konfirmasi(opsi) {
    opsi = opsi || {};
    var overlay = document.createElement("div");
    overlay.className = "kx-modal-overlay kx-dialog-hapus";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-labelledby", "kx-hapus-judul");

    var modal = document.createElement("div");
    modal.className = "kx-modal";

    var kepala = document.createElement("div");
    kepala.className = "kx-modal-head";
    var judul = document.createElement("h2");
    judul.className = "kx-modal-title";
    judul.id = "kx-hapus-judul";
    judul.textContent = teks(opsi.judul, "Hapus item?");
    kepala.appendChild(judul);

    var tutup = document.createElement("button");
    tutup.type = "button";
    tutup.className = "kx-btn kx-btn-icon";
    tutup.setAttribute("data-kx-tutup", "");
    tutup.setAttribute("aria-label", "Tutup dialog");
    tutup.textContent = "\u00d7";
    kepala.appendChild(tutup);
    modal.appendChild(kepala);

    var badan = document.createElement("div");
    badan.className = "kx-modal-body";
    var paragraf = document.createElement("p");
    paragraf.appendChild(document.createTextNode("Item "));
    var nama = document.createElement("span");
    nama.className = "kx-dialog-hapus-nama";
    nama.textContent = teks(opsi.nama, "ini");
    paragraf.appendChild(nama);
    paragraf.appendChild(document.createTextNode(" akan dihapus permanen. Tindakan ini tidak dapat dibatalkan."));
    badan.appendChild(paragraf);
    modal.appendChild(badan);

    var kaki = document.createElement("div");
    kaki.className = "kx-modal-foot";
    var batal = document.createElement("button");
    batal.type = "button";
    batal.className = "kx-btn kx-btn-secondary";
    batal.setAttribute("data-kx-tutup", "");
    batal.textContent = teks(opsi.labelBatal, "Batal");
    kaki.appendChild(batal);

    var hapus = document.createElement("button");
    hapus.type = "button";
    hapus.className = "kx-btn kx-btn-danger-solid";
    hapus.textContent = teks(opsi.labelTombol, "Hapus");
    kaki.appendChild(hapus);
    modal.appendChild(kaki);

    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    KX.modal.buka(overlay);

    function selesai() {
      KX.modal.tutup(overlay);
      overlay.remove();
    }

    hapus.addEventListener("click", function () {
      var cb = opsi.onKonfirmasi;
      selesai();
      if (typeof cb === "function") cb();
    });
    batal.addEventListener("click", selesai);
    tutup.addEventListener("click", selesai);
    overlay.addEventListener("click", function (e) {
      if (e.target === overlay) selesai();
    });
    document.addEventListener("keydown", function esc(e) {
      if (e.key === "Escape" && document.body.contains(overlay)) {
        document.removeEventListener("keydown", esc);
        selesai();
      }
    });
    return overlay;
  }

  KX.konfirmasiHapus = konfirmasi;
})();
