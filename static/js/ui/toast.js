/* static/js/ui/toast.js - Notifikasi toast KOSYAK */
(function () {
  "use strict";

  var KX = (window.KX = window.KX || {});

  var JENIS = {
    success: "success",
    danger: "danger",
    error: "danger",
    warning: "warning",
    warn: "warning",
    info: "info",
    message: "info",
    default: "info"
  };

  function wadah() {
    var el = document.querySelector(".kx-toast-wrap");
    if (!el) {
      el = document.createElement("div");
      el.className = "kx-toast-wrap";
      el.setAttribute("role", "status");
      el.setAttribute("aria-live", "polite");
      document.body.appendChild(el);
    }
    return el;
  }

  function normalisasi(jenis) {
    return JENIS[String(jenis || "info").toLowerCase()] || "info";
  }

  function tampil(pesan, jenis, durasi) {
    if (!pesan) return null;
    var tipe = normalisasi(jenis);
    var kotak = document.createElement("div");
    kotak.className = "kx-toast kx-toast-" + tipe;

    var isi = document.createElement("div");
    isi.className = "kx-toast-body";
    isi.textContent = String(pesan);
    kotak.appendChild(isi);

    var tutup = document.createElement("button");
    tutup.type = "button";
    tutup.className = "kx-toast-close";
    tutup.setAttribute("aria-label", "Tutup notifikasi");
    tutup.textContent = "\u00d7";
    tutup.addEventListener("click", function () { kotak.remove(); });
    kotak.appendChild(tutup);

    wadah().appendChild(kotak);
    var lama = typeof durasi === "number" ? durasi : 4000;
    if (lama > 0) {
      window.setTimeout(function () { kotak.remove(); }, lama);
    }
    return kotak;
  }

  function bacaFlash() {
    var sumber = document.getElementById("kx-flash");
    if (!sumber) return;
    var data = [];
    try {
      data = JSON.parse(sumber.getAttribute("data-pesan") || "[]");
    } catch (_err) {
      data = [];
    }
    if (!Array.isArray(data)) return;
    data.forEach(function (baris) {
      if (Array.isArray(baris) && baris.length >= 2) {
        tampil(baris[1], baris[0]);
      }
    });
    sumber.remove();
  }

  KX.toast = tampil;
  KX.notifikasi = tampil;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bacaFlash);
  } else {
    bacaFlash();
  }
})();
