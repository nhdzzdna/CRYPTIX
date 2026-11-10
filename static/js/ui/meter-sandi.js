/* static/js/ui/meter-sandi.js - Meter kekuatan kata sandi 4 segmen */
(function () {
  "use strict";

  var KX = (window.KX = window.KX || {});
  var LABEL = ["", "Lemah", "Sedang", "Kuat", "Sangat kuat"];

  function hitung(nilai) {
    if (!nilai) return 0;
    var skor = 0;
    if (nilai.length >= 12) skor += 1;
    if (nilai.length >= 16) skor += 1;
    var jenis = 0;
    if (/[a-z]/.test(nilai)) jenis += 1;
    if (/[A-Z]/.test(nilai)) jenis += 1;
    if (/[0-9]/.test(nilai)) jenis += 1;
    if (/[^A-Za-z0-9]/.test(nilai)) jenis += 1;
    if (jenis >= 3) skor += 1;
    if (jenis >= 4 && nilai.length >= 12) skor += 1;
    return Math.max(1, Math.min(4, skor));
  }

  function pasang(kotak) {
    if (kotak.dataset.kxMeterSiap === "1") return;
    var selektor = kotak.getAttribute("data-kx-meter-input");
    var input = selektor
      ? document.querySelector(selektor)
      : kotak.parentElement.querySelector("input");
    if (!input) return;
    kotak.dataset.kxMeterSiap = "1";

    if (!kotak.querySelector(".kx-meter-track")) {
      var trek = document.createElement("div");
      trek.className = "kx-meter-track";
      for (var i = 0; i < 4; i += 1) {
        var seg = document.createElement("span");
        seg.className = "kx-meter-seg";
        trek.appendChild(seg);
      }
      kotak.appendChild(trek);
    }
    if (!kotak.querySelector(".kx-meter-label")) {
      var label = document.createElement("span");
      label.className = "kx-meter-label";
      kotak.appendChild(label);
    }

    var segmen = kotak.querySelectorAll(".kx-meter-seg");
    var teks = kotak.querySelector(".kx-meter-label");

    function perbarui() {
      var level = hitung(input.value);
      kotak.setAttribute("data-level", String(level));
      Array.prototype.forEach.call(segmen, function (seg, indeks) {
        seg.classList.toggle("is-on", indeks < level);
      });
      teks.textContent = level ? LABEL[level] : "";
    }

    input.addEventListener("input", perbarui);
    perbarui();
  }

  function init() {
    document.querySelectorAll("[data-kx-meter]").forEach(pasang);
  }

  KX.meterSandi = { init: init, hitung: hitung };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
