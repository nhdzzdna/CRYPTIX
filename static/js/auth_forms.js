/**
 * static/js/auth_forms.js — interaksi presentasional form autentikasi.
 *
 * Dua perilaku murni di sisi klien (tidak mengubah validasi server):
 *   1. tombol tampil/sembunyikan password (data-toggle-password="<idInput>");
 *   2. meteran kekuatan password (data-strength-for="<idInput>") — petunjuk
 *      visual kebijakan "minimal 12 karakter, 3 dari 4 jenis karakter".
 */

"use strict";

(function () {
  // ── Tombol tampil/sembunyikan password ──────────────────────────────────────
  document.querySelectorAll("[data-toggle-password]").forEach(function (tombol) {
    var input = document.getElementById(tombol.getAttribute("data-toggle-password"));
    if (!input) {
      return;
    }
    var ikonMata = tombol.querySelector(".auth-icon-eye");
    var ikonCoret = tombol.querySelector(".auth-icon-eye-off");

    function perbarui() {
      var tampil = input.type === "text";
      tombol.setAttribute("aria-pressed", tampil ? "true" : "false");
      tombol.setAttribute(
        "aria-label",
        tampil ? "Sembunyikan password" : "Tampilkan password"
      );
      tombol.setAttribute(
        "title",
        tampil ? "Sembunyikan password" : "Tampilkan password"
      );
      if (ikonMata) {
        ikonMata.hidden = tampil;
      }
      if (ikonCoret) {
        ikonCoret.hidden = !tampil;
      }
    }

    tombol.addEventListener("click", function () {
      input.type = input.type === "password" ? "text" : "password";
      perbarui();
      input.focus();
    });
    perbarui();
  });

  // ── Meteran kekuatan password ──────────────────────────────────────────────
  var LABEL = ["", "Lemah", "Sedang", "Kuat", "Sangat kuat"];

  function jenisKarakter(nilai) {
    var jenis = 0;
    if (/[a-z]/.test(nilai)) {
      jenis += 1;
    }
    if (/[A-Z]/.test(nilai)) {
      jenis += 1;
    }
    if (/[0-9]/.test(nilai)) {
      jenis += 1;
    }
    if (/[^A-Za-z0-9]/.test(nilai)) {
      jenis += 1;
    }
    return jenis;
  }

  function hitungSkor(nilai) {
    // Petunjuk visual saja; keputusan akhir tetap di tangan server.
    if (!nilai) {
      return 0;
    }
    var jenis = jenisKarakter(nilai);
    var skor = 1;                    // ada isian, belum memenuhi panjang minimum
    if (nilai.length >= 12) {
      skor = 2;                      // panjang minimum terpenuhi
    }
    if (nilai.length >= 12 && jenis >= 3) {
      skor += 1;                     // variasi jenis karakter cukup
    }
    if (nilai.length >= 16 && jenis >= 3) {
      skor += 1;                     // ruang lebih dari kebijakan minimum
    }
    return Math.min(skor, 4);
  }

  document.querySelectorAll("[data-strength-for]").forEach(function (meter) {
    var input = document.getElementById(meter.getAttribute("data-strength-for"));
    var label = meter.querySelector(".auth-pw-meter-label");
    var segmen = meter.querySelectorAll(".auth-pw-seg");
    if (!input) {
      return;
    }

    function perbarui() {
      var skor = hitungSkor(input.value);
      meter.setAttribute("data-level", String(skor));
      segmen.forEach(function (seg, urutan) {
        seg.classList.toggle("on", urutan < skor);
      });
      if (label) {
        label.textContent = skor ? "Kekuatan: " + LABEL[skor] : "";
      }
    }

    input.addEventListener("input", perbarui);
    perbarui();
  });
})();
