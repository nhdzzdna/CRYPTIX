/* static/js/ui/sandi.js - Tombol tampilkan/sembunyikan kata sandi */
(function () {
  "use strict";

  var KX = (window.KX = window.KX || {});

  function alamatSprite() {
    var contoh = document.querySelector("use[href*='sprite.svg']");
    if (contoh) {
      var href = contoh.getAttribute("href") || "";
      return href.split("#")[0];
    }
    return "/static/icons/sprite.svg";
  }

  function aturIkon(tombol, terlihat) {
    var pakai = tombol.querySelector("use");
    if (!pakai) return;
    pakai.setAttribute("href", alamatSprite() + "#" + (terlihat ? "eye" : "eye-off"));
  }

  function pasang(kotak) {
    if (kotak.dataset.kxSandiSiap === "1") return;
    var input = kotak.querySelector("input");
    if (!input) return;
    kotak.dataset.kxSandiSiap = "1";

    var tombol = kotak.querySelector(".kx-sandi-toggle");
    if (!tombol) {
      tombol = document.createElement("button");
      tombol.type = "button";
      tombol.className = "kx-sandi-toggle";
      kotak.appendChild(tombol);
    }
    tombol.setAttribute("aria-label", "Tampilkan kata sandi");
    tombol.setAttribute("aria-pressed", "false");
    tombol.innerHTML = '<svg class="kx-icon" width="17" height="17" aria-hidden="true" focusable="false"><use href="' +
      alamatSprite() + '#eye-off"></use></svg>';

    tombol.addEventListener("click", function () {
      var terlihat = input.type === "text";
      input.type = terlihat ? "password" : "text";
      tombol.setAttribute("aria-pressed", terlihat ? "false" : "true");
      tombol.setAttribute("aria-label", terlihat ? "Tampilkan kata sandi" : "Sembunyikan kata sandi");
      aturIkon(tombol, !terlihat);
      input.focus();
    });
  }

  function init() {
    document.querySelectorAll("[data-kx-sandi]").forEach(pasang);
  }

  KX.sandi = { init: init };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
