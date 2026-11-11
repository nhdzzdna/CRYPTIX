/* static/js/ui/salin.js - Tombol salin dan sel hash */
(function () {
  "use strict";

  var KX = (window.KX = window.KX || {});

  function salinTeks(teks) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(teks);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = teks;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        area.remove();
      }
    });
  }

  function salin(teks, tombol) {
    if (!teks) return Promise.resolve();
    return salinTeks(String(teks)).then(function () {
      if (KX.toast) KX.toast("Disalin ke clipboard.", "success", 2500);
      if (tombol) {
        tombol.classList.add("is-copied");
        window.setTimeout(function () { tombol.classList.remove("is-copied"); }, 1600);
      }
    }).catch(function () {
      if (KX.toast) KX.toast("Gagal menyalin. Salin secara manual.", "danger");
    });
  }

  function pasangTombol() {
    document.querySelectorAll("[data-kx-salin]").forEach(function (el) {
      if (el.dataset.kxSalinSiap === "1") return;
      el.dataset.kxSalinSiap = "1";
      el.addEventListener("click", function (e) {
        e.preventDefault();
        var teks = el.getAttribute("data-kx-salin");
        if (!teks) {
          var target = el.getAttribute("data-kx-salin-target");
          var sumber = target ? document.querySelector(target) : null;
          teks = sumber ? sumber.textContent : el.textContent;
        }
        salin(teks.trim(), el);
      });
    });
  }

  function pasangHash() {
    document.querySelectorAll("[data-kx-hash]").forEach(function (el) {
      if (el.dataset.kxHashSiap === "1") return;
      el.dataset.kxHashSiap = "1";
      var penuh = (el.getAttribute("data-kx-hash") || "").trim();
      if (!penuh) return;
      var teks = el.querySelector(".kx-hash-teks");
      if (!teks) {
        teks = document.createElement("span");
        teks.className = "kx-hash-teks";
        el.insertBefore(teks, el.firstChild);
      }
      teks.textContent = penuh.length > 16 ? penuh.slice(0, 16) + "\u2026" : penuh;
      teks.title = penuh;

      var tombol = el.querySelector(".kx-hash-copy");
      if (!tombol) {
        tombol = document.createElement("button");
        tombol.type = "button";
        tombol.className = "kx-hash-copy";
        tombol.setAttribute("aria-label", "Salin hash lengkap");
        tombol.textContent = "Salin";
        el.appendChild(tombol);
      }
      tombol.addEventListener("click", function (e) {
        e.preventDefault();
        salin(penuh, tombol);
      });
    });
  }

  function init() {
    pasangTombol();
    pasangHash();
  }

  KX.salin = salin;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
