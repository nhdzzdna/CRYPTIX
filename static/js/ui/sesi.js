/* static/js/ui/sesi.js - Hitung mundur badge sesi di topbar */
(function () {
  "use strict";

  var KX = (window.KX = window.KX || {});

  function dua(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function mulai() {
    var badge = document.getElementById("kx-session");
    var waktu = document.getElementById("kx-session-waktu");
    if (!badge || !waktu) return;

    var sisa = parseInt(badge.getAttribute("data-sisa"), 10);
    if (isNaN(sisa)) sisa = 0;

    function gambar() {
      var menit = Math.floor(sisa / 60);
      var detik = sisa % 60;
      waktu.textContent = dua(menit) + ":" + dua(detik);
      badge.classList.toggle("is-warning", sisa > 0 && sisa < 60);
    }

    gambar();

    var timer = window.setInterval(function () {
      if (sisa > 0) sisa -= 1;
      gambar();
      if (sisa <= 0) window.clearInterval(timer);
    }, 1000);

    badge.addEventListener("click", function () {
      window.location.reload();
    });
  }

  KX.sesi = { mulai: mulai };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mulai);
  } else {
    mulai();
  }
})();
