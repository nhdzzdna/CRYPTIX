/* static/js/security_center.js — Security Center UI logic */
(function () {
  "use strict";

  var KX = window.KX || {};

  function initVerificationToast() {
    var page = document.querySelector(".kx-sc-page");
    if (!page) return;

    if (page.getAttribute("data-verified") === "1") {
      var isValid = page.getAttribute("data-chain-valid") === "1";
      var msgValid = page.getAttribute("data-msg-valid") || "Rantai global utuh: semua blok tervalidasi.";
      var msgTamperedTpl = page.getAttribute("data-msg-tampered") || "{count} blok pada rantai global terdeteksi rusak!";
      var count = page.getAttribute("data-tampered-count") || "1";

      if (isValid) {
        if (KX.toast) KX.toast(msgValid, "success", 4000);
      } else {
        var msg = msgTamperedTpl.replace("{count}", count);
        if (KX.toast) KX.toast(msg, "danger", 6000);
      }
    }
  }

  function initFilterChips() {
    var chips = document.querySelectorAll(".kx-sc-chips .kx-chip");
    var rows = document.querySelectorAll(".kx-sc-log-row");
    var emptyMsg = document.getElementById("filter-empty-msg");
    var tableWrap = document.querySelector(".kx-sc-card-log .kx-table-wrap");

    if (!chips.length || !rows.length) return;

    chips.forEach(function (chip) {
      chip.addEventListener("click", function () {
        chips.forEach(function (c) {
          c.classList.remove("is-active");
          c.setAttribute("aria-pressed", "false");
        });
        chip.classList.add("is-active");
        chip.setAttribute("aria-pressed", "true");

        var filter = chip.getAttribute("data-filter");
        var visibleCount = 0;

        rows.forEach(function (row) {
          var action = row.getAttribute("data-action");
          if (filter === "all" || action === filter) {
            row.style.display = "";
            visibleCount++;
          } else {
            row.style.display = "none";
          }
        });

        if (emptyMsg) {
          emptyMsg.hidden = (visibleCount > 0);
        }
        if (tableWrap) {
          tableWrap.style.display = (visibleCount > 0) ? "" : "none";
        }
      });
    });
  }

  function init() {
    initVerificationToast();
    initFilterChips();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
