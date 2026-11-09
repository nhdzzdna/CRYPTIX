/* static/js/script.js — CRYPTIX global helpers */

"use strict";

// ── Sidebar toggle (mobile) ───────────────────────────────────────────────────
function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  if (sidebar) sidebar.classList.toggle("open");
}

document.addEventListener("DOMContentLoaded", function () {
  const tombol = document.getElementById("sidebar-toggle");
  if (tombol) tombol.addEventListener("click", toggleSidebar);
});

// Close sidebar when clicking outside on mobile
document.addEventListener("click", function (e) {
  const sidebar = document.getElementById("sidebar");
  if (!sidebar) return;
  const toggle = document.querySelector(".sidebar-toggle");
  if (
    sidebar.classList.contains("open") &&
    !sidebar.contains(e.target) &&
    e.target !== toggle
  ) {
    sidebar.classList.remove("open");
  }
});

// ── Auto-dismiss flash messages ───────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", function () {
  const flashes = document.querySelectorAll(".alert");
  flashes.forEach(function (el) {
    setTimeout(function () {
      el.style.transition = "opacity .5s";
      el.style.opacity = "0";
      setTimeout(function () { el.remove(); }, 500);
    }, 5000);
  });
});

// ── Confirm delete helper ─────────────────────────────────────────────────────
function confirmDelete(msg) {
  return confirm(msg || "Yakin ingin menghapus item ini?");
}

// ── Copy to clipboard helper ─────────────────────────────────────────────────
function copyToClipboard(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(function () {
      alert("Disalin ke clipboard!");
    });
  }
}
