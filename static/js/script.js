/* static/js/script.js — CRYPTIX global helpers */

"use strict";

// ── Sidebar toggle (mobile) ───────────────────────────────────────────────────
function setSidebarState(open) {
  const sidebar = document.getElementById("sidebar");
  const backdrop = document.getElementById("sidebar-backdrop");
  const toggle = document.getElementById("sidebar-toggle");
  if (!sidebar) return;
  sidebar.classList.toggle("open", open);
  document.body.classList.toggle("sidebar-open", open);
  if (backdrop) {
    backdrop.classList.toggle("visible", open);
    backdrop.setAttribute("aria-hidden", open ? "false" : "true");
  }
  if (toggle) toggle.setAttribute("aria-expanded", open ? "true" : "false");
}

function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  if (!sidebar) return;
  setSidebarState(!sidebar.classList.contains("open"));
}

document.addEventListener("DOMContentLoaded", function () {
  const tombol = document.getElementById("sidebar-toggle");
  if (tombol) tombol.addEventListener("click", toggleSidebar);

  const backdrop = document.getElementById("sidebar-backdrop");
  if (backdrop) backdrop.addEventListener("click", function () { setSidebarState(false); });

  const navLinks = document.querySelectorAll(".sidebar-nav .nav-item");
  navLinks.forEach(function (link) {
    link.addEventListener("click", function () {
      if (window.matchMedia("(max-width: 860px)").matches) setSidebarState(false);
    });
  });

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") setSidebarState(false);
  });
});

// Close sidebar when clicking outside on mobile
document.addEventListener("click", function (e) {
  const sidebar = document.getElementById("sidebar");
  if (!sidebar) return;
  const toggle = document.querySelector(".sidebar-toggle");
  if (
    sidebar.classList.contains("open") &&
    !sidebar.contains(e.target) &&
    e.target !== toggle &&
    !(toggle && toggle.contains(e.target))
  ) {
    setSidebarState(false);
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
