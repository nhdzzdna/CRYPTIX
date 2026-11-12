/* static/js/ui/dropzone.js - Dropzone berkas dengan nama, ukuran, dan hapus */
(function () {
  "use strict";

  var KX = (window.KX = window.KX || {});

  function ukuran(bytes) {
    if (!bytes && bytes !== 0) return "";
    var satuan = ["B", "KB", "MB", "GB"];
    var nilai = bytes;
    var i = 0;
    while (nilai >= 1024 && i < satuan.length - 1) {
      nilai /= 1024;
      i += 1;
    }
    var angka = i === 0 ? String(nilai) : nilai.toFixed(1);
    return angka + " " + satuan[i];
  }

  function init(root) {
    if (!root || root.dataset.kxDropzoneSiap === "1") return;
    var input = root.querySelector("input[type='file']");
    if (!input) return;
    root.dataset.kxDropzoneSiap = "1";

    var isiAwal = Array.prototype.slice.call(root.children).filter(function (n) {
      return n !== input;
    });
    var panelFile = document.createElement("div");
    panelFile.className = "kx-dropzone-file";
    panelFile.hidden = true;

    var meta = document.createElement("span");
    meta.className = "kx-file-meta";
    var nama = document.createElement("span");
    nama.className = "kx-file-name";
    var besar = document.createElement("span");
    besar.className = "kx-file-size";
    meta.appendChild(nama);
    meta.appendChild(besar);

    var hapus = document.createElement("button");
    hapus.type = "button";
    hapus.className = "kx-btn kx-btn-icon";
    hapus.setAttribute("aria-label", "Hapus berkas terpilih");
    hapus.textContent = "\u00d7";

    panelFile.appendChild(meta);
    panelFile.appendChild(hapus);
    root.appendChild(panelFile);

    function tampilkan() {
      var berkas = input.files && input.files[0];
      if (!berkas) {
        panelFile.hidden = true;
        isiAwal.forEach(function (n) { n.hidden = false; });
        return;
      }
      nama.textContent = berkas.name;
      besar.textContent = ukuran(berkas.size);
      panelFile.hidden = false;
      isiAwal.forEach(function (n) { n.hidden = true; });
    }

    input.addEventListener("change", tampilkan);

    hapus.addEventListener("click", function (e) {
      if (e) {
        e.preventDefault();
        e.stopPropagation();
      }
      input.value = "";
      tampilkan();
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });

    var form = input.form || root.closest("form");
    if (form) {
      form.addEventListener("reset", function () {
        setTimeout(tampilkan, 0);
      });
    }

    ["dragenter", "dragover"].forEach(function (ev) {
      root.addEventListener(ev, function (e) {
        e.preventDefault();
        root.classList.add("is-drag");
      });
    });
    ["dragleave", "dragend", "drop"].forEach(function (ev) {
      root.addEventListener(ev, function (e) {
        e.preventDefault();
        root.classList.remove("is-drag");
      });
    });
    root.addEventListener("drop", function (e) {
      if (!e.dataTransfer || !e.dataTransfer.files || !e.dataTransfer.files.length) return;
      try {
        input.files = e.dataTransfer.files;
      } catch (_err) {
        return;
      }
      tampilkan();
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });

    root.addEventListener("click", function (e) {
      if (e.target.closest("button") || e.target === input) return;
      input.click();
    });

    tampilkan();
  }

  function initSemua() {
    document.querySelectorAll("[data-kx-dropzone]").forEach(init);
  }

  KX.dropzone = { init: init, initSemua: initSemua, ukuran: ukuran };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initSemua);
  } else {
    initSemua();
  }
})();
