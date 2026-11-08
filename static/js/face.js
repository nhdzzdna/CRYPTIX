/**
 * static/js/face.js — pendaftaran dan verifikasi wajah (butir 2.6).
 *
 * Pendaftaran: 30 frame atau lebih selama sedikitnya 3 detik, lalu dikirim
 * ke /api/register_face beserta duration_ms. Verifikasi tahap 2 login: lima
 * frame dikirim sebagai bukti metode "wajah" ke /login/biometric.
 *
 * Semua pengambilan frame terjadi di memori peramban; tidak ada citra wajah
 * yang disimpan ke server selain template terenkripsi.
 */
"use strict";

window.CryptixBiometrik = window.CryptixBiometrik || { penangan: {} };

(function () {
  function setStatus(el, pesan, warna) {
    if (!el) {
      return;
    }
    el.textContent = pesan;
    el.style.color = warna || "";
  }

  function sekarang() {
    return (window.performance && performance.now)
      ? performance.now()
      : Date.now();
  }

  function tangkap(video, canvas, jumlah, durasiMs, onProgress) {
    return new Promise(function (resolve) {
      const mulai = sekarang();
      const frames = [];
      const timer = setInterval(function () {
        if (!video.videoWidth) {
          return;
        }
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        canvas.getContext("2d").drawImage(video, 0, 0);
        frames.push(canvas.toDataURL("image/jpeg", 0.85));
        const berlalu = sekarang() - mulai;
        if (onProgress) {
          onProgress(frames.length, berlalu);
        }
        if (frames.length >= jumlah && berlalu >= durasiMs) {
          clearInterval(timer);
          resolve({
            frames: frames,
            duration_ms: Math.round(berlalu),
          });
        }
      }, 100);
    });
  }

  async function bukaKamera(video) {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    video.srcObject = stream;
    video.style.display = "block";
    await video.play().catch(function () {});
    return stream;
  }

  async function kirimPendaftaran(hasil, statusEl, grant) {
    const headers = grant ? { "X-Reauth-Grant": grant } : undefined;
    const resp = await apiFetch("/api/register_face", {
      method: "POST",
      headers: headers,
      body: JSON.stringify(hasil),
    });
    const data = await resp.json();
    if (!data.success) {
      throw new Error(data.error || "Pendaftaran wajah gagal.");
    }
    setStatus(statusEl, "\u2705 " + data.message, "#22c55e");
    if (data.setup_done) {
      setTimeout(function () {
        window.location.href = "/login";
      }, 800);
    }
    return data;
  }

  async function daftar(videoId, canvasId, statusId, opsiOpsional) {
    const opsiTambahan = opsiOpsional || {};
    const grant = typeof opsiTambahan.grant === "string" ? opsiTambahan.grant : "";
    const video = document.getElementById(videoId);
    const canvas = document.getElementById(canvasId);
    const statusEl = document.getElementById(statusId);
    if (!video || !canvas) {
      throw new Error("Elemen kamera tidak ditemukan.");
    }
    setStatus(statusEl, "Menyiapkan kamera\u2026");
    let stream = null;
    try {
      stream = await bukaKamera(video);
      const hasil = await tangkap(video, canvas, 30, 3000, function (n) {
        setStatus(statusEl, "Sampel: " + n + "/30");
      });
      setStatus(statusEl, "Mengirim sampel\u2026");
      return await kirimPendaftaran(hasil, statusEl, grant);
    } catch (err) {
      setStatus(statusEl, "\u274c " + (err.message || "Pendaftaran wajah gagal."),
        "#ef4444");
      throw err;
    } finally {
      if (stream) {
        stream.getTracks().forEach(function (t) { t.stop(); });
      }
      video.style.display = "none";
    }
  }

  window.CryptixFace = { daftar: daftar, tangkap: tangkap };

  // Penangan tahap 2 login: lima frame base64 sebagai bukti metode "wajah".
  window.CryptixBiometrik.penangan.wajah = async function () {
    const video = document.createElement("video");
    video.setAttribute("playsinline", "");
    const canvas = document.createElement("canvas");
    let stream = null;
    try {
      stream = await bukaKamera(video);
      const hasil = await tangkap(video, canvas, 5, 0);
      return hasil.frames;
    } finally {
      if (stream) {
        stream.getTracks().forEach(function (t) { t.stop(); });
      }
    }
  };
})();
