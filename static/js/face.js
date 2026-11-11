/**
 * static/js/face.js - pendaftaran dan verifikasi wajah.
 *
 * Pendaftaran: 30 frame atau lebih selama sedikitnya 3 detik, lalu dikirim
 * ke /api/register_face beserta duration_ms. Verifikasi tahap 2 login: lima
 * frame dikirim sebagai bukti metode "wajah".
 *
 * Semua pengambilan frame terjadi di memori peramban; tidak ada citra wajah
 * yang disimpan ke server selain templat terenkripsi.
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

  function teksPanel(panel, nama, cadangan) {
    if (panel && panel.dataset && panel.dataset[nama]) {
      return panel.dataset[nama];
    }
    return cadangan;
  }

  function sekarang() {
    return (window.performance && performance.now)
      ? performance.now()
      : Date.now();
  }

  function tidur(ms) {
    return new Promise(function (resolve) {
      window.setTimeout(resolve, ms);
    });
  }

  function tangkap(video, canvas, jumlah, durasiMs, onProgress) {
    return new Promise(function (resolve) {
      const mulai = sekarang();
      const frames = [];
      const timer = window.setInterval(function () {
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
          window.clearInterval(timer);
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

  async function bacaJson(resp) {
    const teks = await resp.text();
    try {
      return JSON.parse(teks);
    } catch (_) {
      return { success: false, error: null };
    }
  }

  async function kirimPendaftaran(hasil, statusEl, grant, panel) {
    const headers = grant ? { "X-Reauth-Grant": grant } : {};
    const resp = await apiFetch("/api/register_face", {
      method: "POST",
      headers: headers,
      body: JSON.stringify(hasil),
    });
    const data = await bacaJson(resp);
    if (!data.success) {
      throw new Error(
        data.error || teksPanel(panel, "msgFailed", "Pendaftaran wajah gagal.")
      );
    }
    setStatus(statusEl, data.message, "#22c55e");
    if (data.setup_done) {
      window.setTimeout(function () {
        window.location.href = "/login";
      }, 800);
    }
    return data;
  }

  function rasioWarnaKulit(video) {
    const luas = 64 * 48;
    const kecil = document.createElement("canvas");
    kecil.width = 64;
    kecil.height = 48;
    const konteks = kecil.getContext("2d", { willReadFrequently: true });
    if (!konteks) {
      return 0;
    }
    konteks.drawImage(video, 0, 0, 64, 48);
    const data = konteks.getImageData(0, 0, 64, 48).data;
    let cocok = 0;
    for (let i = 0; i < data.length; i += 4) {
      const r = data[i];
      const g = data[i + 1];
      const b = data[i + 2];
      const terang = Math.max(r, g, b);
      const gelap = Math.min(r, g, b);
      if (r > 95 && g > 40 && b > 20 && r > g && r > b &&
          terang - gelap > 15) {
        cocok += 1;
      }
    }
    return cocok / luas;
  }

  function mulaiDeteksiLangsung(video, panel) {
    const el = document.getElementById("setup-face-live");
    if (!el) {
      return { berhenti: function () {} };
    }

    let aktif = true;
    let detektor = null;
    if (typeof window.FaceDetector === "function") {
      try {
        detektor = new window.FaceDetector({
          fastMode: true,
          maxDetectedFaces: 2,
        });
      } catch (_) {
        detektor = null;
      }
    }

    async function putaran() {
      while (aktif) {
        await tidur(500);
        if (!aktif) {
          return;
        }
        if (video.readyState < 2 || !video.videoWidth) {
          continue;
        }
        if (detektor) {
          try {
            const wajah = await detektor.detect(video);
            if (wajah.length > 1) {
              el.textContent = teksPanel(panel, "msgMultiple", "");
            } else if (wajah.length === 1) {
              el.textContent = teksPanel(panel, "msgDetected", "");
            } else {
              el.textContent = teksPanel(panel, "msgNotDetected", "");
            }
          } catch (_) {
            el.textContent = teksPanel(panel, "msgDetectOff", "");
          }
        } else {
          // Cadangan tanpa FaceDetector: perkiraan kasar keberadaan wajah
          // dari warna kulit pada bingkai kecil. Server tetap memverifikasi
          // jumlah dan persentase deteksi sebelum menyimpan templat.
          el.textContent = rasioWarnaKulit(video) >= 0.08
            ? teksPanel(panel, "msgDetected", "")
            : teksPanel(panel, "msgNotDetected", "");
        }
      }
    }

    putaran();
    return {
      berhenti: function () {
        aktif = false;
      },
    };
  }

  function perbaruiProgres(panel, jumlah, teks) {
    const bilah = document.getElementById("setup-face-progress");
    const label = document.getElementById("setup-face-progress-text");
    if (bilah) {
      bilah.max = 30;
      bilah.value = Math.min(jumlah, 30);
    }
    if (label) {
      label.textContent = teks || "";
    }
    if (panel) {
      panel.dataset.jumlahFrame = String(jumlah);
    }
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
    const panel = video.closest("[data-msg-preparing]");
    let stream = null;
    let pemantau = null;
    setStatus(statusEl, teksPanel(panel, "msgPreparing", "Menyiapkan kamera..."));
    perbaruiProgres(panel, 0, "");
    try {
      stream = await bukaKamera(video);
      pemantau = mulaiDeteksiLangsung(video, panel);
      const hasil = await tangkap(video, canvas, 30, 3000, function (n) {
        const teks = teksPanel(panel, "msgCapturing", "Mengambil gambar: {n} dari 30")
          .replace("{n}", String(n));
        setStatus(statusEl, teks);
        perbaruiProgres(panel, n, teks);
      });
      if (pemantau) {
        pemantau.berhenti();
        pemantau = null;
      }
      setStatus(statusEl, teksPanel(panel, "msgSending", "Mengirim sampel..."));
      return await kirimPendaftaran(hasil, statusEl, grant, panel);
    } catch (err) {
      const galatKamera = err && (
        err.name === "NotAllowedError" ||
        err.name === "NotFoundError" ||
        err.name === "NotReadableError" ||
        err.name === "SecurityError"
      );
      const pesan = galatKamera
        ? teksPanel(panel, "msgCameraFailed", "Kamera tidak dapat dibuka.")
        : (err && err.message
          ? err.message
          : teksPanel(panel, "msgFailed", "Pendaftaran wajah gagal."));
      setStatus(statusEl, pesan, "#ef4444");
      throw err;
    } finally {
      if (pemantau) {
        pemantau.berhenti();
      }
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

