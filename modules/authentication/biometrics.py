"""
modules/authentication/biometrics.py
────────────────────────────────────
Registry metode biometrik untuk tahap 2 login dua tahap (butir 2.4b).

Alur:
  • Tiap metode mendaftarkan diri lewat tambah_metode() dengan dua
    pemeriksaan: ``terdaftar(user_id)`` — apakah pengguna sudah punya
    metode ini, dan ``verifikasi(user_id, bukti)`` — apakah bukti yang
    dikirim cocok.
  • Tahap 2 memverifikasi satu metode yang dipilih pengguna. Metode
    pilihan harus terdaftar pada akun; satu metode yang lulus sudah
    cukup dan tidak ada metode yang boleh dilewati.
  • Tanpa metode terdaftar verifikasi selalu gagal: tidak ada bypass
    biometrik, termasuk pada CRYPTIX_DEV_MODE.

Metode baru (mis. WebAuthn atau pengenalan wajah) cukup memanggil
tambah_metode() saat modulnya dimuat; daftar metode dapat diperluas
tanpa mengubah berkas ini.
"""

from __future__ import annotations

import config
from modules.strings import MSG

# nama → {"label", "terdaftar", "verifikasi"}
_METODE: dict[str, dict] = {}


def tambah_metode(nama: str, label: str, terdaftar, verifikasi) -> None:
    """
    Daftarkan sebuah metode biometrik.

    Parameters
    ----------
    nama      : str  Kunci pendek (mis. "webauthn") dipakai pada bukti.
    label     : str  Nama tampilan untuk pengguna.
    terdaftar : callable(user_id) -> bool  True bila pengguna punya metode ini.
    verifikasi: callable(user_id, bukti) -> bool  True bila bukti sah.
    """
    if not nama or not callable(terdaftar) or not callable(verifikasi):
        raise ValueError("Metode biometrik tidak valid.")
    _METODE[nama] = {
        "label": label,
        "terdaftar": terdaftar,
        "verifikasi": verifikasi,
    }


def hapus_metode(nama: str) -> None:
    """Cabut pendaftaran sebuah metode (dipakai pengujian)."""
    _METODE.pop(nama, None)


def metode_biometrik_terdaftar(user_id: int) -> list[str]:
    """
    Nama metode yang terdaftar bagi ``user_id``, urut abjad.

    Inilah daftar yang wajib lulus pada tahap 2 menurut BIOMETRIC_POLICY.
    """
    return sorted(
        nama for nama, metode in _METODE.items()
        if metode["terdaftar"](user_id)
    )


def metode_untuk_pengguna(user_id: int) -> list[dict]:
    """Daftar metode terdaftar untuk ditampilkan pada halaman login."""
    return [
        {"nama": nama, "label": _METODE[nama]["label"]}
        for nama in metode_biometrik_terdaftar(user_id)
    ]


def verifikasi_metode_biometrik(
    user_id: int, nama: str, bukti, konteks: dict | None = None
) -> dict:
    """
    Verifikasi satu metode biometrik yang dipilih pengguna.

    Mengembalikan dict dengan kunci ``success`` dan, bila gagal, ``error``
    serta ``code`` opsional. Metode yang tidak terdaftar pada akun ditolak
    sebelum bukti diperiksa. ``konteks`` diteruskan sebagai argumen kata
    kunci (mis. ``dek`` untuk metode wajah).
    """
    terdaftar = metode_biometrik_terdaftar(user_id)
    if not terdaftar:
        return {"success": False, "error": MSG.LOGIN_BIOMETRIC_NONE}
    if nama not in terdaftar:
        return {
            "success": False,
            "error": MSG.LOGIN_BIOMETRIC_METHOD_INVALID,
            "code": "metode_tidak_terdaftar",
        }

    isi = bukti.get(nama) if isinstance(bukti, dict) else None
    if isi is None:
        return {"success": False, "error": MSG.LOGIN_BIOMETRIC_FAILED}

    fungsi = _METODE[nama]["verifikasi"]
    try:
        try:
            hasil = fungsi(user_id, isi, **(konteks or {}))
        except TypeError:
            hasil = fungsi(user_id, isi)
    except Exception:
        return {"success": False, "error": MSG.LOGIN_BIOMETRIC_FAILED}

    if isinstance(hasil, dict):
        if hasil.get("success"):
            return {"success": True}
        keluaran = {
            "success": False,
            "error": hasil.get("error") or MSG.LOGIN_BIOMETRIC_FAILED,
        }
        if hasil.get("code"):
            keluaran["code"] = hasil["code"]
        return keluaran
    if hasil:
        return {"success": True}
    return {"success": False, "error": MSG.LOGIN_BIOMETRIC_FAILED}


# DEPRECATED: diganti verifikasi_metode_biometrik() pada UC1. Dipertahankan
# sementara untuk pengujian unit registry sampai T8/T11 menghapusnya.
def verifikasi_tahap_biometrik(user_id: int, bukti, konteks: dict | None = None) -> dict[str, bool]:
    """
    Verifikasi tiap metode terdaftar terhadap bukti yang dikirim.

    ``konteks`` diteruskan sebagai argumen kata kunci (mis. ``dek`` untuk
    metode wajah). Metode terdaftar tanpa bukti bernilai False sehingga tidak
    dapat dilewati; kesalahan pada sebuah metode juga dihitung False.
    """
    konteks = konteks or {}
    hasil: dict[str, bool] = {}
    if not isinstance(bukti, dict):
        bukti = {}
    for nama in metode_biometrik_terdaftar(user_id):
        isi = bukti.get(nama)
        if isi is None:
            hasil[nama] = False
            continue
        fungsi = _METODE[nama]["verifikasi"]
        try:
            try:
                hasil[nama] = bool(fungsi(user_id, isi, **konteks))
            except TypeError:
                hasil[nama] = bool(fungsi(user_id, isi))
        except Exception:
            hasil[nama] = False
    return hasil


# DEPRECATED: kebijakan "all_enrolled"/"any" diganti pilihan satu metode pada
# UC1. Dipertahankan sementara sampai T8/T11 menghapusnya.
def kebijakan_dipenuhi(hasil: dict[str, bool]) -> bool:
    """
    Terapkan BIOMETRIC_POLICY terhadap hasil verifikasi tahap 2.

    Kebijakan yang tidak dikenal diperlakukan seperti "all_enrolled".
    Hasil kosong (tidak ada metode terdaftar) selalu gagal.
    """
    if not hasil:
        return False
    if config.BIOMETRIC_POLICY == "any":
        return any(hasil.values())
    return all(hasil.values())
