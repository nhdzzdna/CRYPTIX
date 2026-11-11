"""
tests/test_super_encryption_stages.py
──────────────────────────────────────
Uji struktur jejak tahapan Super Encryption, batas tampilan, dan
ketiadaan kunci/passphrase pada data tahapan.
"""

import json

import pytest

import modules.cryptography.super_encryption as se
from modules.cryptography.super_encryption import super_encrypt_stages

PASSPHRASE = "frasa-uji-tahapan-42"


@pytest.fixture(scope="module")
def detail():
    return super_encrypt_stages("Halo Dunia", passphrase=PASSPHRASE)


def _stages(detail):
    return {stage["kode"]: stage for stage in detail["stages"]}


class TestStageStructure:
    def test_final_and_stage_order(self, detail):
        assert detail["final"].startswith("CXSE2.")
        assert [s["kode"] for s in detail["stages"]] == [
            "vigenere", "playfair", "chacha20", "blowfish", "final",
        ]

    def test_every_stage_has_required_fields(self, detail):
        for stage in detail["stages"]:
            for key in (
                "nama", "kode", "jenis", "input", "output", "keterangan",
                "jejak", "jejak_total", "jejak_ditampilkan",
                "jejak_dipotong", "catatan",
            ):
                assert key in stage, f"{stage['kode']} tidak memiliki {key}"

    def test_layer_labels(self, detail):
        names = [s["nama"] for s in detail["stages"]]
        assert "Layer 1 — Vigenere" in names
        assert "Layer 2 — Playfair" in names
        assert "Layer 3 — ChaCha20" in names
        assert "Layer 4 — Blowfish-CBC" in names

    def test_vigenere_trace_per_character(self, detail):
        stage = _stages(detail)["vigenere"]
        assert stage["jenis"] == "vigenere"
        assert stage["jejak"]
        baris = stage["jejak"][0]
        assert set(baris) == {"asal", "kunci", "hasil"}
        assert baris["asal"] == "H"
        assert baris["hasil"] == stage["output"][0]
        # Kunci layer tidak boleh tampil sebagai huruf kunci sebenarnya.
        assert all(row["kunci"] in ("", "***") for row in stage["jejak"])

    def test_playfair_trace_per_pair_with_rule(self, detail):
        stage = _stages(detail)["playfair"]
        assert stage["jenis"] == "playfair"
        assert stage["jejak"]
        baris = stage["jejak"][0]
        assert set(baris) == {"pasangan_asal", "pasangan_hasil", "aturan"}
        assert len(baris["pasangan_asal"]) == 2
        assert len(baris["pasangan_hasil"]) == 2
        assert baris["aturan"] in {"baris sama", "kolom sama", "persegi"}

    def test_modern_trace_per_byte_with_safe_parameters(self, detail):
        stages = _stages(detail)
        for kode in ("chacha20", "blowfish"):
            stage = stages[kode]
            assert stage["jenis"] == "modern"
            assert stage["jejak"]
            baris = stage["jejak"][0]
            assert set(baris) == {"sebelum", "sesudah"}
            assert len(baris["sebelum"]) == 2
            assert len(baris["sesudah"]) == 2
            label = " ".join(p["label"].lower() for p in stage["parameter"])
            assert "mode" in label
            assert "padding" in label
            assert "nonce" in label or "iv" in label
            assert "per huruf tidak bermakna" in stage["keterangan"]

    def test_final_stage_has_no_trace(self, detail):
        stage = _stages(detail)["final"]
        assert stage["jenis"] == "final"
        assert stage["jejak"] == []
        assert stage["output"] == detail["final"]


class TestTraceLimits:
    def test_long_text_limits_each_layer(self):
        detail = super_encrypt_stages("A" * 300, passphrase=PASSPHRASE)
        stages = _stages(detail)

        vigenere = stages["vigenere"]
        assert len(vigenere["jejak"]) == 200
        assert vigenere["jejak_dipotong"] is True
        assert "ditampilkan 200 pertama" in vigenere["catatan"]

        playfair = stages["playfair"]
        assert len(playfair["jejak"]) == 100
        assert playfair["jejak_dipotong"] is True
        assert "ditampilkan 100 pasangan pertama" in playfair["catatan"]

        for kode in ("chacha20", "blowfish"):
            stage = stages[kode]
            assert len(stage["jejak"]) == 64
            assert stage["jejak_dipotong"] is True
            assert "ditampilkan 64 byte pertama" in stage["catatan"]

    def test_short_text_not_truncated(self):
        detail = super_encrypt_stages("Hi", passphrase=PASSPHRASE)
        for stage in detail["stages"]:
            assert stage["jejak_dipotong"] is False
            assert stage["catatan"] == ""


class TestNoSecretMaterial:
    def test_passphrase_absent_from_stage_data(self, detail):
        dumped = json.dumps(detail, ensure_ascii=False)
        assert PASSPHRASE not in dumped

    def test_derived_keys_absent_with_fixed_salt(self, monkeypatch):
        salt = b"\x02" * 16
        monkeypatch.setattr(se.os, "urandom", lambda n: b"\x02" * n)
        detail = se.super_encrypt_stages("Rahasia", passphrase=PASSPHRASE)
        keys = se._message_keys(
            se._base_keys(None, PASSPHRASE, salt), salt
        )
        dumped = json.dumps(detail, ensure_ascii=False)
        for value in keys.values():
            if isinstance(value, str):
                assert value not in dumped
            else:
                assert value.hex() not in dumped
