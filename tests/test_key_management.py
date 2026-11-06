"""
tests/test_key_management.py
────────────────────────────
Uji hierarki kunci: bundel, pembukaan DEK, bungkus ulang, pemulihan,
kunci per tujuan, dan pemisahan salt autentikasi dari kek_salt.
"""

import base64

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from modules.authentication.password_hash import hash_password
from modules.cryptography.key_management import (
    PURPOSE_LABELS,
    _derive_kek,
    create_key_bundle,
    format_recovery_key,
    purpose_key,
    recover_dek,
    rewrap_dek,
    unlock_dek,
)

PASSWORD = "kata-sandi-uji-123"
USB_SECRET = bytes(range(32))


class TestKeyBundle:
    def test_bundle_shape_without_raw_dek(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=1)
        assert set(bundle) == {
            "user_id", "kek_salt", "wrapped_dek",
            "recovery_wrapped_dek", "recovery_key",
        }
        # DEK polos tidak boleh ada di bundle yang disimpan ke database.
        for value in bundle.values():
            assert not isinstance(value, bytes)

    def test_unlock_roundtrip(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=7)
        dek = unlock_dek(PASSWORD, USB_SECRET, bundle)
        assert isinstance(dek, bytes)
        assert len(dek) == 32

    def test_wrong_password_rejected(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=1)
        with pytest.raises(ValueError):
            unlock_dek("kata-sandi-salah", USB_SECRET, bundle)

    def test_wrong_usb_secret_rejected(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=1)
        with pytest.raises(ValueError):
            unlock_dek(PASSWORD, bytes(reversed(USB_SECRET)), bundle)

    def test_user_id_mismatch_rejected(self):
        """AAD memuat id pengguna: blob tidak dapat dipindahkan ke user lain."""
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=1)
        bundle["user_id"] = 2
        with pytest.raises(ValueError):
            unlock_dek(PASSWORD, USB_SECRET, bundle)

    def test_kek_salt_random_per_bundle(self):
        b1 = create_key_bundle(PASSWORD, USB_SECRET, user_id=1)
        b2 = create_key_bundle(PASSWORD, USB_SECRET, user_id=1)
        assert b1["kek_salt"] != b2["kek_salt"]
        assert b1["wrapped_dek"] != b2["wrapped_dek"]

    def test_usb_secret_must_be_32_bytes(self):
        with pytest.raises(ValueError):
            create_key_bundle(PASSWORD, b"pendek", user_id=1)


class TestRewrap:
    def test_rewrap_preserves_dek(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=3)
        dek_lama = unlock_dek(PASSWORD, USB_SECRET, bundle)
        baru = rewrap_dek(dek_lama, "kata-sandi-baru-456", USB_SECRET, user_id=3)
        dek_baru = unlock_dek("kata-sandi-baru-456", USB_SECRET, baru)
        assert dek_baru == dek_lama

    def test_old_password_fails_after_rewrap(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=3)
        dek = unlock_dek(PASSWORD, USB_SECRET, bundle)
        baru = rewrap_dek(dek, "kata-sandi-baru-456", USB_SECRET, user_id=3)
        with pytest.raises(ValueError):
            unlock_dek(PASSWORD, USB_SECRET, baru)

    def test_wrong_usb_after_rewrap_rejected(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=3)
        dek = unlock_dek(PASSWORD, USB_SECRET, bundle)
        baru = rewrap_dek(dek, "kata-sandi-baru-456", USB_SECRET, user_id=3)
        with pytest.raises(ValueError):
            unlock_dek("kata-sandi-baru-456", bytes(reversed(USB_SECRET)), baru)


class TestRecovery:
    def test_recover_roundtrip(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=2)
        dek = unlock_dek(PASSWORD, USB_SECRET, bundle)
        assert recover_dek(bundle["recovery_key"], bundle) == dek

    def test_recovery_key_display_format(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=2)
        display = bundle["recovery_key"]
        # Base32 berkelompok: kelompok 8 karakter dipisah tanda hubung.
        groups = display.split("-")
        assert all(1 <= len(g) <= 8 for g in groups)
        assert display == display.upper()
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567-")
        assert set(display) <= allowed

    def test_recovery_key_accepts_loose_input(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=2)
        loose = bundle["recovery_key"].replace("-", " ").lower()
        dek = unlock_dek(PASSWORD, USB_SECRET, bundle)
        assert recover_dek(loose, bundle) == dek

    def test_wrong_recovery_key_rejected(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=2)
        with pytest.raises(ValueError):
            recover_dek("AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD-EEEEEEEE-FFFF", bundle)

    def test_recovery_survives_password_change(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=2)
        dek = unlock_dek(PASSWORD, USB_SECRET, bundle)
        baru = rewrap_dek(dek, "kata-sandi-baru-789", USB_SECRET, user_id=2)
        bundle["kek_salt"] = baru["kek_salt"]
        bundle["wrapped_dek"] = baru["wrapped_dek"]
        assert recover_dek(bundle["recovery_key"], bundle) == dek

    def test_recovery_key_not_stored_in_bundle_fields(self):
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=2)
        display = bundle["recovery_key"]
        # Tidak ada field lain yang memuat kunci pemulihan.
        for field in ("kek_salt", "wrapped_dek", "recovery_wrapped_dek"):
            assert display.replace("-", "") not in bundle[field]


class TestPurposeKey:
    def test_32_bytes_and_deterministic(self):
        dek = b"\x11" * 32
        k1 = purpose_key(dek, "file")
        k2 = purpose_key(dek, "file")
        assert len(k1) == 32
        assert k1 == k2

    def test_distinct_per_label(self):
        dek = b"\x22" * 32
        keys = [purpose_key(dek, label) for label in PURPOSE_LABELS]
        assert len(set(keys)) == len(PURPOSE_LABELS)

    def test_unknown_label_rejected(self):
        with pytest.raises(ValueError):
            purpose_key(b"\x33" * 32, "label-tidak-ada")

    def test_raw_bytes_label_allowed(self):
        dek = b"\x44" * 32
        assert len(purpose_key(dek, b"custom-label")) == 32

    def test_wrong_dek_length_rejected(self):
        with pytest.raises(ValueError):
            purpose_key(b"pendek", "file")


class TestAuthSaltSeparation:
    """Butir 1.1g: hash autentikasi tidak pernah dapat dipakai sebagai kunci."""

    def test_kek_salt_differs_from_auth_salt(self):
        _, auth_salt = hash_password(PASSWORD)
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=1)
        assert bundle["kek_salt"] != auth_salt

    def test_auth_salt_cannot_unlock_dek(self):
        """Membentuk KEK dengan salt autentikasi gagal membuka wrapped_dek."""
        _, auth_salt = hash_password(PASSWORD)
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=1)
        salah = dict(bundle)
        salah["kek_salt"] = auth_salt
        with pytest.raises(ValueError):
            unlock_dek(PASSWORD, USB_SECRET, salah)

    def test_password_hash_value_cannot_unlock_dek(self):
        """Nilai hash password (dari kolom password_hash) bukan kunci yang sah."""
        pw_hash, _ = hash_password(PASSWORD)
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=1)
        kek_hash = bytes.fromhex(pw_hash)
        with pytest.raises(Exception):
            AESGCM(kek_hash).decrypt(
                bytes.fromhex(bundle["wrapped_dek"].split(":")[1]),
                bytes.fromhex(bundle["wrapped_dek"].split(":")[2]),
                f"cryptix-kek-v1:{bundle['user_id']}".encode("utf-8"),
            )

    def test_derived_kek_with_auth_salt_differs(self):
        _, auth_salt = hash_password(PASSWORD)
        bundle = create_key_bundle(PASSWORD, USB_SECRET, user_id=1)
        kek_benar = _derive_kek(PASSWORD, bytes.fromhex(bundle["kek_salt"]), USB_SECRET)
        kek_salah = _derive_kek(PASSWORD, bytes.fromhex(auth_salt), USB_SECRET)
        assert kek_benar != kek_salah


class TestRecoveryKeyCodec:
    def test_format_is_reversible(self):
        key = bytes(range(32))
        display = format_recovery_key(key)
        assert "-" in display
        groups = display.split("-")
        assert "".join(groups) == base64.b32encode(key).decode().rstrip("=")

    def test_invalid_format_rejected(self):
        from modules.cryptography.key_management import _parse_recovery_key
        with pytest.raises(ValueError):
            _parse_recovery_key("!!!")
