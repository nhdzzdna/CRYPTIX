"""
tests/test_encrypted_storage.py
────────────────────────────────
Uji integrasi rute penyimpanan: kolom nonce/tag palsu hilang, nama berkas serta
isi catatan/kredensial terenkripsi, berkas per chunk terverifikasi setelah
dekripsi, dan pemodifan tercatat sebagai blok TAMPER_DETECTED.
"""

import hashlib
import io
import os
import re
import tempfile

import pytest
from PIL import Image

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth

from modules.blockchain.blockchain import account_hash, content_hash

from modules.cryptography import session_keys
from modules.cryptography.database_encryption import decrypt_record
from modules.cryptography.key_management import purpose_key
from modules.cryptography.super_encryption import super_decrypt

MASTER_HEX = hashlib.sha256(b"kunci-sesi-uji").hexdigest()
KATA_SANDI = "kata-sandi-uji-tersimpan"
JUDUL = "Judul Catatan Rahasia"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "uji.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted_files"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego_images"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary_files"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pengujingsatu"), (2, "pengujingdua")):
            db.execute(
                """INSERT OR IGNORE INTO users
                   (id, username, email, password_hash, salt) VALUES (?,?,?,?,?)""",
                (uid, nama, f"{nama}@contoh.test", "hash-tidak-dipakai", "garam"),
            )
        db.commit()

    application = create_app()
    application.config["TESTING"] = True
    reauth.clear()
    return application


@pytest.fixture()
def client(app):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "pengujingsatu"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, bytes.fromhex(MASTER_HEX))
    return c


def _csrf(client, halaman: str) -> str:
    """Ambil token CSRF dari halaman; sekaligus membuktikan halaman terbuka."""
    page = client.get(halaman)
    assert page.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True))
    assert match, "token CSRF tidak ditemukan"
    return match.group(1)


def _kolom(tabel: str) -> set[str]:
    with get_db() as db:
        return {baris["name"] for baris in db.execute(f"PRAGMA table_info({tabel})")}


def _blok() -> list[str]:
    with get_db() as db:
        return [
            b["action"]
            for b in db.execute("SELECT action FROM blockchain_log ORDER BY block_index")
        ]


class TestSkema:
    @pytest.mark.parametrize("tabel", ["account_vault", "secure_notes", "vault_files"])
    def test_kolom_nonce_tag_palsu_sudah_dihapus(self, app, tabel):
        kolom = _kolom(tabel)
        assert "nonce" not in kolom
        assert "tag" not in kolom

    def test_vault_files_menyimpan_dua_hash(self, app):
        assert {"sha256_hash", "sha256_ciphertext"} <= _kolom("vault_files")


class TestSecureNotes:
    def test_catatan_tersimpan_terenkripsi(self, client):
        token = _csrf(client, "/secure-notes")
        resp = client.post("/secure-notes/add", data={
            "csrf_token": token, "title": JUDUL, "content": f"Isi {KATA_SANDI}",
        })
        assert resp.status_code == 302

        with get_db() as db:
            row = db.execute("SELECT * FROM secure_notes WHERE user_id=1").fetchone()
        assert row["title_enc"].startswith("v1:")
        assert JUDUL not in row["title_enc"]
        assert KATA_SANDI not in row["content_enc"]

    def test_daftar_hanya_menampilkan_judul(self, client):
        token = _csrf(client, "/secure-notes")
        client.post("/secure-notes/add", data={
            "csrf_token": token, "title": "Catatan Terlihat", "content": "Isi terlihat",
        })
        body = client.get("/secure-notes").get_data(as_text=True)
        assert "Catatan Terlihat" in body
        assert "Isi terlihat" not in body

    def test_catatan_dipindah_ke_pengguna_lain_tidak_terbaca(self, client):
        token = _csrf(client, "/secure-notes")
        client.post("/secure-notes/add", data={
            "csrf_token": token, "title": JUDUL, "content": "Isi pindah pengguna",
        })
        with get_db() as db:
            db.execute("UPDATE secure_notes SET user_id=2 WHERE user_id=1")
            db.commit()

        milik_satu = client.get("/secure-notes").get_data(as_text=True)
        assert JUDUL not in milik_satu

        with client.session_transaction() as sess:
            sess["user_id"] = 2
        milik_dua = client.get("/secure-notes").get_data(as_text=True)
        assert JUDUL not in milik_dua
        assert "[Error]" in milik_dua

    def test_tanpa_csrf_ditolak(self, client):
        resp = client.post("/secure-notes/add", data={"title": "x", "content": "y"})
        assert resp.status_code == 400


class TestAccountVault:
    def test_kredensial_terenkripsi_dan_terbaca_kembali(self, client):
        token = _csrf(client, "/account-vault")
        resp = client.post("/account-vault/add", data={
            "csrf_token": token,
            "site_name": "Situs Uji Kredensial",
            "username": "pengguna-rahasia",
            "password": KATA_SANDI,
            "url": "https://contoh.test",
            "notes": "catatan akun",
        })
        assert resp.status_code == 302

        with get_db() as db:
            row = db.execute("SELECT * FROM account_vault WHERE user_id=1").fetchone()
        assert row["password_enc"].startswith("v1:")
        assert KATA_SANDI not in row["password_enc"]
        assert "pengguna-rahasia" not in row["username_enc"]

        body = client.get("/account-vault").get_data(as_text=True)
        assert "Situs Uji Kredensial" in body
        assert "pe***" in body
        assert "pengguna-rahasia" not in body
        assert KATA_SANDI not in body


def _unggah(client, nama: str, isi: bytes):
    token = _csrf(client, "/vault")
    return client.post("/vault/upload", data={
        "csrf_token": token,
        "file": (io.BytesIO(isi), nama),
    }, content_type="multipart/form-data")


def _unduh(client, file_id: int):
    token = _csrf(client, "/vault")
    grant = _token_grant(client, "file.download", file_id)
    return client.post(
        f"/vault/decrypt/{file_id}",
        data={"csrf_token": token, "reauth_grant": grant},
    )


class TestVaultFiles:
    @pytest.fixture()
    def unggahan(self, client):
        isi = b"isi dokumen uji terenkripsi " * 40
        resp = _unggah(client, "laporan-rahasia.pdf", isi)
        assert resp.status_code == 302
        with get_db() as db:
            row = db.execute("SELECT * FROM vault_files WHERE user_id=1").fetchone()
        return dict(row), isi

    def test_nama_simpan_acak_dan_nama_asli_terenkripsi(self, unggahan):
        row, isi = unggahan
        assert re.fullmatch(r"[0-9a-f]{32}\.bin", row["stored_name"])
        assert ".pdf" not in row["stored_name"]
        assert row["original_name"].startswith("v1:")
        assert "laporan-rahasia.pdf" not in row["original_name"]
        assert row["file_type"] == "document"
        assert row["file_size"] == len(isi)

    def test_dua_hash_disimpan_dan_sesuai_kenyataan(self, unggahan):
        row, isi = unggahan
        with open(f"{config.ENCRYPTED_FILES_DIR}/{row['stored_name']}", "rb") as f:
            blob = f.read()
        assert blob[:8] == b"CRYPTIX1"
        assert row["sha256_hash"] == hashlib.sha256(isi).hexdigest()
        assert row["sha256_ciphertext"] == hashlib.sha256(blob).hexdigest()

    def test_daftar_menampilkan_nama_asli(self, unggahan, client):
        body = client.get("/vault").get_data(as_text=True)
        assert "laporan-rahasia.pdf" in body
        assert "v1:" not in body

    def test_dokumen_terlihat_di_daftar_dokumen(self, unggahan, client):
        body = client.get("/documents").get_data(as_text=True)
        assert "laporan-rahasia.pdf" in body

    def test_unduhan_mengembalikan_plaintext_asli(self, unggahan, client):
        row, isi = unggahan
        resp = _unduh(client, row["id"])
        assert resp.status_code == 200
        assert resp.data == isi
        assert "laporan-rahasia.pdf" in resp.headers.get("Content-Disposition", "")

    def test_pemodifan_isi_berkas_dicatat_sebagai_tamper(self, unggahan, client):
        row, _isi = unggahan
        path = f"{config.ENCRYPTED_FILES_DIR}/{row['stored_name']}"
        with open(path, "rb") as f:
            blob = bytearray(f.read())
        blob[50] ^= 0xFF
        with open(path, "wb") as f:
            f.write(bytes(blob))

        resp = _unduh(client, row["id"])
        assert resp.status_code == 302
        assert "TAMPER_DETECTED" in _blok()

    def test_hash_plaintext_beda_dicatat_sebagai_tamper(self, unggahan, client):
        row, _isi = unggahan
        with get_db() as db:
            db.execute(
                "UPDATE vault_files SET sha256_hash=? WHERE id=?",
                ("0" * 64, row["id"]),
            )
            db.commit()

        resp = _unduh(client, row["id"])
        assert resp.status_code == 302
        assert "TAMPER_DETECTED" in _blok()


class TestStegoOriginalName:
    @pytest.fixture()
    def gambar(self, tmp_path):
        img = Image.new("RGB", (160, 160), color=(12, 90, 200))
        jalur = tmp_path / "gambar-pribadi.png"
        img.save(jalur, format="PNG")
        return jalur

    def test_nama_gambar_terenkripsi_dan_terbuka_kembali(self, client, gambar):
        token = _csrf(client, "/steganography")
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(gambar.read_bytes()), "gambar-pribadi.png"),
            "message": "pesan tersembunyi",
        }, content_type="multipart/form-data")
        assert resp.status_code == 302

        with get_db() as db:
            row = db.execute("SELECT * FROM stego_images WHERE user_id=1").fetchone()
        assert row["original_name"].startswith("v1:")
        assert "gambar-pribadi.png" not in row["original_name"]

        body = client.get("/steganography").get_data(as_text=True)
        assert "gambar-pribadi.png" in body

        with client.session_transaction() as sess:
            sid = sess["session_id"]
        grant = reauth.issue_grant(sid, "stego.download", row["id"])["token"]
        unduhan = client.get(
            f"/steganography/download/{row['id']}",
            headers={"X-Reauth-Grant": grant},
        )
        assert unduhan.status_code == 200
        assert "gambar-pribadi.png" in unduhan.headers.get("Content-Disposition", "")


def _token_grant(client, scope: str, resource_id: int) -> str:
    with client.session_transaction() as sess:
        sid = sess["session_id"]
    return reauth.issue_grant(sid, scope, resource_id)["token"]


def _client_pengguna(app, user_id: int, username: str):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = username
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, bytes.fromhex(MASTER_HEX))
    return c


def _tambah_kredensial(client, site="Situs Rahasia", username="rahasia-pengguna",
                       password=KATA_SANDI) -> dict:
    token = _csrf(client, "/account-vault")
    resp = client.post("/account-vault/add", data={
        "csrf_token": token,
        "site_name": site,
        "username": username,
        "password": password,
        "url": "https://rahasia.test",
        "notes": "catatan rahasia",
    })
    assert resp.status_code == 302
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM account_vault WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (1,),
        ).fetchone()
    return dict(row)


def _baris_kredensial(entry_id: int) -> dict | None:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM account_vault WHERE id=?", (entry_id,)
        ).fetchone()
    return dict(row) if row else None


class TestAccountVaultSesiI:
    def test_reveal_tanpa_grant_ditolak(self, client):
        baris = _tambah_kredensial(client)
        token = _csrf(client, "/account-vault")
        resp = client.post(
            f"/account-vault/reveal/{baris['id']}",
            headers={"X-CSRFToken": token},
        )
        assert resp.status_code == 401
        assert resp.get_json()["success"] is False
        assert resp.get_json()["reason"] == "missing"
        assert "REVEAL" not in _blok()

    def test_reveal_dengan_grant_mengembalikan_json_dan_mencatat_blok(self, client):
        baris = _tambah_kredensial(client)
        grant = _token_grant(client, "account.reveal", baris["id"])
        token = _csrf(client, "/account-vault")
        resp = client.post(
            f"/account-vault/reveal/{baris['id']}",
            headers={"X-CSRFToken": token, "X-Reauth-Grant": grant},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["username"] == "rahasia-pengguna"
        assert data["password"] == KATA_SANDI

        with get_db() as db:
            blok = db.execute(
                "SELECT * FROM blockchain_log WHERE action='REVEAL' "
                "AND asset_ref=?",
                (f"cred:{baris['id']}",),
            ).fetchall()
        assert len(blok) == 1
        assert blok[0]["asset_hash"] == account_hash(
            baris["site_name_enc"], baris["username_enc"], baris["password_enc"]
        )

    def test_reveal_scope_salah_ditolak(self, client):
        baris = _tambah_kredensial(client)
        grant = _token_grant(client, "item.delete", baris["id"])
        token = _csrf(client, "/account-vault")
        resp = client.post(
            f"/account-vault/reveal/{baris['id']}",
            headers={"X-CSRFToken": token, "X-Reauth-Grant": grant},
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "scope"

    def test_reveal_resource_lain_ditolak(self, client):
        baris = _tambah_kredensial(client)
        grant = _token_grant(client, "account.reveal", baris["id"] + 99)
        token = _csrf(client, "/account-vault")
        resp = client.post(
            f"/account-vault/reveal/{baris['id']}",
            headers={"X-CSRFToken": token, "X-Reauth-Grant": grant},
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "resource"

    def test_reveal_idor_pengguna_lain(self, app, client):
        baris = _tambah_kredensial(client)
        lain = _client_pengguna(app, 2, "pengujingdua")
        grant = _token_grant(lain, "account.reveal", baris["id"])
        token = _csrf(lain, "/account-vault")
        resp = lain.post(
            f"/account-vault/reveal/{baris['id']}",
            headers={"X-CSRFToken": token, "X-Reauth-Grant": grant},
        )
        assert resp.status_code == 404
        assert "REVEAL" not in _blok()

    def test_edit_memerlukan_grant_dan_mencatat_modify(self, client):
        baris = _tambah_kredensial(client)
        token = _csrf(client, "/account-vault")
        tanpa_grant = client.post(
            f"/account-vault/edit/{baris['id']}",
            data={"csrf_token": token, "site_name": "Situs Baru",
                  "username": "pengguna-baru", "password": "sandi-baru"},
        )
        assert tanpa_grant.status_code == 401
        assert _baris_kredensial(baris["id"]) == baris

        grant = _token_grant(client, "account.reveal", baris["id"])
        resp = client.post(
            f"/account-vault/edit/{baris['id']}",
            data={
                "csrf_token": token,
                "reauth_grant": grant,
                "site_name": "Situs Baru",
                "username": "pengguna-baru",
                "password": "sandi-baru",
                "url": "https://baru.test",
                "notes": "catatan baru",
            },
        )
        assert resp.status_code == 302

        baru = _baris_kredensial(baris["id"])
        assert baru["site_name_enc"] != baris["site_name_enc"]
        assert "pengguna-baru" not in baru["username_enc"]
        assert "sandi-baru" not in baru["password_enc"]
        with get_db() as db:
            blok = db.execute(
                "SELECT * FROM blockchain_log WHERE action='MODIFY' "
                "AND asset_ref=?",
                (f"cred:{baris['id']}",),
            ).fetchall()
        assert len(blok) == 1
        assert blok[0]["asset_hash"] == account_hash(
            baru["site_name_enc"], baru["username_enc"], baru["password_enc"]
        )

    def test_edit_idor_pengguna_lain(self, app, client):
        baris = _tambah_kredensial(client)
        lain = _client_pengguna(app, 2, "pengujingdua")
        grant = _token_grant(lain, "account.reveal", baris["id"])
        token = _csrf(lain, "/account-vault")
        resp = lain.post(
            f"/account-vault/edit/{baris['id']}",
            data={
                "csrf_token": token,
                "reauth_grant": grant,
                "site_name": "Dibajak",
                "username": "penyusup",
                "password": "sandi-penyusup",
            },
        )
        assert resp.status_code == 404
        assert _baris_kredensial(baris["id"]) == baris

    def test_hapus_memerlukan_item_delete(self, client):
        baris = _tambah_kredensial(client)
        token = _csrf(client, "/account-vault")
        tanpa_grant = client.post(
            f"/account-vault/delete/{baris['id']}",
            data={"csrf_token": token},
        )
        assert tanpa_grant.status_code == 401
        assert _baris_kredensial(baris["id"]) is not None

        grant = _token_grant(client, "item.delete", baris["id"])
        resp = client.post(
            f"/account-vault/delete/{baris['id']}",
            data={"csrf_token": token, "reauth_grant": grant},
        )
        assert resp.status_code == 302
        assert _baris_kredensial(baris["id"]) is None
        with get_db() as db:
            blok = db.execute(
                "SELECT * FROM blockchain_log WHERE action='DELETE' "
                "AND asset_ref=?",
                (f"cred:{baris['id']}",),
            ).fetchall()
        assert len(blok) == 1

    def test_hapus_idor_pengguna_lain(self, app, client):
        baris = _tambah_kredensial(client)
        lain = _client_pengguna(app, 2, "pengujingdua")
        grant = _token_grant(lain, "item.delete", baris["id"])
        token = _csrf(lain, "/account-vault")
        resp = lain.post(
            f"/account-vault/delete/{baris['id']}",
            data={"csrf_token": token, "reauth_grant": grant},
        )
        assert resp.status_code == 404
        assert _baris_kredensial(baris["id"]) is not None


def _tambah_catatan(client, judul="Judul Catatan Uji",
                    isi="Isi catatan sangat rahasia") -> dict:
    token = _csrf(client, "/secure-notes")
    resp = client.post("/secure-notes/add", data={
        "csrf_token": token, "title": judul, "content": isi,
    })
    assert resp.status_code == 302
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM secure_notes WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (1,),
        ).fetchone()
    return dict(row)


def _baris_catatan(note_id: int) -> dict | None:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM secure_notes WHERE id=?", (note_id,)
        ).fetchone()
    return dict(row) if row else None


class TestSecureNotesSesiI:
    def test_isi_terenkripsi_ganda(self, client):
        isi = "Isi ganda yang sangat rahasia"
        baris = _tambah_catatan(client, isi=isi)
        assert baris["content_enc"].startswith("v1:")
        assert isi not in baris["content_enc"]

        dek = bytes.fromhex(MASTER_HEX)
        lapisan_field = decrypt_record(
            {"content_enc": baris["content_enc"]},
            purpose_key(dek, "database"), 1, "secure_notes",
        )["content_enc"]
        assert lapisan_field.startswith("CXSE2.")
        assert isi not in lapisan_field
        assert super_decrypt(lapisan_field, master_key=dek) == isi

    def test_open_tanpa_grant_ditolak(self, client):
        baris = _tambah_catatan(client)
        token = _csrf(client, "/secure-notes")
        resp = client.post(
            f"/secure-notes/open/{baris['id']}",
            headers={"X-CSRFToken": token},
        )
        assert resp.status_code == 401
        assert resp.get_json()["success"] is False
        assert resp.get_json()["reason"] == "missing"

    def test_open_dengan_grant_mengembalikan_isi(self, client):
        isi = "Isi yang hanya terbuka dengan grant"
        baris = _tambah_catatan(client, isi=isi)
        grant = _token_grant(client, "note.open", baris["id"])
        token = _csrf(client, "/secure-notes")
        resp = client.post(
            f"/secure-notes/open/{baris['id']}",
            headers={"X-CSRFToken": token, "X-Reauth-Grant": grant},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["content"] == isi

    def test_open_scope_salah_ditolak(self, client):
        baris = _tambah_catatan(client)
        grant = _token_grant(client, "note.edit", baris["id"])
        token = _csrf(client, "/secure-notes")
        resp = client.post(
            f"/secure-notes/open/{baris['id']}",
            headers={"X-CSRFToken": token, "X-Reauth-Grant": grant},
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "scope"

    def test_open_idor_pengguna_lain(self, app, client):
        baris = _tambah_catatan(client)
        lain = _client_pengguna(app, 2, "pengujingdua")
        grant = _token_grant(lain, "note.open", baris["id"])
        token = _csrf(lain, "/secure-notes")
        resp = lain.post(
            f"/secure-notes/open/{baris['id']}",
            headers={"X-CSRFToken": token, "X-Reauth-Grant": grant},
        )
        assert resp.status_code == 404

    def test_edit_memerlukan_grant_dan_mencatat_modify(self, client):
        baris = _tambah_catatan(client)
        token = _csrf(client, "/secure-notes")
        tanpa_grant = client.post(
            f"/secure-notes/edit/{baris['id']}",
            data={"csrf_token": token, "title": "Baru", "content": "Isi baru"},
        )
        assert tanpa_grant.status_code == 401
        assert _baris_catatan(baris["id"]) == baris

        grant = _token_grant(client, "note.edit", baris["id"])
        resp = client.post(
            f"/secure-notes/edit/{baris['id']}",
            data={
                "csrf_token": token,
                "reauth_grant": grant,
                "title": "Judul Baru",
                "content": "Isi catatan baru",
            },
        )
        assert resp.status_code == 302

        baru = _baris_catatan(baris["id"])
        assert baru["title_enc"] != baris["title_enc"]
        assert baru["content_enc"] != baris["content_enc"]
        assert "Isi catatan baru" not in baru["content_enc"]
        with get_db() as db:
            blok = db.execute(
                "SELECT * FROM blockchain_log WHERE action='MODIFY' "
                "AND asset_ref=?",
                (f"note:{baris['id']}",),
            ).fetchall()
        assert len(blok) == 1
        assert blok[0]["asset_hash"] == content_hash(
            baru["content_enc"].encode("utf-8")
        )

    def test_edit_idor_pengguna_lain(self, app, client):
        baris = _tambah_catatan(client)
        lain = _client_pengguna(app, 2, "pengujingdua")
        grant = _token_grant(lain, "note.edit", baris["id"])
        token = _csrf(lain, "/secure-notes")
        resp = lain.post(
            f"/secure-notes/edit/{baris['id']}",
            data={
                "csrf_token": token,
                "reauth_grant": grant,
                "title": "Dibajak",
                "content": "Isi bajakan",
            },
        )
        assert resp.status_code == 404
        assert _baris_catatan(baris["id"]) == baris

    def test_hapus_memerlukan_item_delete(self, client):
        baris = _tambah_catatan(client)
        token = _csrf(client, "/secure-notes")
        tanpa_grant = client.post(
            f"/secure-notes/delete/{baris['id']}",
            data={"csrf_token": token},
        )
        assert tanpa_grant.status_code == 401
        assert _baris_catatan(baris["id"]) is not None

        grant = _token_grant(client, "item.delete", baris["id"])
        resp = client.post(
            f"/secure-notes/delete/{baris['id']}",
            data={"csrf_token": token, "reauth_grant": grant},
        )
        assert resp.status_code == 302
        assert _baris_catatan(baris["id"]) is None
        with get_db() as db:
            blok = db.execute(
                "SELECT * FROM blockchain_log WHERE action='DELETE' "
                "AND asset_ref=?",
                (f"note:{baris['id']}",),
            ).fetchall()
        assert len(blok) == 1

    def test_hapus_idor_pengguna_lain(self, app, client):
        baris = _tambah_catatan(client)
        lain = _client_pengguna(app, 2, "pengujingdua")
        grant = _token_grant(lain, "item.delete", baris["id"])
        token = _csrf(lain, "/secure-notes")
        resp = lain.post(
            f"/secure-notes/delete/{baris['id']}",
            data={"csrf_token": token, "reauth_grant": grant},
        )
        assert resp.status_code == 404
        assert _baris_catatan(baris["id"]) is not None


def _baris_berkas(file_id: int) -> dict | None:
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE id=?", (file_id,)
        ).fetchone()
    return dict(row) if row else None


def _unggah_berkas(client, nama: str, isi: bytes) -> dict:
    resp = _unggah(client, nama, isi)
    assert resp.status_code == 302
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (1,),
        ).fetchone()
    return dict(row)


class TestVaultSesiI:
    def test_unggah_menolak_ekstensi_tidak_diizinkan(self, client):
        _unggah(client, "program.exe", b"bukan berkas sah")
        with get_db() as db:
            jumlah = db.execute("SELECT COUNT(*) AS n FROM vault_files").fetchone()["n"]
        assert jumlah == 0

    def test_unggah_menolak_isi_gambar_palsu(self, client):
        _unggah(client, "gambar.png", b"ini bukan gambar PNG")
        with get_db() as db:
            jumlah = db.execute("SELECT COUNT(*) AS n FROM vault_files").fetchone()["n"]
        assert jumlah == 0

    def test_unggah_menerima_gambar_sah(self, client):
        buf = io.BytesIO()
        Image.new("RGB", (32, 32), color=(10, 20, 30)).save(buf, format="PNG")
        row = _unggah_berkas(client, "foto-sah.png", buf.getvalue())
        assert row["file_type"] == "image"
        assert row["file_size"] == len(buf.getvalue())

    def test_unduh_tanpa_grant_ditolak(self, client):
        row = _unggah_berkas(client, "dokumen.pdf", b"isi dokumen")
        token = _csrf(client, "/vault")
        resp = client.post(
            f"/vault/decrypt/{row['id']}", data={"csrf_token": token}
        )
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"

    def test_unduh_scope_salah_ditolak(self, client):
        row = _unggah_berkas(client, "dokumen.pdf", b"isi dokumen")
        token = _csrf(client, "/vault")
        grant = _token_grant(client, "item.delete", row["id"])
        resp = client.post(
            f"/vault/decrypt/{row['id']}",
            data={"csrf_token": token, "reauth_grant": grant},
        )
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "scope"

    def test_unduh_memakai_grant_dan_header_aman(self, client):
        isi = b"isi dokumen aman " * 20
        row = _unggah_berkas(client, "dokumen-aman.pdf", isi)
        resp = _unduh(client, row["id"])
        assert resp.status_code == 200
        assert resp.data == isi
        assert "attachment" in resp.headers.get("Content-Disposition", "").lower()
        assert "dokumen-aman.pdf" in resp.headers.get("Content-Disposition", "")
        assert resp.headers.get("Cache-Control") == "no-store"
        assert "DOWNLOAD" in _blok()

    def test_unduh_idor_pengguna_lain(self, app, client):
        row = _unggah_berkas(client, "milik-satu.pdf", b"rahasia satu")
        lain = _client_pengguna(app, 2, "pengujingdua")
        token = _csrf(lain, "/vault")
        grant = _token_grant(lain, "file.download", row["id"])
        resp = lain.post(
            f"/vault/decrypt/{row['id']}",
            data={"csrf_token": token, "reauth_grant": grant},
        )
        assert resp.status_code == 404

    def test_hapus_memerlukan_item_delete(self, client):
        row = _unggah_berkas(client, "akan-dihapus.pdf", b"isi")
        token = _csrf(client, "/vault")
        tanpa_grant = client.post(
            f"/vault/delete/{row['id']}", data={"csrf_token": token}
        )
        assert tanpa_grant.status_code == 401
        assert _baris_berkas(row["id"]) is not None

        grant = _token_grant(client, "item.delete", row["id"])
        resp = client.post(
            f"/vault/delete/{row['id']}",
            data={"csrf_token": token, "reauth_grant": grant},
        )
        assert resp.status_code == 302
        assert _baris_berkas(row["id"]) is None
        assert not os.path.exists(
            os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        )
        assert "DELETE" in _blok()

    def test_hapus_idor_pengguna_lain(self, app, client):
        row = _unggah_berkas(client, "milik-satu.pdf", b"rahasia satu")
        lain = _client_pengguna(app, 2, "pengujingdua")
        token = _csrf(lain, "/vault")
        grant = _token_grant(lain, "item.delete", row["id"])
        resp = lain.post(
            f"/vault/delete/{row['id']}",
            data={"csrf_token": token, "reauth_grant": grant},
        )
        assert resp.status_code == 404
        assert _baris_berkas(row["id"]) is not None

    def test_startup_menyiapkan_tempdir_dan_membersihkan(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "mulai.db"))
        monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "enc"))
        monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
        monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temp"))
        os.makedirs(config.TEMPORARY_FILES_DIR, exist_ok=True)
        sisa = os.path.join(config.TEMPORARY_FILES_DIR, "sisa.tmp")
        with open(sisa, "wb") as handle:
            handle.write(b"sisa")
        init_db()

        create_app()
        assert tempfile.tempdir == config.TEMPORARY_FILES_DIR
        assert not os.path.exists(sisa)
