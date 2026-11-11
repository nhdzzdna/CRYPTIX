"""
tests/test_ub_sampah.py
───────────────────────
Uji fitur Sampah (UB): migrasi kolom ``deleted_at``, penghapusan lunak yang
menutup akses langsung, halaman sampah, pemulihan, penghapusan permanen
ber-grant ``trash.purge``, pengosongan sampah, retensi 30 hari, dan
isolasi antar pengguna.
"""

import hashlib
import io
import json
import os
import re
from datetime import datetime, timedelta, timezone

import pytest
from PIL import Image

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import reauth
from modules.cryptography import session_keys
from modules.strings import MSG

MASTER_HEX = hashlib.sha256(b"kunci-sesi-uji-sampah").hexdigest()


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "ub-sampah.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted_files"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego_images"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary_files"))
    init_db()
    with get_db() as db:
        for uid, nama in ((1, "pengujisatu"), (2, "pengujidua")):
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
        sess["username"] = "pengujisatu"
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, bytes.fromhex(MASTER_HEX))
    return c


# ── Pembantu ───────────────────────────────────────────────────────────────────


def _client_pengguna(app, user_id: int, username: str):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = username
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
        session_keys.put(sid, bytes.fromhex(MASTER_HEX))
    return c


def _csrf(client, halaman="/sampah") -> str:
    page = client.get(halaman)
    assert page.status_code == 200
    cocok = re.search(
        r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)
    )
    assert cocok, "token CSRF tidak ditemukan"
    return cocok.group(1)


def _grant(client, scope="trash.purge", resource_id=None) -> str:
    with client.session_transaction() as sess:
        sid = sess["session_id"]
    return reauth.issue_grant(sid, scope, resource_id)["token"]


def _unggah(client, nama="laporan.pdf", isi=b"isi dokumen uji") -> dict:
    token = _csrf(client, "/vault")
    resp = client.post("/vault/upload", data={
        "csrf_token": token,
        "file": (io.BytesIO(isi), nama),
    }, content_type="multipart/form-data")
    assert resp.status_code == 302
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM vault_files WHERE user_id=1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    return dict(row)


def _tambah_catatan(client, judul="Judul Catatan Uji") -> dict:
    token = _csrf(client, "/secure-notes")
    resp = client.post("/secure-notes/add", data={
        "csrf_token": token, "title": judul, "content": "isi catatan uji",
    })
    assert resp.status_code == 302
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM secure_notes WHERE user_id=1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return dict(row)


def _tambah_kredensial(client, site="Situs Uji") -> dict:
    token = _csrf(client, "/account-vault")
    resp = client.post("/account-vault/add", data={
        "csrf_token": token, "site_name": site, "username": "pengguna-uji",
        "password": "sandi-uji", "url": "https://contoh.test", "notes": "",
    })
    assert resp.status_code == 302
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM account_vault WHERE user_id=1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return dict(row)


HALAMAN_HAPUS = {
    "file": ("/vault", "/vault/delete/{}"),
    "note": ("/secure-notes", "/secure-notes/delete/{}"),
    "cred": ("/account-vault", "/account-vault/delete/{}"),
    "stego": ("/steganography", "/steganography/delete/{}"),
}


def _pindah_ke_sampah(client, jenis: str, item_id: int):
    """Pindahkan item milik pengguna sesi ke sampah lewat endpoint hapus."""
    halaman, pola = HALAMAN_HAPUS[jenis]
    token = _csrf(client, halaman)
    resp = client.post(pola.format(item_id), data={"csrf_token": token})
    assert resp.status_code == 302


def _items(*pasangan) -> str:
    """Badan items: JSON string daftar {jenis, id} seperti form halaman sampah."""
    return json.dumps([{"jenis": j, "id": i} for j, i in pasangan])


def _blok_aksi(asset_ref: str) -> list[str]:
    with get_db() as db:
        return [
            b["action"] for b in db.execute(
                "SELECT action FROM blockchain_log WHERE asset_ref=? "
                "ORDER BY block_index", (asset_ref,),
            )
        ]


def _baris(tabel: str, item_id: int) -> dict | None:
    with get_db() as db:
        row = db.execute(
            f"SELECT * FROM {tabel} WHERE id=?", (item_id,)
        ).fetchone()
    return dict(row) if row else None


def _hitung_dashboard(client, kelas="dash-stat-value") -> list[str]:
    body = client.get("/dashboard").get_data(as_text=True)
    return re.findall(rf'class="{kelas}">\s*(\d+)\s*<', body)


# ── Migrasi ────────────────────────────────────────────────────────────────────


class TestMigrasiSampah:
    @pytest.mark.parametrize(
        "tabel",
        ["vault_files", "secure_notes", "account_vault", "stego_images"],
    )
    def test_kolom_deleted_at_tersedia(self, app, tabel):
        with get_db() as db:
            kolom = {b["name"] for b in db.execute(f"PRAGMA table_info({tabel})")}
        assert "deleted_at" in kolom

    def test_migrasi_dua_kali_tanpa_galat(self, app):
        init_db()
        init_db()


# ── Penghapusan lunak ──────────────────────────────────────────────────────────


class TestHapusLunak:
    def test_hapus_tanpa_grant_memindah_ke_sampah(self, client):
        row = _unggah(client, "laporan-sampah.pdf", b"isi rahasia")
        _pindah_ke_sampah(client, "file", row["id"])

        sesudah = _baris("vault_files", row["id"])
        assert sesudah is not None
        assert sesudah["deleted_at"] is not None
        # Berkas terenkripsi tetap di disk dan tetap diverifikasi rantai.
        assert os.path.exists(
            os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        )

        aksi = _blok_aksi(f"file:{row['id']}")
        assert aksi.count("TRASH_MOVE") == 1
        assert "DELETE" not in aksi
        with get_db() as db:
            blok = db.execute(
                "SELECT asset_hash FROM blockchain_log "
                "WHERE asset_ref=? AND action='TRASH_MOVE'",
                (f"file:{row['id']}",),
            ).fetchone()
        assert blok["asset_hash"] == row["sha256_ciphertext"]

    def test_hapus_idempoten_ditolak_saat_sudah_di_sampah(self, client):
        row = _unggah(client, "dua-kali.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        token = _csrf(client, "/vault")
        resp = client.post(
            f"/vault/delete/{row['id']}", data={"csrf_token": token}
        )
        assert resp.status_code == 404
        assert _baris("vault_files", row["id"]) is not None

    def test_sampah_tidak_tampil_di_daftar(self, client):
        row = _unggah(client, "tidak-tampil.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        body = client.get("/vault").get_data(as_text=True)
        assert "tidak-tampil.pdf" not in body
        media = client.get("/media-vault").get_data(as_text=True)
        assert "tidak-tampil.pdf" not in media

    def test_sampah_tidak_dihitung_dashboard(self, client):
        _unggah(client, "dihitung.pdf")
        assert _hitung_dashboard(client)[0] == "1"
        row = _unggah(client, "tidak-dihitung.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        assert _hitung_dashboard(client)[0] == "1"

    def test_sampah_menutup_akses_langsung(self, client):
        row = _unggah(client, "terkunci.mp3", b"isi audio uji")
        _pindah_ke_sampah(client, "file", row["id"])
        fid = row["id"]

        # Unduh vault tetap butuh grant file.download; item sampah → 404.
        token = _csrf(client, "/vault")
        resp = client.post(
            f"/vault/decrypt/{fid}",
            data={"csrf_token": token, "reauth_grant": _grant(client, "file.download", fid)},
        )
        assert resp.status_code == 404

        for scope, url in (
            ("media.stream", f"/media-vault/stream/{fid}"),
            ("file.download", f"/media-vault/download/{fid}"),
        ):
            resp = client.get(
                url, headers={"X-Reauth-Grant": _grant(client, scope, fid)}
            )
            assert resp.status_code == 404
        assert client.get(f"/media-vault/view/{fid}").status_code == 404
        assert client.get(f"/media-vault/thumb/{fid}").status_code == 404

    def test_sampah_note_menutup_akses_langsung(self, client):
        baris = _tambah_catatan(client, "Catatan Terkunci")
        _pindah_ke_sampah(client, "note", baris["id"])
        resp = client.post(
            f"/secure-notes/open/{baris['id']}",
            headers={
                "X-CSRFToken": _csrf(client, "/secure-notes"),
                "X-Reauth-Grant": _grant(client, "note.open", baris["id"]),
            },
        )
        assert resp.status_code == 404

    def test_sampah_cred_menutup_akses_langsung(self, client):
        baris = _tambah_kredensial(client)
        _pindah_ke_sampah(client, "cred", baris["id"])
        resp = client.post(
            f"/account-vault/reveal/{baris['id']}",
            headers={
                "X-CSRFToken": _csrf(client, "/account-vault"),
                "X-Reauth-Grant": _grant(client, "account.reveal", baris["id"]),
            },
        )
        assert resp.status_code == 404

    def test_sampah_stego_menutup_akses_langsung(self, client, tmp_path):
        gambar = Image.new("RGB", (160, 160), color=(30, 60, 120))
        jalur = tmp_path / "gambar-stego.png"
        gambar.save(jalur, format="PNG")
        token = _csrf(client, "/steganography")
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(jalur.read_bytes()), "gambar-stego.png"),
            "message": "pesan tersembunyi",
        }, content_type="multipart/form-data")
        assert resp.status_code == 302
        with get_db() as db:
            row = dict(db.execute(
                "SELECT * FROM stego_images WHERE user_id=1 "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone())
        _pindah_ke_sampah(client, "stego", row["id"])

        # Berkas fisik stego tetap di disk sampai dihapus permanen.
        assert os.path.exists(
            os.path.join(config.STEGO_IMAGES_DIR, row["stored_name"])
        )
        ekstrak = client.post(
            f"/steganography/extract/{row['id']}",
            headers={
                "X-CSRFToken": _csrf(client, "/steganography"),
                "X-Reauth-Grant": _grant(client, "stego.extract", row["id"]),
            },
        )
        assert ekstrak.status_code == 404
        unduh = client.get(
            f"/steganography/download/{row['id']}",
            headers={"X-Reauth-Grant": _grant(client, "stego.download", row["id"])},
        )
        assert unduh.status_code == 404


# ── Halaman sampah ─────────────────────────────────────────────────────────────


class TestHalamanSampah:
    def test_kosong(self, client):
        body = client.get("/sampah").get_data(as_text=True)
        assert MSG.TRASH_EMPTY in body

    def test_menampilkan_item_dengan_nama_terdekripsi(self, client):
        catatan = _tambah_catatan(client, "Judul Rahasia Sampah")
        _pindah_ke_sampah(client, "note", catatan["id"])
        row = _unggah(client, "berkas-sampah.pdf")
        _pindah_ke_sampah(client, "file", row["id"])

        body = client.get("/sampah").get_data(as_text=True)
        assert "Judul Rahasia Sampah" in body
        assert "berkas-sampah.pdf" in body
        assert MSG.TRASH_KIND_NOTE in body
        assert MSG.TRASH_KIND_FILE in body
        assert MSG.TRASH_RESTORE_BUTTON in body
        assert MSG.TRASH_PURGE_BUTTON in body
        assert MSG.TRASH_EMPTY_BUTTON in body
        # Nilai terenkripsi tidak pernah bocor ke halaman.
        assert catatan["title_enc"] not in body
        assert row["original_name"] not in body


# ── Pemulihan ──────────────────────────────────────────────────────────────────


class TestPulihkan:
    def test_pulihkan_mengembalikan_item(self, client):
        row = _unggah(client, "dipulihkan.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        resp = client.post("/api/sampah/pulihkan", data={
            "csrf_token": _csrf(client, "/sampah"),
            "items": _items(("file", row["id"])),
        })
        assert resp.status_code == 302

        sesudah = _baris("vault_files", row["id"])
        assert sesudah is not None
        assert sesudah["deleted_at"] is None
        assert "dipulihkan.pdf" in client.get("/vault").get_data(as_text=True)
        assert MSG.TRASH_EMPTY in client.get("/sampah").get_data(as_text=True)

    def test_pulihkan_respons_json(self, client):
        row = _unggah(client, "dipulihkan-json.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        resp = client.post(
            "/api/sampah/pulihkan",
            json={"items": [{"jenis": "file", "id": row["id"]}]},
            headers={"X-CSRFToken": _csrf(client, "/sampah")},
        )
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True
        assert _baris("vault_files", row["id"])["deleted_at"] is None

    def test_pulihkan_tanpa_csrf_ditolak(self, client):
        row = _unggah(client, "tanpa-csrf.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        resp = client.post("/api/sampah/pulihkan", data={
            "items": _items(("file", row["id"])),
        })
        assert resp.status_code == 400
        assert _baris("vault_files", row["id"])["deleted_at"] is not None

    def test_pulihkan_gagal_bila_satu_item_tidak_di_sampah(self, client):
        row = _unggah(client, "masih-aktif.pdf")
        catatan = _tambah_catatan(client)
        _pindah_ke_sampah(client, "note", catatan["id"])
        resp = client.post("/api/sampah/pulihkan", data={
            "csrf_token": _csrf(client, "/sampah"),
            "items": _items(("file", row["id"]), ("note", catatan["id"])),
        })
        assert resp.status_code == 404
        # All-or-nothing: catatan tetap di sampah.
        assert _baris("secure_notes", catatan["id"])["deleted_at"] is not None

    def test_items_tidak_sah_ditolak(self, client):
        token = _csrf(client, "/sampah")
        for isi in ("bukan-json", json.dumps([]),
                    json.dumps([{"jenis": "album", "id": 1}]),
                    json.dumps([{"jenis": "file", "id": "bukan-angka"}])):
            resp = client.post("/api/sampah/pulihkan", data={
                "csrf_token": token, "items": isi,
            })
            assert resp.status_code == 400


# ── Hapus permanen (grant trash.purge) ─────────────────────────────────────────


class TestHapusPermanen:
    def test_tanpa_grant_ditolak(self, client):
        row = _unggah(client, "tanpa-grant.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        resp = client.post("/api/sampah/hapus-permanen", data={
            "csrf_token": _csrf(client, "/sampah"),
            "items": _items(("file", row["id"])),
        })
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "missing"
        assert _baris("vault_files", row["id"]) is not None

    def test_scope_salah_ditolak(self, client):
        row = _unggah(client, "scope-salah.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        resp = client.post("/api/sampah/hapus-permanen", data={
            "csrf_token": _csrf(client, "/sampah"),
            "reauth_grant": _grant(client, "item.delete"),
            "items": _items(("file", row["id"])),
        })
        assert resp.status_code == 403
        assert resp.get_json()["reason"] == "scope"
        assert _baris("vault_files", row["id"]) is not None

    def test_grant_sekali_pakai(self, client):
        row = _unggah(client, "pertama.pdf")
        lain = _unggah(client, "kedua.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        _pindah_ke_sampah(client, "file", lain["id"])
        token = _csrf(client, "/sampah")
        grant = _grant(client, "trash.purge")
        pertama = client.post("/api/sampah/hapus-permanen", data={
            "csrf_token": token, "reauth_grant": grant,
            "items": _items(("file", row["id"])),
        })
        assert pertama.status_code == 302
        kedua = client.post("/api/sampah/hapus-permanen", data={
            "csrf_token": token, "reauth_grant": grant,
            "items": _items(("file", lain["id"])),
        })
        assert kedua.status_code == 401
        assert _baris("vault_files", lain["id"]) is not None

    def test_purge_menghapus_baris_berkas_dan_blok(self, client):
        row = _unggah(client, "purge-saya.pdf", b"isi purge")
        _pindah_ke_sampah(client, "file", row["id"])
        resp = client.post("/api/sampah/hapus-permanen", data={
            "csrf_token": _csrf(client, "/sampah"),
            "reauth_grant": _grant(client, "trash.purge"),
            "items": _items(("file", row["id"])),
        })
        assert resp.status_code == 302
        assert _baris("vault_files", row["id"]) is None
        assert not os.path.exists(
            os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        )
        aksi = _blok_aksi(f"file:{row['id']}")
        assert aksi == ["UPLOAD", "TRASH_MOVE", "DELETE"]

    def test_purge_respons_json(self, client):
        row = _unggah(client, "purge-json.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        resp = client.post(
            "/api/sampah/hapus-permanen",
            json={"items": [{"jenis": "file", "id": row["id"]}]},
            headers={
                "X-CSRFToken": _csrf(client, "/sampah"),
                "X-Reauth-Grant": _grant(client, "trash.purge"),
            },
        )
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True
        assert _baris("vault_files", row["id"]) is None

    def test_purge_banyak_jenis_sekaligus(self, client):
        row = _unggah(client, "berkas.pdf")
        catatan = _tambah_catatan(client)
        kred = _tambah_kredensial(client)
        _pindah_ke_sampah(client, "file", row["id"])
        _pindah_ke_sampah(client, "note", catatan["id"])
        _pindah_ke_sampah(client, "cred", kred["id"])

        resp = client.post("/api/sampah/hapus-permanen", data={
            "csrf_token": _csrf(client, "/sampah"),
            "reauth_grant": _grant(client, "trash.purge"),
            "items": _items(("file", row["id"]), ("note", catatan["id"]),
                            ("cred", kred["id"])),
        })
        assert resp.status_code == 302
        assert _baris("vault_files", row["id"]) is None
        assert _baris("secure_notes", catatan["id"]) is None
        assert _baris("account_vault", kred["id"]) is None
        assert "DELETE" in _blok_aksi(f"file:{row['id']}")
        assert "DELETE" in _blok_aksi(f"note:{catatan['id']}")
        assert "DELETE" in _blok_aksi(f"cred:{kred['id']}")

    def test_purge_menghapus_relasi_koleksi(self, client):
        row = _unggah(client, "di-koleksi.pdf")
        with get_db() as db:
            koleksi = db.execute(
                "INSERT INTO collections (user_id, kind, name_enc) "
                "VALUES (1, 'dokumen', 'v1:aa:bb')",
            ).lastrowid
            db.execute(
                "INSERT INTO collection_items (file_id, collection_id, state) "
                "VALUES (?, ?, 'normal')",
                (row["id"], koleksi),
            )
            db.commit()
        _pindah_ke_sampah(client, "file", row["id"])

        resp = client.post("/api/sampah/hapus-permanen", data={
            "csrf_token": _csrf(client, "/sampah"),
            "reauth_grant": _grant(client, "trash.purge"),
            "items": _items(("file", row["id"])),
        })
        assert resp.status_code == 302
        with get_db() as db:
            relasi = db.execute(
                "SELECT COUNT(*) FROM collection_items WHERE file_id=?",
                (row["id"],),
            ).fetchone()[0]
        assert relasi == 0

    def test_purge_stego_menghapus_berkas_fisik(self, client, tmp_path):
        gambar = Image.new("RGB", (160, 160), color=(90, 30, 120))
        jalur = tmp_path / "gambar-stego-purge.png"
        gambar.save(jalur, format="PNG")
        token = _csrf(client, "/steganography")
        resp = client.post("/steganography/embed", data={
            "csrf_token": token,
            "carrier_image": (io.BytesIO(jalur.read_bytes()), "gambar-stego.png"),
            "message": "pesan purge",
        }, content_type="multipart/form-data")
        assert resp.status_code == 302
        with get_db() as db:
            row = dict(db.execute(
                "SELECT * FROM stego_images WHERE user_id=1 "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone())
        _pindah_ke_sampah(client, "stego", row["id"])
        path = os.path.join(config.STEGO_IMAGES_DIR, row["stored_name"])

        purge = client.post("/api/sampah/hapus-permanen", data={
            "csrf_token": _csrf(client, "/sampah"),
            "reauth_grant": _grant(client, "trash.purge"),
            "items": _items(("stego", row["id"])),
        })
        assert purge.status_code == 302
        assert _baris("stego_images", row["id"]) is None
        assert not os.path.exists(path)
        assert "DELETE" in _blok_aksi(f"stego:{row['id']}")

    def test_item_tidak_di_sampah_ditolak(self, client):
        row = _unggah(client, "masih-aktif.pdf")
        resp = client.post("/api/sampah/hapus-permanen", data={
            "csrf_token": _csrf(client, "/sampah"),
            "reauth_grant": _grant(client, "trash.purge"),
            "items": _items(("file", row["id"])),
        })
        assert resp.status_code == 404
        assert _baris("vault_files", row["id"]) is not None


# ── Kosongkan sampah ───────────────────────────────────────────────────────────


class TestKosongkanSampah:
    def test_kosongkan_menghapus_semua(self, client):
        row = _unggah(client, "dikosongkan.pdf")
        catatan = _tambah_catatan(client)
        _pindah_ke_sampah(client, "file", row["id"])
        _pindah_ke_sampah(client, "note", catatan["id"])

        resp = client.post("/api/sampah/kosongkan", data={
            "csrf_token": _csrf(client, "/sampah"),
            "reauth_grant": _grant(client, "trash.purge"),
        })
        assert resp.status_code == 302
        assert _baris("vault_files", row["id"]) is None
        assert _baris("secure_notes", catatan["id"]) is None
        assert not os.path.exists(
            os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        )
        assert "DELETE" in _blok_aksi(f"file:{row['id']}")
        body = client.get("/sampah").get_data(as_text=True)
        assert MSG.TRASH_EMPTY in body

    def test_kosongkan_tanpa_grant_ditolak(self, client):
        row = _unggah(client, "tetap-ada.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        resp = client.post("/api/sampah/kosongkan", data={
            "csrf_token": _csrf(client, "/sampah"),
        })
        assert resp.status_code == 401
        assert _baris("vault_files", row["id"]) is not None

    def test_kosongkan_sampah_kosong_tetap_berhasil(self, client):
        resp = client.post("/api/sampah/kosongkan", data={
            "csrf_token": _csrf(client, "/sampah"),
            "reauth_grant": _grant(client, "trash.purge"),
        })
        assert resp.status_code == 302


# ── Retensi 30 hari ────────────────────────────────────────────────────────────


class TestRetensi:
    def _jadikan_lama(self, tabel, item_id, hari: int):
        lama = (
            datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=hari)
        ).strftime("%Y-%m-%d %H:%M:%S")
        with get_db() as db:
            db.execute(
                f"UPDATE {tabel} SET deleted_at=? WHERE id=?", (lama, item_id)
            )
            db.commit()

    def test_item_kedaluwarsa_dibersihkan_otomatis(self, client):
        row = _unggah(client, "kedaluwarsa.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        self._jadikan_lama("vault_files", row["id"], config.TRASH_RETENTION_DAYS + 1)

        resp = client.get("/sampah")
        assert resp.status_code == 200
        assert _baris("vault_files", row["id"]) is None
        assert not os.path.exists(
            os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        )
        assert "DELETE" in _blok_aksi(f"file:{row['id']}")

    def test_item_baru_tidak_dibersihkan(self, client):
        row = _unggah(client, "masih-segar.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        client.get("/sampah")
        assert _baris("vault_files", row["id"]) is not None
        assert os.path.exists(
            os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        )

    def test_retensi_hanya_sampah_pengguna_sesi(self, app, client):
        row = _unggah(client, "milik-satu.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        self._jadikan_lama("vault_files", row["id"], config.TRASH_RETENTION_DAYS + 1)

        lain = _client_pengguna(app, 2, "pengujidua")
        assert lain.get("/sampah").status_code == 200
        # Sampah milik pengguna lain tidak disentuh.
        assert _baris("vault_files", row["id"]) is not None

        # Pemiliknya sendiri yang membuka halaman membersihkan item itu.
        assert client.get("/sampah").status_code == 200
        assert _baris("vault_files", row["id"]) is None


# ── Isolasi antar pengguna ─────────────────────────────────────────────────────


class TestAntarPengguna:
    def test_pulihkan_milik_orang_lain_ditolak(self, app, client):
        row = _unggah(client, "milik-satu.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        lain = _client_pengguna(app, 2, "pengujidua")
        resp = lain.post("/api/sampah/pulihkan", data={
            "csrf_token": _csrf(lain, "/sampah"),
            "items": _items(("file", row["id"])),
        })
        assert resp.status_code == 404
        assert _baris("vault_files", row["id"])["deleted_at"] is not None

    def test_purge_milik_orang_lain_ditolak(self, app, client):
        row = _unggah(client, "milik-satu.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        lain = _client_pengguna(app, 2, "pengujidua")
        resp = lain.post("/api/sampah/hapus-permanen", data={
            "csrf_token": _csrf(lain, "/sampah"),
            "reauth_grant": _grant(lain, "trash.purge"),
            "items": _items(("file", row["id"])),
        })
        assert resp.status_code == 404
        assert _baris("vault_files", row["id"]) is not None
        assert os.path.exists(
            os.path.join(config.ENCRYPTED_FILES_DIR, row["stored_name"])
        )

    def test_kosongkan_tidak_menyentuh_sampah_orang_lain(self, app, client):
        row = _unggah(client, "milik-satu.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        lain = _client_pengguna(app, 2, "pengujidua")
        resp = lain.post("/api/sampah/kosongkan", data={
            "csrf_token": _csrf(lain, "/sampah"),
            "reauth_grant": _grant(lain, "trash.purge"),
        })
        assert resp.status_code == 302
        assert _baris("vault_files", row["id"]) is not None

    def test_halaman_sampah_tidak_menampilkan_orang_lain(self, app, client):
        row = _unggah(client, "milik-satu.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        lain = _client_pengguna(app, 2, "pengujidua")
        body = lain.get("/sampah").get_data(as_text=True)
        assert "milik-satu.pdf" not in body
        assert MSG.TRASH_EMPTY in body


# ── Scope grant ────────────────────────────────────────────────────────────────


class TestScopeTrashPurge:
    def test_scope_dikenal_dan_sekali_pakai(self, client):
        with client.session_transaction() as sess:
            sid = sess["session_id"]
        detail = reauth.issue_grant(sid, "trash.purge")
        assert detail["scope"] == "trash.purge"
        assert detail["reusable"] is False

    def test_grant_sesi_lain_ditolak(self, app, client):
        row = _unggah(client, "sesi-lain.pdf")
        _pindah_ke_sampah(client, "file", row["id"])
        lain = _client_pengguna(app, 2, "pengujidua")
        grant = _grant(lain, "trash.purge")
        resp = client.post("/api/sampah/hapus-permanen", data={
            "csrf_token": _csrf(client, "/sampah"),
            "reauth_grant": grant,
            "items": _items(("file", row["id"])),
        })
        assert resp.status_code == 401
        assert resp.get_json()["reason"] == "session"
        assert _baris("vault_files", row["id"]) is not None
