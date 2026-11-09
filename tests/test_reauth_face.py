"""
tests/test_reauth_face.py
─────────────────────────
Uji metode wajah pada autentikasi ulang (step-up): verifikasi frame kamera
terhadap template terenkripsi milik sesi aktif, penerbitan grant, dan
penolakan tanpa grant bila wajah tidak cocok atau template belum ada.
"""

import re

import numpy as np
import pytest

import config
from app import create_app
from database.db import get_db, init_db
from modules.authentication import face_recognition as face_mod
from modules.authentication import reauth
from modules.authentication.password_hash import hash_password
from modules.blockchain import blockchain as bc
from modules.cryptography import session_keys
from modules.strings import MSG

DEK = bytes(range(32))
PASSWORD = "KataSandi-Reauth-Wajah-2026!"
USERNAME = "penguji_wajah_reauth"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "reauth_face.db"))
    monkeypatch.setattr(config, "ENCRYPTED_FILES_DIR", str(tmp_path / "encrypted"))
    monkeypatch.setattr(config, "STEGO_IMAGES_DIR", str(tmp_path / "stego"))
    monkeypatch.setattr(config, "TEMPORARY_FILES_DIR", str(tmp_path / "temporary"))
    monkeypatch.setattr(config, "FACE_CONFIDENCE_THRESHOLD", 50.0)
    monkeypatch.setattr(bc, "CHAIN_HEAD_PATH", str(tmp_path / "chain_head.json"))
    init_db()

    pw_hash, salt = hash_password(PASSWORD)
    with get_db() as db:
        db.execute(
            """INSERT INTO users (id, username, email, password_hash, salt)
               VALUES (?,?,?,?,?)""",
            (1, USERNAME, "wajah-reauth@contoh.test", pw_hash, salt),
        )
        db.execute(
            """INSERT INTO users (id, username, email, password_hash, salt)
               VALUES (?,?,?,?,?)""",
            (2, USERNAME + "_lain", "lain@contoh.test", pw_hash, salt),
        )
        db.commit()

    application = create_app()
    application.config["TESTING"] = True

    def file_view(resource_id: int):
        return {"ok": True, "resource_id": resource_id}

    def stream_view(resource_id: int):
        return {"ok": True, "resource_id": resource_id}

    application.add_url_rule(
        "/uji/file/<int:resource_id>", "uji_file",
        reauth.require_grant("file.download")(file_view),
        methods=["GET", "POST"],
    )
    application.add_url_rule(
        "/uji/stream/<int:resource_id>", "uji_stream",
        reauth.require_grant("media.stream")(stream_view),
    )

    reauth.clear()
    session_keys.clear()
    yield application
    reauth.clear()
    session_keys.clear()


def _client(app, user_id: int = 1):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["username"] = USERNAME
        sid = session_keys.create_session_id()
        sess["session_id"] = sid
    session_keys.put(sid, DEK)
    return client


def _csrf(client, jalur="/media-vault") -> str:
    halaman = client.get(jalur)
    assert halaman.status_code == 200
    cocok = re.search(
        r'<meta name="csrf-token" content="([^"]+)"',
        halaman.get_data(as_text=True),
    )
    assert cocok
    return cocok.group(1)


def _simpan_template(user_id: int = 1) -> None:
    samples = [
        np.full((200, 200), nilai, dtype=np.uint8) for nilai in range(1, 6)
    ]
    face_mod._simpan_template(user_id, DEK, samples)


def _pasang_wajah(monkeypatch, confidence: float = 10.0) -> None:
    monkeypatch.setattr(face_mod, "_decode_frame", lambda item: item)
    monkeypatch.setattr(
        face_mod, "_deteksi_roi",
        lambda frame: np.full((200, 200), 5, dtype=np.uint8),
    )
    monkeypatch.setattr(face_mod, "_latih", lambda samples: object())
    monkeypatch.setattr(
        face_mod, "_prediksi", lambda pen, roi: float(confidence)
    )


def _minta_wajah(client, frames=None, scope="file.download",
                 resource_id=7, halaman_csrf="/media-vault"):
    if frames is None:
        frames = [f"frame-{i}" for i in range(5)]
    return client.post(
        "/api/reauth",
        json={
            "method": "wajah",
            "scope": scope,
            "resource_id": resource_id,
            "frames": frames,
        },
        headers={"X-CSRFToken": _csrf(client, halaman_csrf)},
    )


def _blok_reauth() -> list[dict]:
    with get_db() as db:
        return [
            dict(baris) for baris in db.execute(
                "SELECT * FROM blockchain_log WHERE action = 'REAUTH'"
            )
        ]


class TestReauthWajah:
    def test_wajah_berhasil_dan_grant_melanjutkan_tindakan(
        self, app, monkeypatch
    ):
        client = _client(app)
        _simpan_template()
        _pasang_wajah(monkeypatch)

        resp = _minta_wajah(client)
        assert resp.status_code == 200, resp.get_data(as_text=True)
        data = resp.get_json()
        assert data["success"] is True
        assert data["grant"]
        assert data["scope"] == "file.download"
        assert data["resource_id"] == "7"

        lanjut = client.get(
            "/uji/file/7", headers={"X-Reauth-Grant": data["grant"]}
        )
        assert lanjut.status_code == 200
        assert lanjut.get_json()["resource_id"] == 7
        assert len(_blok_reauth()) == 1

    def test_wajah_tidak_cocok_tidak_menerbitkan_grant(
        self, app, monkeypatch
    ):
        client = _client(app)
        _simpan_template()
        _pasang_wajah(monkeypatch, confidence=100.0)

        resp = _minta_wajah(client)
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.AUTH_FACE_FAILED
        assert _blok_reauth() == []

    def test_template_wajah_belum_terdaftar_ditolak(self, app, monkeypatch):
        client = _client(app)
        _pasang_wajah(monkeypatch)

        resp = _minta_wajah(client)
        assert resp.status_code == 401
        assert resp.get_json()["success"] is False
        assert _blok_reauth() == []

    def test_frame_kurang_atau_tidak_valid_ditolak(self, app, monkeypatch):
        client = _client(app)
        _simpan_template()
        _pasang_wajah(monkeypatch)

        kurang = _minta_wajah(client, frames=["satu"] * 4)
        assert kurang.status_code == 401
        assert kurang.get_json()["success"] is False

        bukan_list = _minta_wajah(client, frames="bukan-frame")
        assert bukan_list.status_code == 401
        assert bukan_list.get_json()["error"] == MSG.FACE_NO_FRAMES
        assert _blok_reauth() == []

    def test_user_lain_tidak_dapat_memakai_template(self, app, monkeypatch):
        client = _client(app, user_id=2)
        _simpan_template(user_id=1)
        _pasang_wajah(monkeypatch)

        resp = _minta_wajah(client)
        assert resp.status_code == 401
        assert _blok_reauth() == []

    def test_sesi_tanpa_kunci_ditolak(self, app, monkeypatch):
        client = app.test_client()
        token = _csrf(client, "/login")
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = USERNAME
            sess["session_id"] = session_keys.create_session_id()
        _pasang_wajah(monkeypatch)

        resp = client.post(
            "/api/reauth",
            json={
                "method": "wajah",
                "scope": "file.download",
                "resource_id": 7,
                "frames": [f"frame-{i}" for i in range(5)],
            },
            headers={"X-CSRFToken": token},
        )
        assert resp.status_code == 401
        assert resp.get_json()["error"] == MSG.SESSION_EXPIRED
        assert _blok_reauth() == []

    def test_grant_terikat_scope_dan_resource(self, app, monkeypatch):
        client = _client(app)
        _simpan_template()
        _pasang_wajah(monkeypatch)

        data = _minta_wajah(client, scope="file.download",
                           resource_id=7).get_json()
        token = data["grant"]

        salah_scope = client.get(
            "/uji/stream/7", headers={"X-Reauth-Grant": token}
        )
        assert salah_scope.status_code == 403
        assert salah_scope.get_json()["reason"] == "scope"

        salah_resource = client.get(
            "/uji/file/8", headers={"X-Reauth-Grant": token}
        )
        assert salah_resource.status_code == 403
        assert salah_resource.get_json()["reason"] == "resource"

        benar = client.get(
            "/uji/file/7", headers={"X-Reauth-Grant": token}
        )
        assert benar.status_code == 200


class TestAntarmukaReauth:
    def test_modal_memuat_pilihan_wajah_webauthn_dan_kata_sandi(
        self, app
    ):
        client = _client(app)
        body = client.get("/media-vault").get_data(as_text=True)
        assert 'id="reauth-face"' in body
        assert 'id="reauth-webauthn"' in body
        assert 'id="reauth-password"' in body
        assert "Verifikasi Wajah" in body
        assert "WebAuthn" in body
        assert "js/face.js" in body
