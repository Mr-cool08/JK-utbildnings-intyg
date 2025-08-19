import io
import os
import sys

import pytest
import sqlite3
from werkzeug.datastructures import FileStorage

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import main


# Tests for normalize_personnummer

def test_normalize_personnummer_valid():
    assert main.normalize_personnummer(" 19900101-1234 ") == "19900101-1234"


def test_normalize_personnummer_invalid():
    with pytest.raises(ValueError):
        main.normalize_personnummer("abc")


# Tests for save_pdf_for_user

def test_save_pdf_for_user(tmp_path, monkeypatch):
    monkeypatch.setitem(main.app.config, "UPLOAD_ROOT", tmp_path)

    pdf_bytes = b"%PDF-1.4 test"
    file_storage = FileStorage(
        stream=io.BytesIO(pdf_bytes),
        filename="test.pdf",
        content_type="application/pdf",
    )

    rel_path = main.save_pdf_for_user("19900101-1234", file_storage)

    abs_path = os.path.abspath(os.path.join(main.APP_ROOT, rel_path))
    assert os.path.exists(abs_path)
    with open(abs_path, "rb") as f:
        assert f.read() == pdf_bytes


def setup_user(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"

    real_connect = sqlite3.connect

    def connect_stub(_):
        return real_connect(db_path)

    monkeypatch.setattr(main.functions.sqlite3, "connect", connect_stub)
    import functions
    monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
    main.app.secret_key = "test-secret"

    functions.create_database()
    conn = real_connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        ("Test", "test@example.com", "secret", "199001011234"),
    )
    conn.commit()
    conn.close()


def test_login_success(tmp_path, monkeypatch):
    setup_user(tmp_path, monkeypatch)
    with main.app.test_client() as client:
        response = client.post(
            "/login", data={"personnummer": "199001011234", "password": "secret"}
        )
        assert response.status_code == 302


def test_login_failure(tmp_path, monkeypatch):
    setup_user(tmp_path, monkeypatch)
    with main.app.test_client() as client:
        response = client.post(
            "/login", data={"personnummer": "199001011234", "password": "wrong"}
        )
        assert response.status_code == 401


def test_dashboard_shows_only_user_pdfs(tmp_path, monkeypatch):
    setup_user(tmp_path, monkeypatch)
    monkeypatch.setitem(main.app.config, "UPLOAD_ROOT", tmp_path)

    user_dir = tmp_path / "199001011234"
    user_dir.mkdir()
    (user_dir / "own.pdf").write_text("test")

    other_dir = tmp_path / "200001011234"
    other_dir.mkdir()
    (other_dir / "other.pdf").write_text("test")

    with main.app.test_client() as client:
        client.post(
            "/login", data={"personnummer": "199001011234", "password": "secret"}
        )
        response = client.get("/dashboard")
        assert b"own.pdf" in response.data
        assert b"other.pdf" not in response.data


def setup_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    real_connect = sqlite3.connect

    def connect_stub(_):
        return real_connect(db_path)

    monkeypatch.setattr(main.functions.sqlite3, "connect", connect_stub)
    import functions
    monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
    main.app.secret_key = "test-secret"

    functions.create_database()
    return db_path


def test_admin_upload_creates_pending_user(tmp_path, monkeypatch):
    db_path = setup_db(tmp_path, monkeypatch)
    monkeypatch.setitem(main.app.config, "UPLOAD_ROOT", tmp_path)

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "new@example.com",
        "username": "New User",
        "personnummer": "199001011234",
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with main.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.post("/admin", data=data, content_type="multipart/form-data")
        assert response.status_code == 200
        assert response.get_json()["status"] == "success"

    # Verify file saved
    user_dir = tmp_path / "199001011234"
    files = list(user_dir.glob("*.pdf"))
    assert len(files) == 1

    # Verify database entry contains pdf_path
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT pdf_path FROM pending_users WHERE email=?", ("new@example.com",)
    )
    row = cursor.fetchone()
    conn.close()
    assert row is not None
    assert row[0].endswith(files[0].name)
