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
