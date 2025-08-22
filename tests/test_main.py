import io
import os
import sys

import pytest
import sqlite3
from werkzeug.datastructures import FileStorage

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import main
import functions


# Tests for normalize_personnummer

def test_normalize_personnummer_valid():
    assert functions.normalize_personnummer(" 19900101-1234 ") == "199001011234"
    assert functions.normalize_personnummer("900101-1234") == "199001011234"


def test_normalize_personnummer_invalid():
    with pytest.raises(ValueError):
        functions.normalize_personnummer("abc")


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
        (
            "Test",
            functions.hash_value("test@example.com"),
            functions.hash_value("secret"),
            functions.hash_value("199001011234"),
        ),
    )
    conn.commit()
    conn.close()


@pytest.mark.parametrize(
    "pnr_input",
    ["199001011234", "19900101-1234", "900101-1234"],
)
def test_login_success(tmp_path, monkeypatch, pnr_input):
    setup_user(tmp_path, monkeypatch)
    with main.app.test_client() as client:
        response = client.post("/login", data={"personnummer": pnr_input, "password": "secret"})
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

    user_dir = tmp_path / functions.hash_value("199001011234")
    user_dir.mkdir()
    (user_dir / "own.pdf").write_text("test")

    other_dir = tmp_path / functions.hash_value("200001011234")
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


@pytest.mark.parametrize(
    "pnr_input",
    ["199001011234", "19900101-1234", "900101-1234"],
)
def test_admin_upload_creates_pending_user(tmp_path, monkeypatch, pnr_input):
    db_path = setup_db(tmp_path, monkeypatch)
    monkeypatch.setitem(main.app.config, "UPLOAD_ROOT", tmp_path)

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "new@example.com",
        "username": "New User",
        "personnummer": pnr_input,
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with main.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.post("/admin", data=data, content_type="multipart/form-data")
        assert response.status_code == 200
        resp_json = response.get_json()
        assert resp_json["status"] == "success"
        assert (
            resp_json["link"]
            == f"/create_user/{functions.normalize_personnummer(pnr_input)}"
        )

    pnr_norm = functions.normalize_personnummer(pnr_input)
    expected_dir = functions.hash_value(pnr_norm)

    # Verify file saved
    user_dir = tmp_path / expected_dir
    files = list(user_dir.glob("*.pdf"))
    assert len(files) == 1

    # Verify database entry contains hashed personnummer and pdf_path
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT personnummer, pdf_path FROM pending_users WHERE email=?",
        (functions.hash_value("new@example.com"),),
    )
    row = cursor.fetchone()
    conn.close()
    assert row is not None
    assert row[0] == expected_dir
    assert row[1].endswith(files[0].name)


def test_admin_upload_existing_user_only_saves_pdf(tmp_path, monkeypatch):
    db_path = setup_db(tmp_path, monkeypatch)
    monkeypatch.setitem(main.app.config, "UPLOAD_ROOT", tmp_path)

    # Lägg till befintlig användare
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Existing",
            functions.hash_value("exist@example.com"),
            functions.hash_value("secret"),
            functions.hash_value("199001011234"),
        ),
    )
    conn.commit()
    conn.close()

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "exist@example.com",
        "username": "Existing",
        "personnummer": "19900101-1234",
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with main.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.post("/admin", data=data, content_type="multipart/form-data")
        assert response.status_code == 200
        assert response.get_json()["status"] == "success"


def test_user_create_hashes_password(tmp_path, monkeypatch):
    db_path = setup_db(tmp_path, monkeypatch)

    # Lägg till pending user
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO pending_users (email, username, personnummer, pdf_path) VALUES (?, ?, ?, ?)",
        (
            functions.hash_value("user@example.com"),
            "User",
            functions.hash_value("199001011234"),
            "doc.pdf",
        ),
    )
    conn.commit()
    conn.close()

    assert functions.user_create_user("mypassword", "199001011234")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password FROM users WHERE personnummer = ?",
        (functions.hash_value("199001011234"),),
    )
    row = cursor.fetchone()
    conn.close()
    assert row is not None
    assert row[0] == functions.hash_value("mypassword")


def test_logout_clears_user_session(tmp_path, monkeypatch):
    setup_user(tmp_path, monkeypatch)
    with main.app.test_client() as client:
        client.post("/login", data={"personnummer": "199001011234", "password": "secret"})
        with client.session_transaction() as sess:
            assert sess.get("user_logged_in")
        client.get("/logout")
        with client.session_transaction() as sess:
            assert "user_logged_in" not in sess
            assert "personnummer" not in sess


def test_logout_clears_admin_session(tmp_path, monkeypatch):
    setup_user(tmp_path, monkeypatch)
    with main.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        client.get("/logout")
        with client.session_transaction() as sess:
            assert "admin_logged_in" not in sess
