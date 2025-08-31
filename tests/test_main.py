import io
import os
import sys

import pytest
import sqlite3
from werkzeug.datastructures import FileStorage

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import app
import functions

import werkzeug
if not hasattr(werkzeug, "__version__"):
    werkzeug.__version__ = "3.0.0"

# Tests for normalize_personnummer

def test_normalize_personnummer_valid():
    assert functions.normalize_personnummer(" 19900101-1234 ") == "199001011234"
    assert functions.normalize_personnummer("900101-1234") == "199001011234"


def test_normalize_personnummer_invalid():
    with pytest.raises(ValueError):
        functions.normalize_personnummer("abc")


# Tests for save_pdf_for_user

def test_save_pdf_for_user(tmp_path, monkeypatch):
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)

    pdf_bytes = b"%PDF-1.4 test"
    file_storage = FileStorage(
        stream=io.BytesIO(pdf_bytes),
        filename="test.pdf",
        content_type="application/pdf",
    )

    rel_path = app.save_pdf_for_user("19900101-1234", file_storage)

    abs_path = os.path.abspath(os.path.join(app.APP_ROOT, rel_path))
    assert os.path.exists(abs_path)
    with open(abs_path, "rb") as f:
        assert f.read() == pdf_bytes


def setup_user(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"

    real_connect = sqlite3.connect

    def connect_stub(_):
        return real_connect(db_path)

    monkeypatch.setattr(app.functions.sqlite3, "connect", connect_stub)
    import functions
    monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
    app.app.secret_key = "test-secret"

    functions.create_database()
    conn = real_connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Test",
            functions.hash_value("test@example.com"),
            functions.hash_password("secret"),
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
    with app.app.test_client() as client:
        response = client.post("/login", data={"personnummer": pnr_input, "password": "secret"})
        assert response.status_code == 302


def test_login_failure(tmp_path, monkeypatch):
    setup_user(tmp_path, monkeypatch)
    with app.app.test_client() as client:
        response = client.post(
            "/login", data={"personnummer": "199001011234", "password": "wrong"}
        )
        assert response.status_code == 401


def test_dashboard_shows_only_user_pdfs(tmp_path, monkeypatch):
    setup_user(tmp_path, monkeypatch)
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)

    user_dir = tmp_path / functions.hash_value("199001011234")
    user_dir.mkdir()
    (user_dir / "own.pdf").write_text("test")

    other_dir = tmp_path / functions.hash_value("200001011234")
    other_dir.mkdir()
    (other_dir / "other.pdf").write_text("test")

    with app.app.test_client() as client:
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

    monkeypatch.setattr(app.functions.sqlite3, "connect", connect_stub)
    import functions
    monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
    app.app.secret_key = "test-secret"

    functions.create_database()
    return db_path


@pytest.mark.parametrize(
    "pnr_input",
    ["199001011234", "19900101-1234", "900101-1234"],
)
def test_admin_upload_creates_pending_user(tmp_path, monkeypatch, pnr_input):
    db_path = setup_db(tmp_path, monkeypatch)
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)

    # Configure a dummy SMTP implementation to capture emails
    sent_emails = []

    class DummySMTP:
        def __init__(self, server, port):
            self.server = server
            self.port = port

        def starttls(self):
            pass

        def login(self, user, password):
            self.login = (user, password)

        def sendmail(self, from_addr, to_addr, msg):
            sent_emails.append((from_addr, to_addr, msg))

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

    monkeypatch.setattr(app, "SMTP", DummySMTP)
    monkeypatch.setenv("smtp_server", "smtp.test")
    monkeypatch.setenv("smtp_port", "587")
    monkeypatch.setenv("smtp_user", "no-reply@example.com")
    monkeypatch.setenv("smtp_password", "secret")

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "new@example.com",
        "username": "New User",
        "personnummer": pnr_input,
        "pdf": [
            (io.BytesIO(pdf_bytes), "doc.pdf"),
            (io.BytesIO(pdf_bytes), "doc2.pdf"),
        ],
    }

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.post("/admin", data=data, content_type="multipart/form-data")
        assert response.status_code == 200
        resp_json = response.get_json()
        assert resp_json["status"] == "success"
        expected_link = (
            f"http://localhost/create_user/{functions.hash_value(functions.normalize_personnummer(pnr_input))}"
        )
        assert resp_json["link"] == expected_link

    # Ensure an email was sent with the correct link
    assert sent_emails, "No email was sent"
    from_addr, to_addr, msg = sent_emails[0]
    assert from_addr == "no-reply@example.com"
    assert to_addr == "new@example.com"
    from email import message_from_string
    email_msg = message_from_string(msg)
    body = email_msg.get_payload(decode=True).decode()
    assert expected_link in body

    pnr_norm = functions.normalize_personnummer(pnr_input)
    expected_dir = functions.hash_value(pnr_norm)

    # Verify files saved
    user_dir = tmp_path / expected_dir
    files = sorted(f.name for f in user_dir.glob("*.pdf"))
    assert len(files) == 2

    # Verify database entry contains hashed personnummer and pdf paths
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
    stored = sorted(os.path.basename(p) for p in row[1].split(';'))
    assert stored == files


def test_admin_upload_email_login_failure(tmp_path, monkeypatch):
    db_path = setup_db(tmp_path, monkeypatch)
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)

    class FailingSMTP:
        def __init__(self, server, port):
            pass

        def starttls(self):
            pass

        def login(self, user, password):
            from smtplib import SMTPAuthenticationError

            raise SMTPAuthenticationError(535, b"auth failed")

        def sendmail(self, from_addr, to_addr, msg):
            raise AssertionError("sendmail should not be called")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            pass

    monkeypatch.setattr(app, "SMTP", FailingSMTP)
    monkeypatch.setenv("smtp_server", "smtp.test")
    monkeypatch.setenv("smtp_port", "587")
    monkeypatch.setenv("smtp_user", "no-reply@example.com")
    monkeypatch.setenv("smtp_password", "wrong")

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "new@example.com",
        "username": "New User",
        "personnummer": "19900101-1234",
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.post("/admin", data=data, content_type="multipart/form-data")
        assert response.status_code == 500
        resp_json = response.get_json()
        assert resp_json["status"] == "error"
        assert "SMTP-inloggning misslyckades" in resp_json["message"]


def test_admin_upload_email_connection_failure(tmp_path, monkeypatch):
    db_path = setup_db(tmp_path, monkeypatch)
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)

    class FailingSMTP:
        def __init__(self, server, port):
            raise OSError("Name or service not known")

    monkeypatch.setattr(app, "SMTP", FailingSMTP)
    monkeypatch.setenv("smtp_server", "smtp.invalid")
    monkeypatch.setenv("smtp_port", "587")
    monkeypatch.setenv("smtp_user", "no-reply@example.com")
    monkeypatch.setenv("smtp_password", "secret")

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        "email": "new@example.com",
        "username": "New User",
        "personnummer": "19900101-1234",
        "pdf": (io.BytesIO(pdf_bytes), "doc.pdf"),
    }

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.post("/admin", data=data, content_type="multipart/form-data")
        assert response.status_code == 500
        resp_json = response.get_json()
        assert resp_json["status"] == "error"
        assert "Det gick inte att ansluta till e-postservern" in resp_json["message"]


def test_admin_upload_existing_user_only_saves_pdf(tmp_path, monkeypatch):
    db_path = setup_db(tmp_path, monkeypatch)
    monkeypatch.setitem(app.app.config, "UPLOAD_ROOT", tmp_path)

    # Lägg till befintlig användare
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Existing",
            functions.hash_value("exist@example.com"),
            functions.hash_password("secret"),
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

    with app.app.test_client() as client:
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

    assert functions.user_create_user(
        "mypassword", functions.hash_value("199001011234")
    )

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password FROM users WHERE personnummer = ?",
        (functions.hash_value("199001011234"),),
    )
    row = cursor.fetchone()
    conn.close()
    assert row is not None
    assert functions.verify_password(row[0], "mypassword")


def test_logout_clears_user_session(tmp_path, monkeypatch):
    setup_user(tmp_path, monkeypatch)
    with app.app.test_client() as client:
        client.post("/login", data={"personnummer": "199001011234", "password": "secret"})
        with client.session_transaction() as sess:
            assert sess.get("user_logged_in")
        client.get("/logout")
        with client.session_transaction() as sess:
            assert "user_logged_in" not in sess
            assert "personnummer" not in sess


def test_logout_clears_admin_session(tmp_path, monkeypatch):
    setup_user(tmp_path, monkeypatch)
    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        client.get("/logout")
        with client.session_transaction() as sess:
            assert "admin_logged_in" not in sess


def test_custom_404_page():
    """Ensure unknown routes return the custom 404 page."""
    with app.app.test_client() as client:
        response = client.get("/this-page-does-not-exist")
        assert response.status_code == 404
        assert b"Sidan du letade efter" in response.data


def test_create_user_route_moves_pending_user(tmp_path, monkeypatch):
    db_path = setup_db(tmp_path, monkeypatch)
    # Skapa en pending user som sedan ska aktiveras
    functions.admin_create_user(
        "user@example.com", "User", "19900101-1234", "doc.pdf"
    )
    pnr_hash = functions.hash_value("199001011234")

    with app.app.test_client() as client:
        resp = client.get(f"/create_user/{pnr_hash}")
        assert resp.status_code == 200
        assert "Skapa konto" in resp.get_data(as_text=True)

        resp = client.post(f"/create_user/{pnr_hash}", data={"password": "newpass"})
        assert resp.status_code == 302

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE personnummer = ?", (pnr_hash,))
    assert cursor.fetchone() is not None
    cursor.execute("SELECT 1 FROM pending_users WHERE personnummer = ?", (pnr_hash,))
    assert cursor.fetchone() is None
    conn.close()
