import sqlite3
import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import functions


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    real_connect = sqlite3.connect

    def connect_stub(_):
        return real_connect(db_path)

    monkeypatch.setattr(functions, "DB_PATH", str(db_path))
    monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
    functions.create_database()
    return db_path


def test_check_user_exists(tmp_db):
    email = "exists@example.com"
    conn = sqlite3.connect(tmp_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Exists",
            functions.hash_value(email),
            functions.hash_password("pass"),
            functions.hash_value("199001011234"),
        ),
    )
    conn.commit()
    conn.close()

    assert functions.check_user_exists(email)
    assert not functions.check_user_exists("missing@example.com")


def test_user_create_user_success(tmp_db):
    email = "new@example.com"
    username = "NewUser"
    personnummer = "19900101-1234"
    pdf_path = "doc.pdf"

    assert functions.admin_create_user(email, username, personnummer, pdf_path)

    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("secret", pnr_hash)

    conn = sqlite3.connect(tmp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM pending_users WHERE personnummer = ?", (pnr_hash,))
    assert cursor.fetchone() is None
    cursor.execute("SELECT email, username FROM users WHERE personnummer = ?", (pnr_hash,))
    row = cursor.fetchone()
    conn.close()

    assert row == (functions.hash_value(email), username)
    assert functions.check_user_exists(email)

