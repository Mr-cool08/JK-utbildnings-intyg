import os
import sqlite3
import sys

import pytest

# Ensure project root on path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import functions


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Create a temporary database and patch sqlite3 to use it."""
    db_path = tmp_path / "test.db"
    real_connect = sqlite3.connect

    def connect_stub(_):
        return real_connect(db_path)

    monkeypatch.setattr(functions, "DB_PATH", str(db_path))
    monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
    functions.create_database()
    functions.verify_certificate.cache_clear()
    return db_path


def test_verify_certificate_existing_user(tmp_db):
    """verify_certificate should return True when a user exists."""
    conn = sqlite3.connect(tmp_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Test",
            functions.hash_value("user@example.com"),
            functions.hash_password("secret"),
            functions.hash_value("199001011234"),
        ),
    )
    conn.commit()
    conn.close()

    assert functions.verify_certificate("199001011234")


def test_check_user_exists(tmp_db):
    """check_user_exists should detect whether an email is registered."""
    email = "tester@example.com"
    conn = sqlite3.connect(tmp_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Tester",
            functions.hash_value(email),
            functions.hash_password("pass"),
            functions.hash_value("199001011234"),
        ),
    )
    conn.commit()
    conn.close()

    assert functions.check_user_exists(email)
    assert not functions.check_user_exists("unknown@example.com")
