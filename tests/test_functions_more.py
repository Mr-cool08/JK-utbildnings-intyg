import os
import sys
import sqlite3
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

def test_check_pending_user_hash_missing(tmp_db):
    assert not functions.check_pending_user_hash("missinghash")

def test_admin_create_user_single_pdf(tmp_db):
    email = "user@example.com"
    username = "User"
    pnr = "19900101-1234"
    pdf = "doc.pdf"
    assert functions.admin_create_user(email, username, pnr, pdf)
    conn = sqlite3.connect(tmp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT email, pdf_path FROM pending_users")
    row = cursor.fetchone()
    conn.close()
    assert row[0] == functions.hash_value(email)
    assert row[1] == pdf

def test_check_password_user_nonexistent(tmp_db):
    assert not functions.check_password_user("no@example.com", "secret")

def test_get_username_nonexistent(tmp_db):
    assert functions.get_username("no@example.com") is None

def test_create_database_creates_tables(tmp_db):
    conn = sqlite3.connect(tmp_db)
    cursor = conn.cursor()
    for table in ["pending_users", "users"]:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
        assert cursor.fetchone() is not None
    conn.close()

def test_verify_certificate_not_found(tmp_db):
    functions.verify_certificate.cache_clear()
    assert not functions.verify_certificate("19900101-1234")

def test_user_create_user_no_pending(tmp_db):
    pnr_hash = functions.hash_value("199001011234")
    assert not functions.user_create_user("pass", pnr_hash)
