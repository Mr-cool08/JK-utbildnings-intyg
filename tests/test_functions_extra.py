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

def test_hash_value_deterministic():
    h1 = functions.hash_value("hello")
    h2 = functions.hash_value("hello")
    h3 = functions.hash_value("world")
    assert h1 == h2
    assert h1 != h3

def test_hash_password_verify():
    hashed = functions.hash_password("s3cret")
    assert functions.verify_password(hashed, "s3cret")
    assert not functions.verify_password(hashed, "wrong")

def test_check_pending_user_and_hash(tmp_db):
    functions.admin_create_user("e@example.com", "User", "19900101-1234", "doc.pdf")
    assert functions.check_pending_user("19900101-1234")
    pnr_hash = functions.hash_value("199001011234")
    assert functions.check_pending_user_hash(pnr_hash)
    assert not functions.check_pending_user("20000101-1234")

def test_admin_create_user_duplicate(tmp_db):
    conn = sqlite3.connect(tmp_db)
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
    assert not functions.admin_create_user("exist@example.com", "Existing", "19900101-1234", "doc.pdf")

def test_check_personnummer_password(tmp_db):
    conn = sqlite3.connect(tmp_db)
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
    assert functions.check_personnummer_password("19900101-1234", "secret")
    assert not functions.check_personnummer_password("19900101-1234", "wrong")

def test_get_user_info(tmp_db):
    conn = sqlite3.connect(tmp_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Info",
            functions.hash_value("info@example.com"),
            functions.hash_password("pass"),
            functions.hash_value("199001011234"),
        ),
    )
    conn.commit()
    conn.close()
    user = functions.get_user_info("19900101-1234")
    assert user[1] == "Info"
    assert user[2] == functions.hash_value("info@example.com")

def test_user_create_user_fails_if_exists(tmp_db):
    pnr_hash = functions.hash_value("199001011234")
    conn = sqlite3.connect(tmp_db)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Existing",
            functions.hash_value("exist@example.com"),
            functions.hash_password("secret"),
            pnr_hash,
        ),
    )
    conn.commit()
    conn.close()
    assert not functions.user_create_user("newpass", pnr_hash)

def test_hash_value_uniqueness_stress():
    values = {functions.hash_value(f"value{i}") for i in range(20)}
    assert len(values) == 20
