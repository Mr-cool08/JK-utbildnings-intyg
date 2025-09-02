import os
import sys
import sqlite3
import pytest
import werkzeug

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app
import functions

if not hasattr(werkzeug, "__version__"):
    werkzeug.__version__ = "3.0.0"


@pytest.fixture
def user_db(tmp_path, monkeypatch):
    """Create a temporary DB with a default user and patch connections."""
    db_path = tmp_path / "test.db"
    real_connect = sqlite3.connect

    def connect_stub(_):
        return real_connect(db_path)

    monkeypatch.setattr(app.functions.sqlite3, "connect", connect_stub)
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

    return db_path


@pytest.fixture
def empty_db(tmp_path, monkeypatch):
    """Create an empty temporary DB and patch connections."""
    db_path = tmp_path / "test.db"
    real_connect = sqlite3.connect

    def connect_stub(_):
        return real_connect(db_path)

    monkeypatch.setattr(app.functions.sqlite3, "connect", connect_stub)
    monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
    app.app.secret_key = "test-secret"
    functions.create_database()

    return db_path
