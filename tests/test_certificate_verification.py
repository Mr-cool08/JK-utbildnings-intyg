import os
import sqlite3
import sys
import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import app
import functions


def setup_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    real_connect = sqlite3.connect
    calls = {"count": 0}

    def connect_stub(_):
        calls["count"] += 1
        return real_connect(db_path)

    monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
    monkeypatch.setattr(app.functions, "sqlite3", functions.sqlite3)
    app.app.secret_key = "test-secret"
    functions.create_database()
    calls["count"] = 0
    return db_path, calls


def test_verify_certificate_caching_and_message(tmp_path, monkeypatch):
    _, calls = setup_db(tmp_path, monkeypatch)
    functions.verify_certificate.cache_clear()

    assert not functions.verify_certificate("19900101-1234")
    assert not functions.verify_certificate("19900101-1234")
    assert calls["count"] == 1

    with app.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["admin_logged_in"] = True
        response = client.get("/verify_certificate/19900101-1234")
        assert response.status_code == 404
        assert b"not verified" in response.data.lower()
        # No additional DB call due to caching
        assert calls["count"] == 1
