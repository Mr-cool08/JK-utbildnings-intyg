import os
import sqlite3

import pytest

import main
import functions


@pytest.fixture
def app(tmp_path, monkeypatch, request):
    env = getattr(request, "param", {})
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    db_path = tmp_path / "test.db"
    real_connect = sqlite3.connect

    def connect_stub(_):
        return real_connect(db_path)

    monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
    monkeypatch.setattr(main.functions.sqlite3, "connect", connect_stub)
    monkeypatch.setenv("SECRET_KEY", "test-secret")

    app = main.create_app()
    app.config["TESTING"] = True
    app.config["UPLOAD_ROOT"] = tmp_path / "uploads"
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def set_env(monkeypatch):
    def _set(**env):
        for k, v in env.items():
            monkeypatch.setenv(k, v)
    return _set
