import io
import os
import sqlite3
import pytest

import main
import functions


@pytest.fixture
def app(tmp_path, monkeypatch):
    db_path = tmp_path / 'test.db'

    def connect_stub(_):
        return sqlite3.connect(db_path)

    monkeypatch.setattr(main.sqlite3, 'connect', connect_stub)
    monkeypatch.setattr(functions.sqlite3, 'connect', connect_stub)
    monkeypatch.setenv('SECRET_KEY', 'test-secret')

    app = main.create_app()
    app.config.update(TESTING=True, UPLOAD_ROOT=str(tmp_path / 'uploads'))
    os.makedirs(app.config['UPLOAD_ROOT'], exist_ok=True)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def set_env(monkeypatch):
    def setter(**envs):
        for k, v in envs.items():
            monkeypatch.setenv(k, str(v))
    return setter
