import os
import sys
import sqlite3
import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _patch_sqlite(monkeypatch, tmp_path):
    db_path = tmp_path / "test.db"
    real_connect = sqlite3.connect

    def connect_stub(_=None, *args, **kwargs):
        return real_connect(db_path)

    monkeypatch.setattr(sqlite3, "connect", connect_stub)
    return db_path


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("FLASK_DEBUG", "0")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://example.com")

    _patch_sqlite(monkeypatch, tmp_path)

    import functions  # noqa: F401
    import main
    importlib.reload(functions)
    importlib.reload(main)

    app = main.app
    app.config.update(TESTING=True, UPLOAD_ROOT=str(tmp_path))
    functions.create_database()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def set_env(monkeypatch):
    def setter(**envs):
        for k, v in envs.items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, str(v))
    return setter
