import os
import sys
import sqlite3
import importlib
from pathlib import Path
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))
import functions
import main


@pytest.fixture
def app_factory(monkeypatch, tmp_path):
    def _factory(**env):
        for k, v in env.items():
            monkeypatch.setenv(k, str(v))
        db_path = tmp_path / "test.db"
        real_connect = sqlite3.connect

        def connect_stub(_):
            return real_connect(db_path)

        monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
        importlib.reload(main)
        app = main.app
        app.config.update(TESTING=True, PROPAGATE_EXCEPTIONS=False)
        upload_root = tmp_path / "uploads"
        os.makedirs(upload_root, exist_ok=True)
        app.config["UPLOAD_ROOT"] = upload_root
        app.secret_key = "test-secret"

        @app.route("/api/boom")
        def boom():  # type: ignore
            raise RuntimeError("boom")

        return app

    return _factory


@pytest.fixture
def app(app_factory):
    return app_factory()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def set_env(monkeypatch):
    def setter(envs):
        for k, v in envs.items():
            monkeypatch.setenv(k, str(v))
    return setter
