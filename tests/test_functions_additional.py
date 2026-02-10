# Copyright (c) Liam Suorsa
import os
import sys
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import OperationalError

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import functions  # noqa: E402
import functions.database as database_module  # noqa: E402


def test_normalize_personnummer():
    assert functions.normalize_personnummer("19900101-1234") == "9001011234"
    assert functions.normalize_personnummer("199001011234") == "9001011234"
    assert functions.normalize_personnummer("9001011234") == "9001011234"
    with pytest.raises(ValueError):
        functions.normalize_personnummer("123")


def test_admin_and_user_create_flow(empty_db, monkeypatch):
    email = "new@example.com"
    username = "New"
    personnummer = "19900101-1234"

    assert functions.admin_create_user(email, username, personnummer)

    with empty_db.connect() as conn:
        pending_row = conn.execute(functions.pending_users_table.select()).first()
    assert pending_row is not None
    assert pending_row.email == functions.hash_value(email)
    assert pending_row.username == username

    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user("secret", pnr_hash)
    assert functions.check_user_exists(email)

    with empty_db.connect() as conn:
        pending_after = conn.execute(functions.pending_users_table.select()).first()
        user_row = conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.personnummer == pnr_hash
            )
        ).first()

    assert pending_after is None
    assert user_row is not None

    functions.verify_certificate.cache_clear()
    assert functions.verify_certificate(personnummer)

    def fail_get_engine():
        raise AssertionError("verify_certificate should use cached value")

    monkeypatch.setattr(functions, "get_engine", fail_get_engine)
    assert functions.verify_certificate(personnummer)


def test_dev_mode_creates_sqlite(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_HOST", raising=False)
    monkeypatch.delenv("POSTGRES_USER", raising=False)
    monkeypatch.delenv("POSTGRES_DB", raising=False)
    monkeypatch.setenv("DEV_MODE", "true")
    db_file = tmp_path / "lokal.db"
    monkeypatch.setenv("LOCAL_TEST_DB_PATH", str(db_file))

    functions.reset_engine()
    engine = functions.get_engine()

    try:
        assert engine.url.get_backend_name() == "sqlite"
        assert engine.url.database == str(db_file)
        assert db_file.parent.exists()
    finally:
        functions.reset_engine()


def test_demo_mode_creates_sqlite_without_dev_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_HOST", raising=False)
    monkeypatch.delenv("POSTGRES_USER", raising=False)
    monkeypatch.delenv("POSTGRES_DB", raising=False)
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.setenv("ENABLE_DEMO_MODE", "true")
    db_file = tmp_path / "demo.db"
    monkeypatch.setenv("LOCAL_TEST_DB_PATH", str(db_file))

    functions.reset_engine()
    engine = functions.get_engine()

    try:
        assert engine.url.get_backend_name() == "sqlite"
        assert engine.url.database == str(db_file)
        assert db_file.parent.exists()
    finally:
        functions.reset_engine()


def test_build_engine_skips_psycopg_when_import_fails(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/testdb")
    monkeypatch.setattr(
        functions.importlib.util, "find_spec", lambda name: object()
    )
    original_import_module = functions.importlib.import_module

    def fake_import_module(name):
        if name == "psycopg":
            raise ImportError("no pq wrapper available")
        return original_import_module(name)

    monkeypatch.setattr(functions.importlib, "import_module", fake_import_module)
    captured = {}

    def fake_create_engine(url, **_kwargs):
        captured["url"] = url
        return SimpleNamespace(url=url)

    monkeypatch.setattr(functions, "create_engine", fake_create_engine)
    engine = functions._build_engine()

    if engine.url.drivername != "postgresql":
        raise AssertionError("Expected postgresql drivername")
    if captured["url"].drivername != "postgresql":
        raise AssertionError("Expected postgresql drivername")


def test_create_database_retries_on_operational_error(monkeypatch):
    monkeypatch.setenv("DATABASE_INIT_MAX_ATTEMPTS", "3")
    state = {"attempts": 0}

    def fake_create_all(_engine):
        state["attempts"] += 1
        if state["attempts"] < 3:
            raise OperationalError("SELECT 1", {}, Exception("dns"))

    monkeypatch.setattr(database_module.metadata, "create_all", fake_create_all)
    monkeypatch.setattr(database_module, "run_migrations", lambda _engine: None)

    class _FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, *_args, **_kwargs):
            return None

    class _FakeEngine:
        def begin(self):
            return _FakeConn()

    monkeypatch.setattr(database_module, "get_engine", lambda: _FakeEngine())
    monkeypatch.setattr(database_module, "inspect", lambda _conn: SimpleNamespace(
        get_columns=lambda _table: [{"name": "categories"}],
        get_table_names=lambda: [
            functions.password_resets_table.name,
            functions.supervisor_password_resets_table.name,
            functions.admin_audit_log_table.name,
        ],
    ))
    monkeypatch.setattr(database_module.time, "sleep", lambda _seconds: None)

    database_module.create_database()

    assert state["attempts"] == 3
