import os
import sys

from sqlalchemy.exc import OperationalError

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import functions  # noqa: E402


def test_check_pending_user_hash_missing(empty_db):
    assert not functions.check_pending_user_hash("missinghash")


def test_admin_create_user_single_pdf(empty_db):
    email = "user@example.com"
    username = "User"
    pnr = "19900101-1234"
    assert functions.admin_create_user(email, username, pnr)
    with empty_db.connect() as conn:
        row = conn.execute(functions.pending_users_table.select()).first()
    assert row.email == functions.hash_value(email)
    assert row.username == username


def test_check_password_user_nonexistent(empty_db):
    assert not functions.check_password_user("no@example.com", "secret")


def test_get_username_nonexistent(empty_db):
    assert functions.get_username("no@example.com") is None


def test_create_database_creates_tables(empty_db):
    with empty_db.connect() as conn:
        for table in [functions.pending_users_table, functions.users_table, functions.user_pdfs_table]:
            result = conn.execute(table.select().limit(0))
            assert result is not None


def test_verify_certificate_not_found(empty_db):
    functions.verify_certificate.cache_clear()
    assert not functions.verify_certificate("19900101-1234")


def test_user_create_user_no_pending(empty_db):
    pnr_hash = functions.hash_value("199001011234")
    assert not functions.user_create_user("pass", pnr_hash)


def test_create_database_auto_creates_postgres(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql://appuser:secret@localhost/appdb"
    )
    functions.reset_engine()

    events = []

    class FakeOrig:
        pgcode = "3D000"
        sqlstate = "3D000"

        def __str__(self):
            return "database \"appdb\" does not exist"

    class DummyConnection:
        def __init__(self, label):
            self.label = label

        def __enter__(self):
            events.append(("enter", self.label))
            return self

        def __exit__(self, exc_type, exc, tb):
            events.append(("exit", self.label))

        def execute(self, statement):
            events.append(("execute", self.label, str(statement)))
            return None

    class DummyEngine:
        def __init__(self, label, fail=False):
            self.label = label
            self._fail = fail

        def connect(self):
            events.append(("connect", self.label))
            if self._fail:
                raise OperationalError("CONNECT", {}, FakeOrig())
            return DummyConnection(self.label)

        def dispose(self):
            events.append(("dispose", self.label))

    primary_calls = {"count": 0}

    def fake_create_engine(url_obj, **kwargs):
        assert kwargs.get("future") is True
        db_name = url_obj.database
        if db_name == "appdb":
            primary_calls["count"] += 1
            fail = primary_calls["count"] == 1
            return DummyEngine("primary", fail=fail)
        if db_name == "postgres":
            assert kwargs.get("isolation_level") == "AUTOCOMMIT"
            return DummyEngine("admin")
        raise AssertionError(f"Unexpected database {db_name}")

    monkeypatch.setattr(functions, "create_engine", fake_create_engine)

    created_with = {}

    def fake_create_all(engine):
        created_with["engine"] = engine

    monkeypatch.setattr(functions.metadata, "create_all", fake_create_all)

    functions.create_database()
    functions.reset_engine()

    assert created_with["engine"].label == "primary"
    assert ("execute", "admin", 'CREATE DATABASE "appdb"') in events
    assert primary_calls["count"] == 2
