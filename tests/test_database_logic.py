import os
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, insert, inspect as sqlalchemy_inspect, select
from sqlalchemy.exc import IntegrityError, OperationalError

import functions
import functions.database as database_module


def _postgres_engine(host="postgres"):
    return SimpleNamespace(
        url=SimpleNamespace(
            get_backend_name=lambda: "postgresql",
            host=host,
            set=lambda **kwargs: SimpleNamespace(
                render_as_string=lambda hide_password=False: (
                    f"postgresql://user:pass@{kwargs['host']}:5432/testdb"
                )
            ),
        )
    )


def _dns_error():
    return OperationalError(
        "SELECT 1",
        {},
        Exception('could not translate host name "postgres" to address'),
    )


def test_run_migrations_creates_schema_migrations_table(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    monkeypatch.setattr(database_module, "MIGRATIONS", [])

    database_module.run_migrations(engine)

    inspector = sqlalchemy_inspect(engine)
    assert database_module.schema_migrations_table.name in inspector.get_table_names()


def test_run_migrations_skips_applied_versions(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)

    with engine.begin() as conn:
        database_module.schema_migrations_table.create(bind=conn)
        conn.execute(
            insert(database_module.schema_migrations_table).values(version="0001_dummy")
        )

    applied = []

    def _migration_0001(_conn):
        applied.append("0001_dummy")

    def _migration_0002(_conn):
        applied.append("0002_dummy")

    monkeypatch.setattr(
        database_module,
        "MIGRATIONS",
        [("0001_dummy", _migration_0001), ("0002_dummy", _migration_0002)],
    )

    database_module.run_migrations(engine)

    with engine.connect() as conn:
        versions = conn.execute(
            select(database_module.schema_migrations_table.c.version)
        ).scalars().all()

    assert applied == ["0002_dummy"]
    assert set(versions) == {"0001_dummy", "0002_dummy"}


def test_migration_0004_raises_for_unsupported_dialect(monkeypatch):
    class _FakeConn:
        dialect = SimpleNamespace(name="mysql")

    monkeypatch.setattr(
        database_module,
        "inspect",
        lambda _conn: SimpleNamespace(
            get_table_names=lambda: [functions.company_users_table.name],
            get_columns=lambda _table: [{"name": "company_id", "nullable": False}],
        ),
    )

    with pytest.raises(RuntimeError, match="stöder inte dialekten 'mysql'"):
        database_module._migration_0004_make_company_id_nullable(_FakeConn())


def test_create_database_backfills_columns_and_aux_tables(monkeypatch):
    executed_sql = []
    created_tables = []

    class _FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, statement, *_args, **_kwargs):
            executed_sql.append(str(statement))
            return None

    class _FakeEngine:
        url = SimpleNamespace(get_backend_name=lambda: "sqlite")

        def begin(self):
            return _FakeConn()

    def _record_create(table_name):
        def _create(**_kwargs):
            created_tables.append(table_name)

        return _create

    monkeypatch.setattr(database_module, "get_engine", lambda: _FakeEngine())
    monkeypatch.setattr(database_module.metadata, "create_all", lambda _engine: None)
    monkeypatch.setattr(database_module, "run_migrations", lambda _engine: None)
    monkeypatch.setattr(
        database_module,
        "inspect",
        lambda _conn: SimpleNamespace(
            get_columns=lambda _table: [{"name": "id"}],
            get_table_names=lambda: [functions.user_pdfs_table.name],
        ),
    )
    monkeypatch.setattr(
        database_module.password_resets_table,
        "create",
        _record_create("password_resets"),
    )
    monkeypatch.setattr(
        database_module.supervisor_password_resets_table,
        "create",
        _record_create("supervisor_password_resets"),
    )
    monkeypatch.setattr(
        database_module.admin_audit_log_table,
        "create",
        _record_create("admin_audit_log"),
    )

    database_module.create_database()

    assert any("ADD COLUMN categories" in sql for sql in executed_sql)
    assert any("ADD COLUMN note" in sql for sql in executed_sql)
    assert set(created_tables) == {
        "password_resets",
        "supervisor_password_resets",
        "admin_audit_log",
    }


def test_create_database_falls_back_to_sqlite_in_dev_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_INIT_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/testdb")
    monkeypatch.setenv("LOCAL_TEST_DB_PATH", str(tmp_path / "dev-fallback.db"))
    monkeypatch.setattr(database_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        database_module,
        "_switch_postgres_host_after_dns_error",
        lambda _engine, _exc: False,
    )
    monkeypatch.setattr(database_module, "run_migrations", lambda _engine: None)

    class _FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, *_args, **_kwargs):
            return None

    class _FakeEngine:
        def __init__(self, backend_name):
            self.url = SimpleNamespace(get_backend_name=lambda: backend_name)

        def begin(self):
            return _FakeConn()

    def _current_engine():
        db_url = os.getenv("DATABASE_URL", "")
        backend_name = "sqlite" if db_url.startswith("sqlite") else "postgresql"
        return _FakeEngine(backend_name)

    attempted_backends = []

    def _fake_create_all(engine):
        backend_name = engine.url.get_backend_name()
        attempted_backends.append(backend_name)
        if backend_name == "postgresql":
            raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    reset_calls = []
    monkeypatch.setattr(database_module, "get_engine", _current_engine)
    monkeypatch.setattr(database_module.metadata, "create_all", _fake_create_all)
    monkeypatch.setattr(database_module, "reset_engine", lambda: reset_calls.append(True))
    monkeypatch.setattr(
        database_module,
        "inspect",
        lambda _conn: SimpleNamespace(
            get_columns=lambda _table: [{"name": "categories"}, {"name": "note"}],
            get_table_names=lambda: [
                functions.password_resets_table.name,
                functions.supervisor_password_resets_table.name,
                functions.admin_audit_log_table.name,
            ],
        ),
    )

    database_module.create_database()

    assert attempted_backends == ["postgresql", "postgresql", "sqlite"]
    assert reset_calls == [True]
    assert os.environ["DATABASE_URL"].startswith("sqlite:///")
    assert "dev-fallback.db" in os.environ["DATABASE_URL"]


def test_create_database_does_not_fallback_to_sqlite_without_dev_mode(monkeypatch):
    monkeypatch.setenv("DATABASE_INIT_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("DEV_MODE", "false")
    database_url = "postgresql://user:pass@postgres:5432/testdb"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(database_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        database_module,
        "_switch_postgres_host_after_dns_error",
        lambda _engine, _exc: False,
    )

    class _FakeEngine:
        url = SimpleNamespace(get_backend_name=lambda: "postgresql")

    attempts = []

    def _always_fail(_engine):
        attempts.append(1)
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    reset_calls = []
    monkeypatch.setattr(database_module, "get_engine", lambda: _FakeEngine())
    monkeypatch.setattr(database_module.metadata, "create_all", _always_fail)
    monkeypatch.setattr(database_module, "reset_engine", lambda: reset_calls.append(True))

    with pytest.raises(OperationalError):
        database_module.create_database()

    assert len(attempts) == 2
    assert reset_calls == []
    assert os.environ["DATABASE_URL"] == database_url


def test_switch_postgres_host_returns_false_without_fallback_hosts(monkeypatch):
    monkeypatch.delenv("POSTGRES_FALLBACK_HOSTS", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/testdb")
    monkeypatch.setattr(database_module, "reset_engine", lambda: None)

    switched = database_module._switch_postgres_host_after_dns_error(
        _postgres_engine(),
        _dns_error(),
    )

    assert switched is False
    assert os.environ["DATABASE_URL"] == "postgresql://user:pass@postgres:5432/testdb"


def test_switch_postgres_host_returns_false_for_non_dns_error(monkeypatch):
    monkeypatch.setenv("POSTGRES_FALLBACK_HOSTS", "localhost,127.0.0.1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/testdb")
    monkeypatch.setattr(database_module, "reset_engine", lambda: None)

    switched = database_module._switch_postgres_host_after_dns_error(
        _postgres_engine(),
        OperationalError("SELECT 1", {}, Exception("timeout")),
    )

    assert switched is False
    assert os.environ["DATABASE_URL"] == "postgresql://user:pass@postgres:5432/testdb"


@pytest.mark.parametrize(
    "message",
    [
        '[Errno -2] Name or service not known',
        '[Errno -3] Temporary failure in name resolution',
        '[Errno 11001] getaddrinfo failed',
        'nodename nor servname provided, or not known',
    ],
)
def test_switch_postgres_host_handles_platform_specific_dns_errors(monkeypatch, message):
    monkeypatch.setenv("POSTGRES_FALLBACK_HOSTS", "localhost,127.0.0.1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/testdb")
    monkeypatch.setattr(database_module, "reset_engine", lambda: None)

    switched = database_module._switch_postgres_host_after_dns_error(
        _postgres_engine(),
        OperationalError("SELECT 1", {}, Exception(message)),
    )

    assert switched is True
    assert os.environ["DATABASE_URL"] == "postgresql://user:pass@localhost:5432/testdb"


def test_switch_postgres_host_returns_false_when_only_current_host_is_listed(monkeypatch):
    monkeypatch.setenv("POSTGRES_FALLBACK_HOSTS", "postgres")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/testdb")
    monkeypatch.setattr(database_module, "reset_engine", lambda: None)

    switched = database_module._switch_postgres_host_after_dns_error(
        _postgres_engine(host="postgres"),
        _dns_error(),
    )

    assert switched is False
    assert os.environ["DATABASE_URL"] == "postgresql://user:pass@postgres:5432/testdb"


def test_company_users_unique_constraint_blocks_duplicate_email_role(empty_db):
    with empty_db.begin() as conn:
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=None,
                role="standard",
                name="Första Användaren",
                email="duplicat@example.com",
            )
        )
        with pytest.raises(IntegrityError):
            conn.execute(
                functions.company_users_table.insert().values(
                    company_id=None,
                    role="standard",
                    name="Andra Användaren",
                    email="duplicat@example.com",
                )
            )


def test_company_users_allows_same_email_for_different_roles(empty_db):
    with empty_db.begin() as conn:
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=None,
                role="standard",
                name="Standardkonto",
                email="delad@example.com",
            )
        )
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=1,
                role="foretagskonto",
                name="Företagskonto",
                email="delad@example.com",
            )
        )

    with empty_db.connect() as conn:
        rows = conn.execute(
            functions.company_users_table.select().where(
                functions.company_users_table.c.email == "delad@example.com"
            )
        ).fetchall()

    assert len(rows) == 2
    assert {row.role for row in rows} == {"standard", "foretagskonto"}


def test_build_engine_requires_postgres_user_when_host_is_set(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.delenv("ENABLE_DEMO_MODE", raising=False)
    monkeypatch.setenv("POSTGRES_HOST", "postgres")
    monkeypatch.delenv("POSTGRES_USER", raising=False)
    monkeypatch.setenv("POSTGRES_DB", "jk")

    with pytest.raises(RuntimeError, match="POSTGRES_USER"):
        database_module._build_engine()


def test_build_engine_requires_postgres_db_when_host_is_set(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DEV_MODE", raising=False)
    monkeypatch.delenv("ENABLE_DEMO_MODE", raising=False)
    monkeypatch.setenv("POSTGRES_HOST", "postgres")
    monkeypatch.setenv("POSTGRES_USER", "jk")
    monkeypatch.delenv("POSTGRES_DB", raising=False)

    with pytest.raises(RuntimeError, match="POSTGRES_DB"):
        database_module._build_engine()


# Copyright (c) Liam Suorsa and Mika Suorsa
