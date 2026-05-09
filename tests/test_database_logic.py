import os
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, insert, inspect as sqlalchemy_inspect, select, text
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


def test_migration_0010_sqlite_adds_indexes_and_duplicate_protection():
    engine = create_engine("sqlite:///:memory:", future=True)

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE pending_users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    personnummer TEXT NOT NULL UNIQUE,
                    orgnr_normalized TEXT DEFAULT NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    personnummer TEXT NOT NULL UNIQUE,
                    orgnr_normalized TEXT DEFAULT NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE supervisor_link_requests (
                    id INTEGER PRIMARY KEY,
                    supervisor_email TEXT NOT NULL,
                    user_personnummer TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE organization_link_requests (
                    id INTEGER PRIMARY KEY,
                    orgnr_normalized TEXT NOT NULL,
                    user_personnummer TEXT NOT NULL,
                    user_name TEXT NOT NULL,
                    user_email TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    handled_by_supervisor_email TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                    handled_at DATETIME
                )
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO pending_users (
                    username,
                    email,
                    personnummer,
                    orgnr_normalized
                ) VALUES (
                    'Pending Person',
                    'pending-hash',
                    'pending-pnr',
                    NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO users (
                    username,
                    email,
                    password,
                    personnummer,
                    orgnr_normalized
                ) VALUES (
                    'Active Person',
                    'active-hash',
                    'hashed-password',
                    'active-pnr',
                    NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO supervisor_link_requests (supervisor_email, user_personnummer)
                VALUES
                    ('chef@example.com', 'pnr-hash'),
                    ('chef@example.com', 'pnr-hash')
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT INTO organization_link_requests (
                    orgnr_normalized,
                    user_personnummer,
                    user_name,
                    user_email
                ) VALUES
                    ('5569668337', 'pnr-hash', 'Test Person', 'test@example.com'),
                    ('5569668337', 'pnr-hash', 'Test Person', 'test@example.com')
                """
            )
        )
        database_module._migration_0010_add_orgnr_to_users_and_org_requests(conn)

    inspector = sqlalchemy_inspect(engine)
    pending_columns = {
        column["name"]: column for column in inspector.get_columns("pending_users")
    }
    user_columns = {column["name"]: column for column in inspector.get_columns("users")}
    pending_indexes = inspector.get_indexes("pending_users")
    user_indexes = inspector.get_indexes("users")

    assert "orgnr_normalized" in pending_columns
    assert "orgnr_normalized" in user_columns
    assert pending_columns["orgnr_normalized"]["nullable"] is False
    assert user_columns["orgnr_normalized"]["nullable"] is False
    assert any(index["column_names"] == ["orgnr_normalized"] for index in pending_indexes)
    assert any(index["column_names"] == ["orgnr_normalized"] for index in user_indexes)

    with engine.begin() as conn:
        pending_row = conn.execute(text("SELECT orgnr_normalized FROM pending_users")).first()
        user_row = conn.execute(text("SELECT orgnr_normalized FROM users")).first()
        supervisor_rows = conn.execute(
            text("SELECT id FROM supervisor_link_requests")
        ).fetchall()
        organization_rows = conn.execute(
            text("SELECT id FROM organization_link_requests")
        ).fetchall()

        assert pending_row.orgnr_normalized == ""
        assert user_row.orgnr_normalized == ""
        assert len(supervisor_rows) == 1
        assert len(organization_rows) == 1

        with pytest.raises(IntegrityError):
            conn.execute(
                text(
                    """
                        INSERT INTO supervisor_link_requests (supervisor_email, user_personnummer)
                        VALUES ('chef@example.com', 'pnr-hash')
                        """
                    )
                )

        with pytest.raises(IntegrityError):
            conn.execute(
                text(
                    """
                        INSERT INTO organization_link_requests (
                            orgnr_normalized,
                            user_personnummer,
                            user_name,
                            user_email
                        ) VALUES (
                            '5569668337',
                            'pnr-hash',
                            'Test Person',
                            'test@example.com'
                        )
                        """
                    )
                )


def test_migration_0010_postgres_adds_missing_constraints_and_indexes(monkeypatch):
    class _FakeResult:
        def __init__(self, value):
            self._value = value

        def scalar_one_or_none(self):
            return self._value

    class _FakeConn:
        dialect = SimpleNamespace(name="postgresql")

        def __init__(self):
            self.executed_sql = []

        def execute(self, statement, parameters=None):
            sql = str(statement)
            self.executed_sql.append((sql, parameters))
            if "FROM pg_constraint" in sql:
                return _FakeResult(None)
            return SimpleNamespace()

    monkeypatch.setattr(
        database_module,
        "inspect",
        lambda _conn: SimpleNamespace(
            get_table_names=lambda: [
                functions.pending_users_table.name,
                functions.users_table.name,
                functions.supervisor_link_requests_table.name,
                functions.organization_link_requests_table.name,
            ],
            get_columns=lambda table_name: [{"name": "id"}]
            if table_name in {functions.pending_users_table.name, functions.users_table.name}
            else [{"name": "id"}, {"name": "user_personnummer"}],
            get_indexes=lambda _table_name: [],
            get_unique_constraints=lambda _table_name: [],
        ),
    )

    conn = _FakeConn()
    database_module._migration_0010_add_orgnr_to_users_and_org_requests(conn)

    executed_sql_texts = [sql for sql, _parameters in conn.executed_sql]
    assert (
        "ALTER TABLE pending_users ADD COLUMN orgnr_normalized TEXT DEFAULT '' NOT NULL"
        in executed_sql_texts
    )
    assert "ALTER TABLE users ADD COLUMN orgnr_normalized TEXT DEFAULT '' NOT NULL" in executed_sql_texts
    assert "UPDATE pending_users SET orgnr_normalized = '' WHERE orgnr_normalized IS NULL" in executed_sql_texts
    assert "UPDATE users SET orgnr_normalized = '' WHERE orgnr_normalized IS NULL" in executed_sql_texts
    assert (
        "CREATE INDEX IF NOT EXISTS ix_pending_users_orgnr_normalized "
        "ON pending_users (orgnr_normalized)"
    ) in executed_sql_texts
    assert (
        "CREATE INDEX IF NOT EXISTS ix_users_orgnr_normalized "
        "ON users (orgnr_normalized)"
    ) in executed_sql_texts
    assert any(
        "DELETE FROM supervisor_link_requests" in sql
        and "GROUP BY supervisor_email, user_personnummer" in sql
        for sql in executed_sql_texts
    )
    assert (
        "ALTER TABLE supervisor_link_requests "
        "ADD CONSTRAINT uq_supervisor_link_requests_pair "
        "UNIQUE (supervisor_email, user_personnummer)"
    ) in executed_sql_texts
    assert any(
        "DELETE FROM organization_link_requests" in sql
        and "GROUP BY orgnr_normalized, user_personnummer" in sql
        for sql in executed_sql_texts
    )
    assert (
        "ALTER TABLE organization_link_requests "
        "ADD CONSTRAINT uq_organization_link_requests_pair "
        "UNIQUE (orgnr_normalized, user_personnummer)"
    ) in executed_sql_texts

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
