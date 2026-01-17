# Copyright (c) Liam Suorsa
from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    case,
    create_engine as sqlalchemy_create_engine,
    func,
    insert,
    inspect,
    select,
    text,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.pool import StaticPool

from config_loader import load_environment
from functions.logging import configure_module_logger


logger = configure_module_logger(__name__)
logger.setLevel(logging.DEBUG)

if importlib.util.find_spec("pysqlite3") is not None:
    import sys

    import pysqlite3 as sqlite3

    sys.modules["sqlite3"] = sqlite3


load_environment()

APP_ROOT = str(Path(__file__).resolve().parent.parent)
logger.debug("Application root directory: %s", APP_ROOT)

metadata = MetaData()

pending_users_table = Table(
    "pending_users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, nullable=False),
    Column("email", String, nullable=False),
    Column("personnummer", String, nullable=False, unique=True),
)

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, nullable=False),
    Column("email", String, nullable=False, unique=True),
    Column("password", String, nullable=False),
    Column("personnummer", String, nullable=False, unique=True),
)

user_pdfs_table = Table(
    "user_pdfs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("personnummer", String, nullable=False, index=True),
    Column("filename", String, nullable=False),
    Column("content", LargeBinary, nullable=False),
    Column("categories", String, nullable=False, server_default=""),
    Column(
        "uploaded_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

pending_supervisors_table = Table(
    "pending_supervisors",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("email", String, nullable=False, unique=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

supervisors_table = Table(
    "supervisors",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("email", String, nullable=False, unique=True),
    Column("password", String, nullable=False),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

supervisor_connections_table = Table(
    "supervisor_connections",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("supervisor_email", String, nullable=False, index=True),
    Column("user_personnummer", String, nullable=False, index=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    UniqueConstraint(
        "supervisor_email",
        "user_personnummer",
        name="uq_supervisor_connections_pair",
    ),
)

supervisor_link_requests_table = Table(
    "supervisor_link_requests",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("supervisor_email", String, nullable=False, index=True),
    Column("user_personnummer", String, nullable=False, index=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    UniqueConstraint(
        "supervisor_email",
        "user_personnummer",
        name="uq_supervisor_link_requests_pair",
    ),
)

password_resets_table = Table(
    "password_resets",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("personnummer", String, nullable=False, index=True),
    Column("email", String, nullable=False),
    Column("token_hash", String, nullable=False, unique=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    Column("used_at", DateTime(timezone=True)),
)

admin_audit_log_table = Table(
    "admin_audit_log",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("admin", String, nullable=False),
    Column("action", String, nullable=False),
    Column("details", String, nullable=False),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

schema_migrations_table = Table(
    "schema_migrations",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("version", String, nullable=False, unique=True),
    Column(
        "applied_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

companies_table = Table(
    "companies",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("orgnr", String, nullable=False, unique=True, index=True),
    Column("invoice_address", String),
    Column("invoice_contact", String),
    Column("invoice_reference", String),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    ),
)

application_requests_table = Table(
    "application_requests",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("account_type", String, nullable=False),
    Column("name", String, nullable=False),
    Column("email", String, nullable=False),
    Column("orgnr_normalized", String, nullable=False, index=True),
    Column("company_name", String, nullable=False),
    Column("invoice_address", String),
    Column("invoice_contact", String),
    Column("invoice_reference", String),
    Column("comment", String),
    Column("status", String, nullable=False, server_default="pending"),
    Column("reviewed_by", String),
    Column("reviewed_at", DateTime(timezone=True)),
    Column("decision_reason", String),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    ),
)

company_users_table = Table(
    "company_users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("company_id", Integer, nullable=True, index=True),
    Column("role", String, nullable=False),
    Column("name", String, nullable=False),
    Column("email", String, nullable=False, unique=True),
    Column("created_via_application_id", Integer, index=True),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    ),
)

TABLE_REGISTRY: dict[str, Table] = {
    table.name: table
    for table in (
        pending_users_table,
        users_table,
        user_pdfs_table,
        pending_supervisors_table,
        supervisors_table,
        supervisor_connections_table,
        supervisor_link_requests_table,
        password_resets_table,
        admin_audit_log_table,
        schema_migrations_table,
        companies_table,
        application_requests_table,
        company_users_table,
    )
}

MigrationFn = Callable[[Connection], None]


def _migration_0001_companies(conn: Connection) -> None:
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())
    if companies_table.name not in existing_tables:
        companies_table.create(bind=conn)
    if application_requests_table.name not in existing_tables:
        application_requests_table.create(bind=conn)
    if company_users_table.name not in existing_tables:
        company_users_table.create(bind=conn)


def _drop_column_if_exists(conn: Connection, table_name: str, column: str) -> None:
    inspector = inspect(conn)
    columns = {col["name"] for col in inspector.get_columns(table_name)}
    if column not in columns:
        return
    conn.execute(text(f"ALTER TABLE {table_name} DROP COLUMN {column}"))


def _migration_0002_remove_phone_columns(conn: Connection) -> None:
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())
    if application_requests_table.name in existing_tables:
        _drop_column_if_exists(conn, application_requests_table.name, "phone")
    if company_users_table.name in existing_tables:
        _drop_column_if_exists(conn, company_users_table.name, "phone")


def _add_column_if_missing(
    conn: Connection, table_name: str, column: str, column_type: str
) -> None:
    inspector = inspect(conn)
    existing_columns = {col["name"] for col in inspector.get_columns(table_name)}
    if column in existing_columns:
        return
    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column} {column_type}"))


def _migration_0003_add_invoice_fields(conn: Connection) -> None:
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())
    if companies_table.name in existing_tables:
        _add_column_if_missing(conn, companies_table.name, "invoice_address", "TEXT")
        _add_column_if_missing(conn, companies_table.name, "invoice_contact", "TEXT")
        _add_column_if_missing(conn, companies_table.name, "invoice_reference", "TEXT")
    if application_requests_table.name in existing_tables:
        _add_column_if_missing(
            conn, application_requests_table.name, "invoice_address", "TEXT"
        )
        _add_column_if_missing(
            conn, application_requests_table.name, "invoice_contact", "TEXT"
        )
        _add_column_if_missing(
            conn, application_requests_table.name, "invoice_reference", "TEXT"
        )


def _migration_0004_make_company_id_nullable(conn: Connection) -> None:
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())
    if company_users_table.name not in existing_tables:
        return

    columns = inspector.get_columns(company_users_table.name)
    company_id_column = next(
        (column for column in columns if column["name"] == "company_id"), None
    )
    if not company_id_column or company_id_column.get("nullable", False):
        return

    dialect = conn.dialect.name
    if dialect == "sqlite":
        conn.execute(text("PRAGMA foreign_keys=OFF"))
        try:
            conn.execute(
                text(
                    """
                    CREATE TABLE company_users_new (
                        id INTEGER PRIMARY KEY,
                        company_id INTEGER,
                        role VARCHAR NOT NULL,
                        name VARCHAR NOT NULL,
                        email VARCHAR NOT NULL UNIQUE,
                        created_via_application_id INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    INSERT INTO company_users_new (
                        id,
                        company_id,
                        role,
                        name,
                        email,
                        created_via_application_id,
                        created_at,
                        updated_at
                    )
                    SELECT
                        id,
                        company_id,
                        role,
                        name,
                        email,
                        created_via_application_id,
                        created_at,
                        updated_at
                    FROM company_users
                    """
                )
            )
            conn.execute(text("DROP TABLE company_users"))
            conn.execute(text("ALTER TABLE company_users_new RENAME TO company_users"))
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_company_users_company_id ON company_users(company_id)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_company_users_created_via_application_id ON company_users(created_via_application_id)"
                )
            )
        finally:
            conn.execute(text("PRAGMA foreign_keys=ON"))
        return
    if dialect.startswith("postgresql"):
        conn.execute(text("ALTER TABLE company_users ALTER COLUMN company_id DROP NOT NULL"))
        return
    raise RuntimeError(
        f"Migration 0004 stöder inte dialekten '{dialect}'. Lägg till hantering eller kör via Alembic."
    )


def _migration_0005_add_supervisor_link_requests(conn: Connection) -> None:
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())
    if supervisor_link_requests_table.name not in existing_tables:
        supervisor_link_requests_table.create(bind=conn)


MIGRATIONS: List[Tuple[str, MigrationFn]] = [
    ("0001_companies", _migration_0001_companies),
    ("0002_remove_phone_columns", _migration_0002_remove_phone_columns),
    ("0003_add_invoice_fields", _migration_0003_add_invoice_fields),
    ("0004_make_company_id_nullable", _migration_0004_make_company_id_nullable),
    ("0005_add_supervisor_link_requests", _migration_0005_add_supervisor_link_requests),
]


def run_migrations(engine: Engine) -> None:
    with engine.begin() as conn:
        inspector = inspect(conn)
        existing_tables = set(inspector.get_table_names())
        if schema_migrations_table.name not in existing_tables:
            schema_migrations_table.create(bind=conn)
        applied_versions = {
            row.version
            for row in conn.execute(select(schema_migrations_table.c.version))
        }
        for version, migration_fn in MIGRATIONS:
            if version in applied_versions:
                continue
            migration_fn(conn)
            conn.execute(insert(schema_migrations_table).values(version=version))


_ENGINE: Optional[Engine] = None


def _is_truthy(value: Optional[str]) -> bool:
    # Return True when the provided string represents a truthy value.
    if value is None:
        return False

    return value.strip().lower() in {
        "1",
        "ja",
        "on",
        "sant",
        "true",
        "t",
        "yes",
        "y",
        "True",
        "TRUE",
        "Ja",
        "JA",
        "On",
        "ON",
        "Sant",
        "SANT",
    }


def _build_engine() -> Engine:
    # Create a SQLAlchemy engine based on configuration.
    db_url = os.getenv("DATABASE_URL")
    sqlite_database_path: Optional[str] = None
    if not db_url:
        if _is_truthy(os.getenv("DEV_MODE", "False")):
            test_db_path = os.getenv("LOCAL_TEST_DB_PATH", "instance/test.db")
            if test_db_path == ":memory:":
                db_url = "sqlite:///:memory:"
                logger.info("Using in-memory SQLite test database")
            else:
                raw_path = Path(test_db_path).expanduser()
                if not raw_path.is_absolute():
                    raw_path = Path(APP_ROOT) / raw_path
                raw_path.parent.mkdir(parents=True, exist_ok=True)
                resolved = raw_path.resolve()
                sqlite_database_path = str(resolved)
                db_url = f"sqlite:///{resolved.as_posix()}"
                logger.info("Using local SQLite test database at %s", resolved)
        else:
            host = os.getenv("POSTGRES_HOST")
            if not host:
                raise RuntimeError(
                    "Sätt DATABASE_URL, aktivera DEV_MODE eller ange POSTGRES_HOST med PostgreSQL-uppgifter"
                )

            user = os.getenv("POSTGRES_USER")
            password = os.getenv("POSTGRES_PASSWORD", "")
            database = os.getenv("POSTGRES_DB")
            port = os.getenv("POSTGRES_PORT", "5432")

            if not user:
                logger.error(
                    "POSTGRES_USER must be set when POSTGRES_HOST is configured"
                )
                raise RuntimeError(
                    "POSTGRES_USER must be set when POSTGRES_HOST is configured"
                )
            if not database:
                logger.error(
                    "POSTGRES_DB must be set when POSTGRES_HOST is configured"
                )
                raise RuntimeError(
                    "POSTGRES_DB must be set when POSTGRES_HOST is configured"
                )

            encoded_user = quote_plus(user)
            encoded_password = quote_plus(password)
            encoded_db = quote_plus(database)
            credentials = (
                encoded_user if password == "" else f"{encoded_user}:{encoded_password}"
            )
            port_segment = f":{port}" if port else ""
            db_url = f"postgresql://{credentials}@{host}{port_segment}/{encoded_db}"
    url = make_url(db_url)
    if sqlite_database_path and url.get_backend_name() == "sqlite":
        url = url.set(database=sqlite_database_path)
    logger.debug("Creating engine for %s", url.render_as_string(hide_password=True))

    if url.get_backend_name() == "postgresql":
        driver = url.get_driver_name() or ""
        if driver in ("", "psycopg2"):
            psycopg_available = False
            import_error = None
            if importlib.util.find_spec("psycopg") is not None:
                try:
                    importlib.import_module("psycopg")
                except ImportError as exc:
                    import_error = exc
                else:
                    psycopg_available = True
            if psycopg_available:
                url = url.set(drivername="postgresql+psycopg")
                logger.debug("Using psycopg driver for PostgreSQL connections")
            else:
                logger.warning(
                    "psycopg driver not available; falling back to %s%s",
                    driver or "default driver",
                    f" ({import_error})" if import_error else "",
                )

    engine_kwargs: Dict[str, Any] = {"future": True}

    if url.get_backend_name() == "sqlite":
        database = url.database or ""
        if database not in ("", ":memory:"):
            os.makedirs(os.path.dirname(database), exist_ok=True)
        connect_args = engine_kwargs.setdefault("connect_args", {})
        connect_args["check_same_thread"] = False
        if database in ("", ":memory:"):
            engine_kwargs["poolclass"] = StaticPool
    try:
        from functions import create_engine as create_engine_fn
    except Exception:
        create_engine_fn = sqlalchemy_create_engine

    return create_engine_fn(url, **engine_kwargs)


def reset_engine() -> None:
    # Reset the cached SQLAlchemy engine.
    global _ENGINE
    if _ENGINE is not None:
        try:
            _ENGINE.dispose()
        except Exception:
            logger.exception("Kunde inte stänga databasmotorn vid återställning")
    _ENGINE = None


def get_engine() -> Engine:
    # Return a cached SQLAlchemy engine instance.
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = _build_engine()
    return _ENGINE


def create_database() -> None:
    # Create required tables if they do not exist.
    engine = get_engine()
    metadata.create_all(engine)
    run_migrations(engine)
    with engine.begin() as conn:
        inspector = inspect(conn)
        columns = {col["name"] for col in inspector.get_columns("user_pdfs")}
        if "categories" not in columns:
            conn.execute(
                text(
                    "ALTER TABLE user_pdfs ADD COLUMN categories TEXT DEFAULT '' NOT NULL"
                )
            )
        existing_tables = set(inspector.get_table_names())
        for table in (password_resets_table, admin_audit_log_table):
            if table.name not in existing_tables:
                table.create(bind=conn)
    logger.info("Database initialized")
