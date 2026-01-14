from __future__ import annotations

from typing import Callable

from sqlalchemy import inspect, insert, select, text
from sqlalchemy.engine import Connection, Engine

from functions.db.schema import (
    application_requests_table,
    companies_table,
    company_users_table,
    schema_migrations_table,
    supervisor_link_requests_table,
)
from functions.logging.logging_utils import configure_module_logger

logger = configure_module_logger(__name__)

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
        conn.execute(
            text("ALTER TABLE company_users ALTER COLUMN company_id DROP NOT NULL")
        )
        return
    raise RuntimeError(
        f"Migration 0004 stöder inte dialekten '{dialect}'. Lägg till hantering eller kör via Alembic."
    )


def _migration_0005_add_supervisor_link_requests(conn: Connection) -> None:
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())
    if supervisor_link_requests_table.name not in existing_tables:
        supervisor_link_requests_table.create(bind=conn)


MIGRATIONS: list[tuple[str, MigrationFn]] = [
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
