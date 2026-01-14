from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote_plus

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.pool import StaticPool

from functions.app_paths import APP_ROOT
from functions.db.migrations import run_migrations
from functions.db.schema import admin_audit_log_table, metadata, password_resets_table
from functions.logging.logging_utils import configure_module_logger

logger = configure_module_logger(__name__)

# --- SQLite shim for platforms without stdlib _sqlite3 ---
try:
    import sys
    import pysqlite3 as sqlite3  # comes from pysqlite3-binary

    sys.modules["sqlite3"] = sqlite3
except Exception as exc:
    logger.warning(
        "Failed to import pysqlite3, falling back to stdlib sqlite3: %s", exc
    )

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
    }


def _build_engine() -> Engine:
    # Create a SQLAlchemy engine based on configuration.
    db_url = os.getenv("DATABASE_URL")
    sqlite_database_path: Optional[str] = None
    if not db_url:
        if _is_truthy(os.getenv("ENABLE_LOCAL_TEST_DB", "True")):
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
                    "Set DATABASE_URL, enable ENABLE_LOCAL_TEST_DB or provide POSTGRES_HOST with PostgreSQL credentials"
                )

            user = os.getenv("POSTGRES_USER")
            password = os.getenv("POSTGRES_PASSWORD", "")
            database = os.getenv("POSTGRES_DB")
            port = os.getenv("POSTGRES_PORT", "5432")

            if not user:
                logger.error("POSTGRES_USER must be set when POSTGRES_HOST is configured")
                raise RuntimeError(
                    "POSTGRES_USER must be set when POSTGRES_HOST is configured"
                )
            if not database:
                logger.error("POSTGRES_DB must be set when POSTGRES_HOST is configured")
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

    engine_kwargs: dict[str, Any] = {"future": True}

    if url.get_backend_name() == "sqlite":
        database = url.database or ""
        if database not in ("", ":memory:"):
            os.makedirs(os.path.dirname(database), exist_ok=True)
        connect_args = engine_kwargs.setdefault("connect_args", {})
        connect_args["check_same_thread"] = False
        if database in ("", ":memory:"):
            engine_kwargs["poolclass"] = StaticPool
    return _create_engine(url, **engine_kwargs)


def _create_engine(url, **engine_kwargs) -> Engine:
    try:
        import functions

        create_engine_fn = getattr(functions, "create_engine", create_engine)
    except Exception:
        create_engine_fn = create_engine
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
