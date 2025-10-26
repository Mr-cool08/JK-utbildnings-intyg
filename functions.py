# Database helpers and utility functions for the Flask application.

from __future__ import annotations

import base64
import hashlib
import importlib.util
import logging
import os
import re
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from functools import lru_cache
import string
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple
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
    bindparam,
    case,
    create_engine,
    delete,
    func,
    insert,
    inspect,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool
from werkzeug.security import check_password_hash, generate_password_hash

from config_loader import load_environment
from logging_utils import configure_module_logger, mask_hash
# --- SQLite shim for platforms without stdlib _sqlite3 ---
try:
    import sys
    import pysqlite3 as sqlite3  # comes from pysqlite3-binary
    sys.modules["sqlite3"] = sqlite3
except Exception:
    # Om pysqlite3 inte är installerat fortsätter vi – på miljöer där stdlib sqlite3 finns.
    pass
logger = configure_module_logger(__name__)
logger.setLevel(logging.DEBUG)  # or INFO in production

load_environment()

APP_ROOT = os.path.abspath(os.path.dirname(__file__))
logger.debug("Application root directory: %s", APP_ROOT)

SALT = os.getenv("HASH_SALT", "static_salt")
if SALT == "static_salt":
    logger.warning(
        "Using default HASH_SALT; set HASH_SALT in environment for stronger security"
    )

DEFAULT_HASH_ITERATIONS = int(os.getenv("HASH_ITERATIONS", "200000"))
TEST_HASH_ITERATIONS = int(os.getenv("HASH_ITERATIONS_TEST", "1000"))

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
    Column("company_id", Integer, nullable=False, index=True),
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
        _add_column_if_missing(conn, application_requests_table.name, "invoice_address", "TEXT")
        _add_column_if_missing(conn, application_requests_table.name, "invoice_contact", "TEXT")
        _add_column_if_missing(conn, application_requests_table.name, "invoice_reference", "TEXT")


MIGRATIONS: List[Tuple[str, MigrationFn]] = [
    ("0001_companies", _migration_0001_companies),
    ("0002_remove_phone_columns", _migration_0002_remove_phone_columns),
    ("0003_add_invoice_fields", _migration_0003_add_invoice_fields),
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
            conn.execute(
                insert(schema_migrations_table).values(version=version)
            )


_ENGINE: Optional[Engine] = None


def _is_truthy(value: Optional[str]) -> bool:
    # Return True when the provided string represents a truthy value.
    if value is None:
        return False

    return value.strip().lower() in {"1", "ja", "on", "sant", "true", "t", "yes", "y", "True", "TRUE", "Ja", "JA", "On", "ON", "Sant", "SANT"}


def _build_engine() -> Engine:
    # Create a SQLAlchemy engine based on configuration.
    db_url = os.getenv("DATABASE_URL")
    sqlite_database_path: Optional[str] = None
    if not db_url:
        if _is_truthy(os.getenv("ENABLE_LOCAL_TEST_DB")):
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
                encoded_user
                if password == ""
                else f"{encoded_user}:{encoded_password}"
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
            if importlib.util.find_spec("psycopg") is not None:
                url = url.set(drivername="postgresql+psycopg")
                logger.debug(
                    "Using psycopg driver for PostgreSQL connections"
                )
            else:
                logger.warning(
                    "psycopg driver not available; falling back to %s",
                    driver or "default driver",
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
    return create_engine(url, **engine_kwargs)


def reset_engine() -> None:
    # Reset the cached SQLAlchemy engine.
    global _ENGINE
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


def _pbkdf2_iterations() -> int:
    # Return the iteration count for PBKDF2 operations.
    if os.getenv("PYTEST_CURRENT_TEST"):
        return TEST_HASH_ITERATIONS
    return DEFAULT_HASH_ITERATIONS


@lru_cache(maxsize=2048)
def _hash_value_cached(value: str, salt: str, iterations: int) -> str:
    # Cacheable helper for PBKDF2 hashing.
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), iterations).hex()






















def hash_value(value: str) -> str:
    # Return a strong deterministic hash of ``value`` using PBKDF2.
    iterations = _pbkdf2_iterations()
    logger.debug("Hashing value with %s iterations", iterations)
    return _hash_value_cached(value, SALT, iterations)


def normalize_email(email: str) -> str:
    # Normalize e-mail addresses before hashing or sending messages.
    if email is None:
        raise ValueError("Saknar e-postadress")

    if "\n" in email or "\r" in email:
        raise ValueError("Ogiltig e-postadress")

    cleaned = email.strip()

    if not cleaned:
        raise ValueError("Ogiltig e-postadress")

    normalized = cleaned.lower()
    logger.debug("Normalizing email address")
    return normalized


def hash_password(password: str) -> str:
    # Hash a password with Werkzeug's PBKDF2 implementation.
    return generate_password_hash(password)


def verify_password(hashed: str, password: str) -> bool:
    # Verify a password against its hashed representation.
    return check_password_hash(hashed, password)


def normalize_personnummer(pnr: str) -> str:
    # Normalize Swedish personal numbers to the YYMMDDXXXX format.
    logger.debug("Normalizing personnummer")
    digits = re.sub(r"\D", "", pnr)
    if len(digits) == 12:
        digits = digits[2:]
    if len(digits) != 10:
        logger.error("Misslyckad normalisering av personnummer: ogiltigt format")
        raise ValueError("Ogiltigt personnummerformat.")
    logger.debug("Personnummer normaliserat")
    return digits


def normalize_orgnr(orgnr: str) -> str:
    """Normalisera organisationsnummer till exakt tio siffror."""

    if orgnr is None:
        raise ValueError("Organisationsnummer saknas.")

    digits = re.sub(r"\D", "", orgnr)
    if len(digits) != 10:
        raise ValueError("Organisationsnumret måste bestå av tio siffror.")
    return digits


def validate_orgnr(orgnr: str) -> str:
    """Validera ett svenskt organisationsnummer med Luhn-mod10."""

    normalized = normalize_orgnr(orgnr)
    total = 0
    for index, char in enumerate(normalized[:-1]):
        digit = int(char)
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    checksum = (10 - (total % 10)) % 10
    if checksum != int(normalized[-1]):
        raise ValueError("Ogiltigt organisationsnummer.")
    return normalized


def _hash_personnummer(pnr: str) -> str:
    # Normalize and hash a personal identity number.
    normalized = normalize_personnummer(pnr)
    return hash_value(normalized)


def check_password_user(email: str, password: str) -> bool:
    # Return True if ``email`` and ``password`` match a user.
    normalized = normalize_email(email)
    hashed_email = hash_value(normalized)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.password).where(users_table.c.email == hashed_email)
        ).first()
    return bool(row and verify_password(row.password, password))


def check_personnummer_password(personnummer: str, password: str) -> bool:
    # Return True if the hashed personnummer and password match a user.
    personnummer_hash = _hash_personnummer(personnummer)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.password).where(
                users_table.c.personnummer == personnummer_hash
            )
        ).first()
    return bool(row and verify_password(row.password, password))


def check_user_exists(email: str) -> bool:
    # Return True if a user with ``email`` exists.
    normalized = normalize_email(email)
    hashed_email = hash_value(normalized)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.id).where(users_table.c.email == hashed_email)
        ).first()
    return row is not None


def get_username(email: str) -> Optional[str]:
    # Return the username associated with ``email`` or ``None``.
    normalized = normalize_email(email)
    hashed_email = hash_value(normalized)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.username).where(users_table.c.email == hashed_email)
        ).first()
    return row.username if row else None


def check_pending_user(personnummer: str) -> bool:
    # Return True if a pending user with ``personnummer`` exists.
    pnr_hash = _hash_personnummer(personnummer)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(pending_users_table.c.id).where(
                pending_users_table.c.personnummer == pnr_hash
            )
        ).first()
    return row is not None


def check_pending_user_hash(personnummer_hash: str) -> bool:
    # Return True if a pending user with ``personnummer_hash`` exists.
    with get_engine().connect() as conn:
        row = conn.execute(
            select(pending_users_table.c.id).where(
                pending_users_table.c.personnummer == personnummer_hash
            )
        ).first()
    return row is not None


@lru_cache(maxsize=256)
def verify_certificate(personnummer: str) -> bool:
    # Return True if a certificate for ``personnummer`` is verified.
    pnr_hash = _hash_personnummer(personnummer)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
    return row is not None


def admin_create_user(email: str, username: str, personnummer: str) -> bool:
    # Insert a new pending user row.
    pnr_hash = _hash_personnummer(personnummer)
    normalized_email = normalize_email(email)
    hashed_email = hash_value(normalized_email)
    try:
        with get_engine().begin() as conn:
            existing_user = conn.execute(
                select(users_table.c.id).where(users_table.c.email == hashed_email)
            ).first()
            if existing_user:
                logger.warning(
                    "Attempt to recreate existing user hash %s", mask_hash(hashed_email)
                )
                return False
            existing_pending = conn.execute(
                select(pending_users_table.c.id).where(
                    pending_users_table.c.personnummer == pnr_hash
                )
            ).first()
            if existing_pending:
                logger.warning(
                    "Pending user already exists for hash %s", mask_hash(pnr_hash)
                )
                return False
            conn.execute(
                insert(pending_users_table).values(
                    email=hashed_email,
                    username=username,
                    personnummer=pnr_hash,
                )
            )
    except IntegrityError:
        logger.warning(
            "Pending user already exists or was created concurrently for hash %s",
            mask_hash(pnr_hash),
        )
        return False
    logger.info("Pending user created for hash %s", mask_hash(pnr_hash))
    return True


def admin_create_supervisor(email: str, name: str) -> bool:
    """Create a pending supervisor that needs to activate the account."""

    normalized_email = normalize_email(email)
    email_hash = hash_value(normalized_email)
    try:
        with get_engine().begin() as conn:
            existing_supervisor = conn.execute(
                select(supervisors_table.c.id).where(
                    supervisors_table.c.email == email_hash
                )
            ).first()
            if existing_supervisor:
                logger.warning("Supervisor %s already exists", mask_hash(email_hash))
                return False

            existing_pending = conn.execute(
                select(pending_supervisors_table.c.id).where(
                    pending_supervisors_table.c.email == email_hash
                )
            ).first()
            if existing_pending:
                logger.warning(
                    "Pending supervisor already exists for %s", mask_hash(email_hash)
                )
                return False

            conn.execute(
                insert(pending_supervisors_table).values(
                    email=email_hash,
                    name=name,
                )
            )
    except IntegrityError:
        logger.warning(
            "Pending supervisor already exists or was created concurrently for %s",
            mask_hash(email_hash),
        )
        return False

    logger.info("Pending supervisor created for %s", mask_hash(email_hash))
    return True


def user_create_user(password: str, personnummer_hash: str) -> bool:
    # Move a pending user identified by ``personnummer_hash`` into users.
    try:
        with get_engine().begin() as conn:
            existing = conn.execute(
                select(users_table.c.id).where(
                    users_table.c.personnummer == personnummer_hash
                )
            ).first()
            if existing:
                logger.warning(
                    "User %s already exists", mask_hash(personnummer_hash)
                )
                return False
            row = conn.execute(
                select(
                    pending_users_table.c.email,
                    pending_users_table.c.username,
                    pending_users_table.c.personnummer,
                ).where(pending_users_table.c.personnummer == personnummer_hash)
            ).first()
            if not row:
                logger.warning(
                    "Pending user %s not found", mask_hash(personnummer_hash)
                )
                return False
            conn.execute(
                delete(pending_users_table).where(
                    pending_users_table.c.personnummer == personnummer_hash
                )
            )
            conn.execute(
                insert(users_table).values(
                    email=row.email,
                    password=hash_password(password),
                    username=row.username,
                    personnummer=row.personnummer,
                )
            )
    except IntegrityError:
        logger.warning(
            "User creation for %s skipped because record already exists",
            mask_hash(personnummer_hash),
        )
        return False
    verify_certificate.cache_clear()
    logger.info("User %s created", row.username)
    return True


def get_user_info(personnummer: str):
    # Return database row for user identified by ``personnummer``.
    pnr_hash = _hash_personnummer(personnummer)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(
                users_table.c.id,
                users_table.c.username,
                users_table.c.email,
                users_table.c.password,
                users_table.c.personnummer,
            ).where(users_table.c.personnummer == pnr_hash)
        ).first()
    return row


def get_username_by_personnummer_hash(personnummer_hash: str) -> Optional[str]:
    # Return the username tied to ``personnummer_hash`` if it exists.

    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.username).where(
                users_table.c.personnummer == personnummer_hash
            )
        ).first()
    return row.username if row else None


def check_pending_supervisor_hash(email_hash: str) -> bool:
    """Return ``True`` if a pending supervisor with ``email_hash`` exists."""

    with get_engine().connect() as conn:
        row = conn.execute(
            select(pending_supervisors_table.c.id).where(
                pending_supervisors_table.c.email == email_hash
            )
        ).first()
    return row is not None


def supervisor_activate_account(email_hash: str, password: str) -> bool:
    """Move a pending supervisor into the active supervisor table."""

    if not password or len(password) < 8:
        raise ValueError("Lösenordet måste vara minst 8 tecken.")

    try:
        with get_engine().begin() as conn:
            existing = conn.execute(
                select(supervisors_table.c.id).where(
                    supervisors_table.c.email == email_hash
                )
            ).first()
            if existing:
                logger.warning(
                    "Supervisor %s already activated", mask_hash(email_hash)
                )
                return False

            row = conn.execute(
                select(
                    pending_supervisors_table.c.email,
                    pending_supervisors_table.c.name,
                ).where(pending_supervisors_table.c.email == email_hash)
            ).first()
            if not row:
                logger.warning(
                    "Pending supervisor %s not found during activation",
                    mask_hash(email_hash),
                )
                return False

            conn.execute(
                delete(pending_supervisors_table).where(
                    pending_supervisors_table.c.email == email_hash
                )
            )
            conn.execute(
                insert(supervisors_table).values(
                    email=row.email,
                    name=row.name,
                    password=hash_password(password),
                )
            )
    except IntegrityError:
        logger.warning(
            "Supervisor activation for %s skipped because record already exists",
            mask_hash(email_hash),
        )
        return False

    logger.info("Supervisor %s activated", mask_hash(email_hash))
    return True


def supervisor_exists(email: str) -> bool:
    """Return ``True`` if a supervisor with ``email`` exists."""

    normalized = normalize_email(email)
    email_hash = hash_value(normalized)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(supervisors_table.c.id).where(
                supervisors_table.c.email == email_hash
            )
        ).first()
    return row is not None


def verify_supervisor_credentials(email: str, password: str) -> bool:
    """Return ``True`` if ``email`` and ``password`` match a supervisor."""

    normalized = normalize_email(email)
    email_hash = hash_value(normalized)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(supervisors_table.c.password).where(
                supervisors_table.c.email == email_hash
            )
        ).first()
    if not row:
        return False
    return verify_password(row.password, password)


def get_supervisor_name_by_hash(email_hash: str) -> Optional[str]:
    """Return the name of the supervisor identified by ``email_hash``."""

    with get_engine().connect() as conn:
        row = conn.execute(
            select(supervisors_table.c.name).where(
                supervisors_table.c.email == email_hash
            )
        ).first()
    if not row:
        return None
    return row.name


def get_supervisor_email_hash(email: str) -> str:
    """Return the hashed e-mail used for supervisor tables."""

    normalized = normalize_email(email)
    return hash_value(normalized)


def list_supervisor_connections(email_hash: str) -> List[Dict[str, Any]]:
    """Return connected users for the given supervisor hash."""

    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                supervisor_connections_table.c.user_personnummer,
                users_table.c.username,
            )
            .select_from(
                supervisor_connections_table.join(
                    users_table,
                    supervisor_connections_table.c.user_personnummer
                    == users_table.c.personnummer,
                )
            )
            .where(supervisor_connections_table.c.supervisor_email == email_hash)
            .order_by(users_table.c.username.asc())
        )

        return [
            {
                "personnummer_hash": row.user_personnummer,
                "username": row.username,
            }
            for row in rows
        ]


def supervisor_has_access(
    supervisor_email_hash: str, personnummer_hash: str
) -> bool:
    """Return ``True`` if supervisor has access to the given user."""

    with get_engine().connect() as conn:
        row = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_connections_table.c.user_personnummer
                == personnummer_hash,
            )
        ).first()
    return row is not None


def supervisor_remove_connection(
    supervisor_email_hash: str, personnummer_hash: str
) -> bool:
    """Remove a connection between supervisor and user."""

    with get_engine().begin() as conn:
        result = conn.execute(
            delete(supervisor_connections_table).where(
                supervisor_connections_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_connections_table.c.user_personnummer
                == personnummer_hash,
            )
        )
    return result.rowcount > 0


def admin_link_supervisor_to_user(
    supervisor_email: str, personnummer: str
) -> tuple[bool, str]:
    """Create a connection between a supervisor and a user.

    Returns a tuple (success, reason). ``reason`` is ``'created'`` when the
    connection was stored, or one of ``'missing_supervisor'``, ``'missing_user'``
    or ``'exists'`` for error cases.
    """

    normalized_email = normalize_email(supervisor_email)
    email_hash = hash_value(normalized_email)
    pnr_hash = _hash_personnummer(personnummer)

    with get_engine().begin() as conn:
        supervisor_row = conn.execute(
            select(supervisors_table.c.id).where(
                supervisors_table.c.email == email_hash
            )
        ).first()
        if not supervisor_row:
            logger.warning(
                "Supervisor %s not found for linking", mask_hash(email_hash)
            )
            return False, "missing_supervisor"

        user_row = conn.execute(
            select(users_table.c.id).where(
                users_table.c.personnummer == pnr_hash
            )
        ).first()
        if not user_row:
            logger.warning(
                "User %s not found when linking supervisor %s",
                mask_hash(pnr_hash),
                mask_hash(email_hash),
            )
            return False, "missing_user"

        existing = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email == email_hash,
                supervisor_connections_table.c.user_personnummer == pnr_hash,
            )
        ).first()
        if existing:
            logger.info(
                "Supervisor %s already connected to %s",
                mask_hash(email_hash),
                mask_hash(pnr_hash),
            )
            return False, "exists"

        conn.execute(
            insert(supervisor_connections_table).values(
                supervisor_email=email_hash,
                user_personnummer=pnr_hash,
            )
        )

    logger.info(
        "Supervisor %s connected to user %s",
        mask_hash(email_hash),
        mask_hash(pnr_hash),
    )
    return True, "created"


def get_supervisor_overview(email_hash: str) -> Optional[Dict[str, Any]]:
    """Return supervisor info together with connected users."""

    with get_engine().connect() as conn:
        supervisor_row = conn.execute(
            select(supervisors_table.c.name).where(
                supervisors_table.c.email == email_hash
            )
        ).first()
        if not supervisor_row:
            return None

        connections = conn.execute(
            select(
                supervisor_connections_table.c.user_personnummer,
                users_table.c.username,
            )
            .select_from(
                supervisor_connections_table.join(
                    users_table,
                    supervisor_connections_table.c.user_personnummer
                    == users_table.c.personnummer,
                )
            )
            .where(supervisor_connections_table.c.supervisor_email == email_hash)
            .order_by(users_table.c.username.asc())
        )

        return {
            "name": supervisor_row.name,
            "email_hash": email_hash,
            "connections": [
                {
                    "personnummer_hash": row.user_personnummer,
                    "username": row.username,
                }
                for row in connections
            ],
        }


def _serialize_categories(categories: Sequence[str] | None) -> str:
    if not categories:
        return ""
    cleaned: List[str] = []
    seen: set[str] = set()
    for category in categories:
        value = category.strip()
        if value and value not in seen:
            cleaned.append(value)
            seen.add(value)
    return ",".join(cleaned)


def _deserialize_categories(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    return [part for part in raw.split(",") if part]


def log_admin_action(admin: str, action: str, details: str) -> None:
    # Spara en revisionspost för administratörsåtgärder.
    admin_name = admin or "okänd"
    trimmed_details = details.strip()
    with get_engine().begin() as conn:
        conn.execute(
            insert(admin_audit_log_table).values(
                admin=admin_name,
                action=action,
                details=trimmed_details[:1000],
            )
        )
    logger.info("Admin %s utförde %s: %s", admin_name, action, trimmed_details)


def delete_user_pdf(personnummer: str, pdf_id: int) -> bool:
    # Ta bort en PDF kopplad till en användares personnummer.
    personnummer_hash = _hash_personnummer(personnummer)
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(user_pdfs_table).where(
                user_pdfs_table.c.personnummer == personnummer_hash,
                user_pdfs_table.c.id == pdf_id,
            )
        )
    deleted = result.rowcount > 0
    if deleted:
        logger.info(
            "PDF %s raderades för %s", pdf_id, mask_hash(personnummer_hash)
        )
    else:
        logger.warning(
            "PDF %s kunde inte raderas för %s", pdf_id, mask_hash(personnummer_hash)
        )
    return deleted


def update_pdf_categories(personnummer: str, pdf_id: int, categories: Sequence[str]) -> bool:
    # Uppdatera kategorierna för en PDF.
    personnummer_hash = _hash_personnummer(personnummer)
    serialized = _serialize_categories(categories)
    with get_engine().begin() as conn:
        result = conn.execute(
            update(user_pdfs_table)
            .where(
                user_pdfs_table.c.personnummer == personnummer_hash,
                user_pdfs_table.c.id == pdf_id,
            )
            .values(categories=serialized)
        )
    updated = result.rowcount > 0
    if updated:
        logger.info(
            "PDF %s fick nya kategorier %s för %s",
            pdf_id,
            serialized,
            mask_hash(personnummer_hash),
        )
    else:
        logger.warning(
            "PDF %s kunde inte uppdateras för %s",
            pdf_id,
            mask_hash(personnummer_hash),
        )
    return updated


def store_pdf_blob(
    personnummer_hash: str,
    filename: str,
    content: bytes,
    categories: Sequence[str] | None = None,
) -> int:
    # Store a PDF for the hashed personnummer and return its database id.
    with get_engine().begin() as conn:
        result = conn.execute(
            insert(user_pdfs_table).values(
                personnummer=personnummer_hash,
                filename=filename,
                content=content,
                categories=_serialize_categories(categories),
            )
        )
        pdf_id = result.inserted_primary_key[0]
    logger.info(
        "Stored PDF %s for %s as id %s",
        filename,
        mask_hash(personnummer_hash),
        pdf_id,
    )
    return int(pdf_id)


def _import_legacy_pdfs(personnummer_hash: str, existing_filenames: Set[str]) -> bool:
    # Import PDFs stored on disk for ``personnummer_hash`` into the database.

    legacy_dir = os.path.join(APP_ROOT, "uploads", personnummer_hash)
    if not os.path.isdir(legacy_dir):
        return False

    imported_count = 0
    for entry in sorted(os.listdir(legacy_dir)):
        if entry in existing_filenames:
            continue
        path = os.path.join(legacy_dir, entry)
        if not os.path.isfile(path):
            continue

        try:
            with open(path, "rb") as legacy_file:
                content = legacy_file.read()
        except OSError:
            logger.exception(
                "Failed to read legacy PDF %s for %s", path, personnummer_hash
            )
            continue

        try:
            store_pdf_blob(personnummer_hash, entry, content)
        except Exception:  # pragma: no cover - defensive; store_pdf_blob rarely fails
            logger.exception(
                "Failed to import legacy PDF %s for %s", entry, personnummer_hash
            )
            continue

        existing_filenames.add(entry)
        imported_count += 1

    if imported_count:
        logger.info(
            "Imported %s legacy PDF(s) for %s from %s",
            imported_count,
            personnummer_hash,
            legacy_dir,
        )
        return True

    return False


def get_user_pdfs(personnummer_hash: str) -> List[Dict[str, Any]]:
    # Return metadata for all PDFs belonging to ``personnummer_hash``.
    def _load() -> List[Dict[str, Any]]:
        with get_engine().connect() as conn:
            rows = conn.execute(
                select(
                    user_pdfs_table.c.id,
                    user_pdfs_table.c.filename,
                    user_pdfs_table.c.categories,
                    user_pdfs_table.c.uploaded_at,
                )
                .where(user_pdfs_table.c.personnummer == personnummer_hash)
                .order_by(
                    user_pdfs_table.c.uploaded_at.desc(),
                    user_pdfs_table.c.id.desc(),
                )
            )
            return [
                {
                    "id": row.id,
                    "filename": row.filename,
                    "categories": _deserialize_categories(row.categories),
                    "uploaded_at": row.uploaded_at,
                }
                for row in rows
            ]

    pdfs = _load()
    existing_filenames = {pdf["filename"] for pdf in pdfs}
    if _import_legacy_pdfs(personnummer_hash, existing_filenames):
        pdfs = _load()
    return pdfs


def get_pdf_metadata(personnummer_hash: str, pdf_id: int) -> Optional[Dict[str, Any]]:
    # Return metadata for a single PDF without loading its content.
    with get_engine().connect() as conn:
        row = conn.execute(
            select(
                user_pdfs_table.c.id,
                user_pdfs_table.c.filename,
                user_pdfs_table.c.categories,
                user_pdfs_table.c.uploaded_at,
            ).where(
                user_pdfs_table.c.personnummer == personnummer_hash,
                user_pdfs_table.c.id == pdf_id,
            )
        ).first()
    if not row:
        return None
    return {
        "id": row.id,
        "filename": row.filename,
        "categories": _deserialize_categories(row.categories),
        "uploaded_at": row.uploaded_at,
    }


def get_pdf_content(personnummer_hash: str, pdf_id: int) -> Optional[Tuple[str, bytes]]:
    # Return the filename and binary content for ``pdf_id``.
    with get_engine().connect() as conn:
        row = conn.execute(
            select(
                user_pdfs_table.c.filename,
                user_pdfs_table.c.content,
            ).where(
                user_pdfs_table.c.personnummer == personnummer_hash,
                user_pdfs_table.c.id == pdf_id,
            )
        ).first()
    if not row:
        return None
    return row.filename, row.content


def _hash_token(token: str) -> str:
    return hash_value(token)


def create_password_reset_token(personnummer: str, email: str) -> str:
    # Skapa ett återställningstoken för en användare.
    personnummer_hash = _hash_personnummer(personnummer)
    normalized_email = normalize_email(email)
    email_hash = hash_value(normalized_email)

    with get_engine().begin() as conn:
        row = conn.execute(
            select(users_table.c.email).where(
                users_table.c.personnummer == personnummer_hash
            )
        ).first()
        if not row or row.email != email_hash:
            logger.warning(
                "Kunde inte skapa återställningstoken för %s: uppgifter matchar inte",
                mask_hash(personnummer_hash),
            )
            raise ValueError("Angivna uppgifter matchar inget aktivt standardkonto.")

        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        conn.execute(
            insert(password_resets_table).values(
                personnummer=personnummer_hash,
                email=email_hash,
                token_hash=token_hash,
            )
        )

    logger.info(
        "Skapade återställningstoken för %s", mask_hash(personnummer_hash)
    )
    return token


def get_password_reset(token: str) -> Optional[Dict[str, Any]]:
    # Hämta metadata för ett återställningstoken.
    token_hash = _hash_token(token)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(
                password_resets_table.c.personnummer,
                password_resets_table.c.email,
                password_resets_table.c.created_at,
                password_resets_table.c.used_at,
            ).where(password_resets_table.c.token_hash == token_hash)
        ).first()
    if not row:
        return None
    return {
        "personnummer": row.personnummer,
        "email": row.email,
        "created_at": row.created_at,
        "used_at": row.used_at,
    }


def reset_password_with_token(token: str, new_password: str) -> bool:
    # Återställ lösenordet för det angivna tokenet.
    token_hash = _hash_token(token)
    now = datetime.now(timezone.utc)
    with get_engine().begin() as conn:
        row = conn.execute(
            select(
                password_resets_table.c.personnummer,
                password_resets_table.c.used_at,
                password_resets_table.c.created_at,
            ).where(password_resets_table.c.token_hash == token_hash)
        ).first()
        if not row:
            logger.warning("Okänt återställningstoken användes")
            return False
        if row.used_at is not None:
            logger.warning("Förbrukat återställningstoken användes igen")
            return False

        created_at = row.created_at
        if created_at and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if created_at and now - created_at > timedelta(days=2):
            logger.warning("Utgånget återställningstoken för %s", row.personnummer)
            return False

        conn.execute(
            update(users_table)
            .where(users_table.c.personnummer == row.personnummer)
            .values(password=hash_password(new_password))
        )
        conn.execute(
            update(password_resets_table)
            .where(password_resets_table.c.token_hash == token_hash)
            .values(used_at=now)
        )

    verify_certificate.cache_clear()
    logger.info("Lösenord återställt för %s", row.personnummer)
    return True


def _get_table(table_name: str) -> Table:
    table = TABLE_REGISTRY.get(table_name)
    if table is None:
        raise ValueError("Okänd tabell")
    return table


def get_table_schema(table_name: str) -> List[Dict[str, Any]]:
    table = _get_table(table_name)
    schema: List[Dict[str, Any]] = []
    for column in table.c:
        schema.append(
            {
                "name": column.name,
                "type": type(column.type).__name__,
                "nullable": bool(column.nullable),
                "primary_key": column.primary_key,
            }
        )
    return schema


def _encode_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _decode_value(column: Column, raw_value: Any) -> Any:
    if raw_value is None:
        return None
    if isinstance(column.type, LargeBinary):
        if raw_value == "":
            return b""
        if isinstance(raw_value, str):
            try:
                return base64.b64decode(raw_value.encode("ascii"))
            except Exception as exc:  # pragma: no cover - defensiv kontroll
                raise ValueError("Ogiltig binärdata") from exc
        raise ValueError("Ogiltig binärdata")
    return raw_value


def fetch_table_rows(table_name: str, search: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    table = _get_table(table_name)
    stmt = select(table)
    if search:
        # Skydda mot SQL-injektion genom att behandla wildcard-tecken som
        # vanliga tecken och använda parametrar.
        escaped = (
            search.lower()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        pattern = f"%{escaped}%"
        parameter = bindparam("search_term", value=pattern)
        conditions = []
        for column in table.c:
            if isinstance(column.type, String):
                conditions.append(
                    func.lower(column).like(parameter, escape="\\")
                )
        if conditions:
            stmt = stmt.where(or_(*conditions))
    stmt = stmt.order_by(table.c.id.asc()).limit(limit)
    with get_engine().connect() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [
        {key: _encode_value(value) for key, value in row.items()}
        for row in rows
    ]


def create_table_row(table_name: str, values: Dict[str, Any]) -> Dict[str, Any]:
    table = _get_table(table_name)
    prepared: Dict[str, Any] = {}
    for column in table.c:
        if column.name in values and not column.primary_key:
            prepared[column.name] = _decode_value(column, values[column.name])
    if not prepared:
        raise ValueError("Inga giltiga kolumner angavs")
    with get_engine().begin() as conn:
        result = conn.execute(insert(table).values(**prepared))
        new_id = None
        if "id" in table.c:
            new_id = result.inserted_primary_key[0]
        if new_id is None:
            return prepared
        row = conn.execute(
            select(table).where(table.c.id == new_id)
        ).mappings().first()
    return {key: _encode_value(value) for key, value in row.items()}


def update_table_row(table_name: str, row_id: int, values: Dict[str, Any]) -> bool:
    table = _get_table(table_name)
    assignments: Dict[str, Any] = {}
    for column in table.c:
        if column.primary_key:
            continue
        if column.name in values:
            assignments[column.name] = _decode_value(column, values[column.name])
    if not assignments:
        raise ValueError("Inga fält att uppdatera")
    with get_engine().begin() as conn:
        result = conn.execute(
            update(table).where(table.c.id == row_id).values(**assignments)
        )
    return result.rowcount > 0


def delete_table_row(table_name: str, row_id: int) -> bool:
    table = _get_table(table_name)
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(table).where(table.c.id == row_id)
        )
    return result.rowcount > 0


def create_test_user() -> None:
    # Populate the database with a simple test user.
    email = "test@example.com"
    username = "Test User"
    personnummer = "9001011234"
    if not check_user_exists(email):
        admin_create_user(email, username, personnummer)
        pnr_hash = _hash_personnummer(personnummer)
        user_create_user("password", pnr_hash)


def ensure_demo_data(
    *,
    user_email: str,
    user_name: str,
    user_personnummer: str,
    user_password: str,
    supervisor_email: str,
    supervisor_name: str,
    supervisor_password: str,
) -> None:
    """Skapa eller uppdatera demodata för företagskonto och standardkonto."""

    try:
        normalized_pnr = normalize_personnummer(user_personnummer)
    except ValueError:
        logger.error("Ogiltigt personnummer för demoanvändare: %s", user_personnummer)
        return

    try:
        normalized_user_email = normalize_email(user_email)
    except ValueError:
        logger.error("Ogiltig e-postadress för demoanvändare: %s", user_email)
        return

    try:
        normalized_supervisor_email = normalize_email(supervisor_email)
    except ValueError:
        logger.error("Ogiltig e-postadress för demoföretagskonto: %s", supervisor_email)
        return

    pnr_hash = _hash_personnummer(normalized_pnr)
    user_email_hash = hash_value(normalized_user_email)
    supervisor_email_hash = hash_value(normalized_supervisor_email)

    engine = get_engine()

    user_created = False
    user_updated = False
    with engine.begin() as conn:
        existing_user = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
        if existing_user:
            conn.execute(
                update(users_table)
                .where(users_table.c.personnummer == pnr_hash)
                .values(
                    username=user_name,
                    email=user_email_hash,
                    password=hash_password(user_password),
                )
            )
            user_updated = True
            logger.info("Demodata: uppdaterade demoanvändare")
        else:
            conn.execute(
                delete(pending_users_table).where(
                    pending_users_table.c.personnummer == pnr_hash
                )
            )
            conn.execute(
                delete(pending_users_table).where(
                    pending_users_table.c.email == user_email_hash
                )
            )
            conn.execute(
                insert(pending_users_table).values(
                    username=user_name,
                    email=user_email_hash,
                    personnummer=pnr_hash,
                )
            )
            user_created = True
            logger.info("Demodata: skapade pending-demoanvändare")

    if user_created:
        if user_create_user(user_password, pnr_hash):
            logger.info("Demodata: demoanvändare aktiverad")
        else:
            logger.warning("Demodata: demoanvändare kunde inte aktiveras")
    elif user_updated:
        verify_certificate.cache_clear()

    supervisor_created = False
    with engine.begin() as conn:
        existing_supervisor = conn.execute(
            select(supervisors_table.c.id).where(
                supervisors_table.c.email == supervisor_email_hash
            )
        ).first()
        if existing_supervisor:
            conn.execute(
                update(supervisors_table)
                .where(supervisors_table.c.email == supervisor_email_hash)
                .values(
                    name=supervisor_name,
                    password=hash_password(supervisor_password),
                )
            )
            logger.info("Demodata: uppdaterade demoföretagskonto")
        else:
            conn.execute(
                delete(pending_supervisors_table).where(
                    pending_supervisors_table.c.email == supervisor_email_hash
                )
            )
            conn.execute(
                insert(pending_supervisors_table).values(
                    name=supervisor_name,
                    email=supervisor_email_hash,
                )
            )
            supervisor_created = True
            logger.info("Demodata: skapade pending-demoföretagskonto")

    if supervisor_created:
        try:
            if supervisor_activate_account(supervisor_email_hash, supervisor_password):
                logger.info("Demodata: demoföretagskonto aktiverat")
            else:
                logger.warning("Demodata: demoföretagskonto kunde inte aktiveras")
        except ValueError:
            logger.error("Demodata: lösenordet för demoföretagskontot är ogiltigt")

    linked, reason = admin_link_supervisor_to_user(
        normalized_supervisor_email, normalized_pnr
    )
    if linked:
        logger.info("Demodata: kopplade företagskonto och demoanvändare")
    elif reason != "exists":
        logger.warning(
            "Demodata: kunde inte koppla företagskonto och demoanvändare (%s)", reason
        )

    _ensure_demo_pdfs(pnr_hash)


DEMO_PDF_DEFINITIONS = [
    {
        "filename": "Kompetensintyg_Demoanvandare.pdf",
        "path": Path(APP_ROOT) / "demo_assets" / "pdfs" / "Kompetensintyg_Demoanvandare.pdf",
        "categories": ["fallskydd", "heta-arbeten"],
    },
    {
        "filename": "Utbildningsbevis_Demoanvandare.pdf",
        "path": Path(APP_ROOT) / "demo_assets" / "pdfs" / "Utbildningsbevis_Demoanvandare.pdf",
        "categories": ["lift"],
    },
]


def _ensure_demo_pdfs(personnummer_hash: str) -> None:
    """Säkerställ att demoanvändaren har exempel-PDF:er uppladdade."""

    with get_engine().begin() as conn:
        existing = conn.execute(
            select(user_pdfs_table.c.filename).where(
                user_pdfs_table.c.personnummer == personnummer_hash
            )
        )
        existing_filenames = {row.filename for row in existing}

    for pdf in DEMO_PDF_DEFINITIONS:
        path = pdf["path"]
        filename = pdf["filename"]
        if not path.is_file():
            logger.warning("Demodata: kunde inte hitta demopdf %s", path)
            continue

        content = path.read_bytes()
        categories_serialized = _serialize_categories(pdf.get("categories"))

        if filename in existing_filenames:
            with get_engine().begin() as conn:
                conn.execute(
                    update(user_pdfs_table)
                    .where(user_pdfs_table.c.personnummer == personnummer_hash)
                    .where(user_pdfs_table.c.filename == filename)
                    .values(content=content, categories=categories_serialized)
                )
            logger.info("Demodata: uppdaterade demopdf %s", filename)
        else:
            store_pdf_blob(personnummer_hash, filename, content, pdf.get("categories"))
            existing_filenames.add(filename)


def _clean_optional_text(value: Optional[str], max_length: int = 2000) -> Optional[str]:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return cleaned[:max_length]


def _ensure_company(
    conn: Connection,
    orgnr: str,
    company_name: Optional[str],
    invoice_address: Optional[str] = None,
    invoice_contact: Optional[str] = None,
    invoice_reference: Optional[str] = None,
) -> Tuple[int, bool, str]:
    cleaned_name = (company_name or "").strip()
    cleaned_invoice_address = (invoice_address or "").strip()
    cleaned_invoice_contact = (invoice_contact or "").strip()
    cleaned_invoice_reference = (invoice_reference or "").strip()

    existing = conn.execute(
        select(companies_table).where(companies_table.c.orgnr == orgnr)
    ).first()
    if existing:
        updates: Dict[str, str] = {}
        existing_name = existing.name
        if cleaned_name and existing_name != cleaned_name:
            updates["name"] = cleaned_name
        if cleaned_invoice_address and (existing.invoice_address or "") != cleaned_invoice_address:
            updates["invoice_address"] = cleaned_invoice_address
        if cleaned_invoice_contact and (existing.invoice_contact or "") != cleaned_invoice_contact:
            updates["invoice_contact"] = cleaned_invoice_contact
        if cleaned_invoice_reference and (existing.invoice_reference or "") != cleaned_invoice_reference:
            updates["invoice_reference"] = cleaned_invoice_reference
        if updates:
            conn.execute(
                update(companies_table)
                .where(companies_table.c.id == existing.id)
                .values(**updates)
            )
            if "name" in updates:
                existing_name = updates["name"]
        return int(existing.id), False, existing_name

    if not cleaned_name:
        raise ValueError("Företagsnamn saknas för detta organisationsnummer.")

    result = conn.execute(
        insert(companies_table).values(
            orgnr=orgnr,
            name=cleaned_name,
            invoice_address=cleaned_invoice_address or None,
            invoice_contact=cleaned_invoice_contact or None,
            invoice_reference=cleaned_invoice_reference or None,
        )
    )
    company_id = result.inserted_primary_key[0]
    return int(company_id), True, cleaned_name


def create_application_request(
    account_type: str,
    name: str,
    email: str,
    orgnr: str,
    company_name: Optional[str],
    comment: Optional[str],
    invoice_address: Optional[str] = None,
    invoice_contact: Optional[str] = None,
    invoice_reference: Optional[str] = None,
) -> int:
    allowed_types = {"standard", "foretagskonto"}
    normalized_type = (account_type or "").strip().lower()
    if normalized_type not in allowed_types:
        raise ValueError("Ogiltig kontotyp.")

    cleaned_name = (name or "").strip()
    if not cleaned_name:
        raise ValueError("Namn saknas.")

    normalized_email = normalize_email(email)
    validated_orgnr = validate_orgnr(orgnr)
    cleaned_company = (company_name or "").strip()
    if normalized_type == "foretagskonto" and not cleaned_company:
        raise ValueError("Företagsnamn krävs för företagskonton.")

    cleaned_comment = _clean_optional_text(comment)
    cleaned_invoice_address = _clean_optional_text(invoice_address, max_length=1000)
    cleaned_invoice_contact = _clean_optional_text(invoice_contact, max_length=255)
    cleaned_invoice_reference = _clean_optional_text(invoice_reference, max_length=255)

    if normalized_type == "foretagskonto":
        if not cleaned_invoice_address:
            raise ValueError("Fakturaadress krävs för företagskonton.")
        if not cleaned_invoice_contact:
            raise ValueError("Kontaktperson för fakturering krävs för företagskonton.")
        if not cleaned_invoice_reference:
            raise ValueError("Märkning för fakturering krävs för företagskonton.")
    else:
        cleaned_invoice_address = None
        cleaned_invoice_contact = None
        cleaned_invoice_reference = None

    stored_company = cleaned_company if cleaned_company else ""

    with get_engine().begin() as conn:
        # Prevent duplicate pending applications for the same email + orgnr combination.
        existing_pending = conn.execute(
            select(application_requests_table).where(
                application_requests_table.c.email == normalized_email,
                application_requests_table.c.orgnr_normalized == validated_orgnr,
                application_requests_table.c.status == 'pending',
            )
        ).first()
        if existing_pending:
            existing_type = existing_pending.account_type
            if existing_type == normalized_type:
                raise ValueError(
                    'Du har redan skickat samma typ av ansökan. Vänta på beslut eller kontakta support.'
                )
            else:
                raise ValueError(
                    'Det finns redan en väntande ansökan för denna e-post och organisationsnummer. Kontakta support om du vill ändra ansökningstyp.'
                )
        result = conn.execute(
            insert(application_requests_table).values(
                account_type=normalized_type,
                name=cleaned_name,
                email=normalized_email,
                orgnr_normalized=validated_orgnr,
                company_name=stored_company,
                comment=cleaned_comment,
                invoice_address=cleaned_invoice_address,
                invoice_contact=cleaned_invoice_contact,
                invoice_reference=cleaned_invoice_reference,
            )
        )
        request_id = result.inserted_primary_key[0]

    email_hash = hash_value(normalized_email)
    logger.info(
        "Mottog kontoansökan %s för %s",
        request_id,
        mask_hash(email_hash),
    )
    return int(request_id)


def list_application_requests(status: Optional[str] = None) -> List[Dict[str, Any]]:
    allowed_statuses = {"pending", "approved", "rejected"}
    query = select(application_requests_table).order_by(
        application_requests_table.c.created_at.desc()
    )
    if status:
        normalized = status.strip().lower()
        if normalized not in allowed_statuses:
            raise ValueError("Ogiltig status.")
        query = query.where(application_requests_table.c.status == normalized)

    with get_engine().connect() as conn:
        rows = conn.execute(query)
        return [dict(row._mapping) for row in rows]


def get_application_request(application_id: int) -> Optional[Dict[str, Any]]:
    with get_engine().connect() as conn:
        row = conn.execute(
            select(application_requests_table).where(
                application_requests_table.c.id == application_id
            )
        ).first()
    return dict(row._mapping) if row else None


def approve_application_request(
    application_id: int, reviewer: str
) -> Dict[str, Any]:
    """
    Approve an application request and create the corresponding company and company user; for corporate accounts, ensure or create a pending supervisor entry.
    
    Parameters:
    	application_id (int): ID of the application request to approve.
    	reviewer (str): Name of the reviewer; empty values are normalized to "okänd".
    
    Returns:
    	result (Dict[str, Any]): Metadata about the created/updated records:
    		company_id (int): ID of the ensured or created company.
    		user_id (int): ID of the newly created company user.
    		orgnr (str): Normalized organization number for the company.
    		email (str): Normalized email address of the created user.
    		account_type (str): Account type from the application (e.g., "foretagskonto").
    		name (str): Applicant's name from the application.
    		company_name (str): Display name of the company (may be provided or derived).
    		company_created (bool): True if a new company was created, False if an existing company was used.
    		invoice_address (Optional[str]): Invoice address from the application.
    		invoice_contact (Optional[str]): Invoice contact from the application.
    		invoice_reference (Optional[str]): Invoice reference from the application.
    		pending_supervisor_created (bool): True if a pending supervisor row was created for corporate accounts.
    		supervisor_activation_required (bool): True if a supervisor account must be activated for the company (corporate accounts).
    		supervisor_email_hash (Optional[str]): Hashed supervisor email for corporate accounts, or None for non-corporate accounts.
    """
    normalized_reviewer = (reviewer or "").strip() or "okänd"

    pending_supervisor_created = False
    supervisor_activation_required = False
    supervisor_email_hash: Optional[str] = None

    with get_engine().begin() as conn:
        application = conn.execute(
            select(application_requests_table).where(
                application_requests_table.c.id == application_id
            )
        ).first()
        if not application:
            raise ValueError("Ansökan hittades inte.")
        if application.status != "pending":
            raise ValueError("Ansökan är redan hanterad.")

        validated_orgnr = validate_orgnr(application.orgnr_normalized)
        company_id, created, company_display = _ensure_company(
            conn,
            validated_orgnr,
            application.company_name,
            application.invoice_address,
            application.invoice_contact,
            application.invoice_reference,
        )

        normalized_email = normalize_email(application.email)
        existing_user = conn.execute(
            select(company_users_table.c.id).where(
                company_users_table.c.email == normalized_email
            )
        ).first()
        if existing_user:
            raise ValueError("E-postadressen är redan registrerad.")

        result = conn.execute(
            insert(company_users_table).values(
                company_id=company_id,
                role=application.account_type,
                name=application.name,
                email=normalized_email,
                created_via_application_id=application.id,
            )
        )
        user_id = result.inserted_primary_key[0]

        if application.account_type == "foretagskonto":
            supervisor_email_hash = hash_value(normalized_email)
            existing_supervisor = conn.execute(
                select(supervisors_table.c.id).where(
                    supervisors_table.c.email == supervisor_email_hash
                )
            ).first()
            pending_row = conn.execute(
                select(
                    pending_supervisors_table.c.id,
                    pending_supervisors_table.c.name,
                ).where(pending_supervisors_table.c.email == supervisor_email_hash)
            ).first()

            cleaned_name = (application.name or "").strip()

            if existing_supervisor:
                supervisor_activation_required = False
            elif pending_row:
                supervisor_activation_required = True
                if cleaned_name and pending_row.name != cleaned_name:
                    conn.execute(
                        update(pending_supervisors_table)
                        .where(pending_supervisors_table.c.id == pending_row.id)
                        .values(name=cleaned_name)
                    )
            else:
                conn.execute(
                    insert(pending_supervisors_table).values(
                        email=supervisor_email_hash,
                        name=cleaned_name,
                    )
                )
                pending_supervisor_created = True
                supervisor_activation_required = True

        conn.execute(
            update(application_requests_table)
            .where(application_requests_table.c.id == application.id)
            .values(
                status="approved",
                reviewed_by=normalized_reviewer,
                reviewed_at=func.now(),
                decision_reason=None,
            )
        )

    email_hash = hash_value(normalized_email)
    logger.info(
        "Ansökan %s godkänd av %s (företag %s, standardkonto %s)",
        application_id,
        normalized_reviewer,
        validated_orgnr,
        mask_hash(email_hash),
    )
    return {
        "company_id": int(company_id),
        "user_id": int(user_id),
        "orgnr": validated_orgnr,
        "email": normalized_email,
        "account_type": application.account_type,
        "name": application.name,
        "company_name": company_display,
        "company_created": created,
        "invoice_address": application.invoice_address,
        "invoice_contact": application.invoice_contact,
        "invoice_reference": application.invoice_reference,
        "pending_supervisor_created": pending_supervisor_created,
        "supervisor_activation_required": supervisor_activation_required,
        "supervisor_email_hash": supervisor_email_hash,
    }


def reject_application_request(
    application_id: int, reviewer: str, reason: str
) -> Dict[str, Any]:
    normalized_reviewer = (reviewer or "").strip() or "okänd"
    cleaned_reason = _clean_optional_text(reason, max_length=500)
    if not cleaned_reason:
        raise ValueError("Ange en motivering till avslaget.")

    with get_engine().begin() as conn:
        application = conn.execute(
            select(application_requests_table).where(
                application_requests_table.c.id == application_id
            )
        ).first()
        if not application:
            raise ValueError("Ansökan hittades inte.")
        if application.status != "pending":
            raise ValueError("Ansökan är redan hanterad.")

        validated_orgnr = validate_orgnr(application.orgnr_normalized)
        company_display = (application.company_name or "").strip()
        if not company_display:
            existing_company = conn.execute(
                select(companies_table.c.name).where(
                    companies_table.c.orgnr == validated_orgnr
                )
            ).first()
            if existing_company and existing_company.name:
                company_display = existing_company.name
            else:
                company_display = f"organisationsnummer {validated_orgnr}"

        conn.execute(
            update(application_requests_table)
            .where(application_requests_table.c.id == application.id)
            .values(
                status="rejected",
                reviewed_by=normalized_reviewer,
                reviewed_at=func.now(),
                decision_reason=cleaned_reason,
            )
        )

    normalized_email = normalize_email(application.email)
    email_hash = hash_value(normalized_email)
    logger.info(
        "Ansökan %s avslogs av %s (%s)",
        application_id,
        normalized_reviewer,
        mask_hash(email_hash),
    )
    return {
        "orgnr": validated_orgnr,
        "email": normalized_email,
        "account_type": application.account_type,
        "name": application.name,
        "company_name": company_display,
        "reason": cleaned_reason,
    }


def list_companies_for_invoicing() -> List[Dict[str, Any]]:
    """Returnerar företag med företagskonton och deras fakturauppgifter."""

    foretagskonto_count_expr = func.sum(
        case((company_users_table.c.role == "foretagskonto", 1), else_=0)
    ).label("foretagskonto_count")
    user_count_expr = func.count(company_users_table.c.id).label("user_count")

    query = (
        select(
            companies_table.c.id,
            companies_table.c.name,
            companies_table.c.orgnr,
            companies_table.c.invoice_address,
            companies_table.c.invoice_contact,
            companies_table.c.invoice_reference,
            foretagskonto_count_expr,
            user_count_expr,
        )
        .select_from(
            companies_table.join(
                company_users_table,
                company_users_table.c.company_id == companies_table.c.id,
            )
        )
        .group_by(
            companies_table.c.id,
            companies_table.c.name,
            companies_table.c.orgnr,
            companies_table.c.invoice_address,
            companies_table.c.invoice_contact,
            companies_table.c.invoice_reference,
        )
        .having(foretagskonto_count_expr > 0)
        .order_by(companies_table.c.name)
    )

    with get_engine().connect() as conn:
        rows = conn.execute(query).fetchall()

    companies: List[Dict[str, Any]] = []
    for row in rows:
        mapping = row._mapping
        companies.append(
            {
                "id": mapping["id"],
                "name": mapping["name"],
                "orgnr": mapping["orgnr"],
                "invoice_address": mapping.get("invoice_address"),
                "invoice_contact": mapping.get("invoice_contact"),
                "invoice_reference": mapping.get("invoice_reference"),
                "foretagskonto_count": int(mapping["foretagskonto_count"] or 0),
                "user_count": int(mapping["user_count"] or 0),
            }
        )

    return companies
