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
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote_plus

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    UniqueConstraint,
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
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool
from werkzeug.security import check_password_hash, generate_password_hash

from config_loader import load_environment
from logging_utils import configure_module_logger

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

_PDF_FERNET_CACHE: Tuple[str, Tuple[Fernet, ...]] | None = None


def reset_pdf_encryption_cache() -> None:
    # Clear cached Fernet instances so environment changes take effect.
    global _PDF_FERNET_CACHE
    _PDF_FERNET_CACHE = None


def _load_pdf_encryption_keys() -> List[str]:
    raw_keys = os.getenv("PDF_ENCRYPTION_KEYS")
    if not raw_keys:
        raw_keys = os.getenv("PDF_ENCRYPTION_KEY")

    if not raw_keys:
        raise RuntimeError(
            "PDF_ENCRYPTION_KEYS/PDF_ENCRYPTION_KEY måste vara satt för att lagra PDF:er."
        )

    parts = [
        segment.strip()
        for segment in re.split(r"[,;\n]", raw_keys)
        if segment.strip()
    ]
    if not parts:
        raise RuntimeError("Minst en PDF-krypteringsnyckel krävs i PDF_ENCRYPTION_KEYS.")

    return parts


def _get_pdf_fernets() -> Tuple[Fernet, ...]:
    global _PDF_FERNET_CACHE

    keys = _load_pdf_encryption_keys()
    normalized = "|".join(keys)

    if _PDF_FERNET_CACHE and _PDF_FERNET_CACHE[0] == normalized:
        return _PDF_FERNET_CACHE[1]

    fernets: List[Fernet] = []
    for index, key in enumerate(keys):
        try:
            fernets.append(Fernet(key.encode("ascii")))
        except Exception:  # pragma: no cover - defensive logging
            logger.exception(
                "Ogiltig PDF-krypteringsnyckel på position %s, hoppar över.", index
            )

    if not fernets:
        raise RuntimeError("Inga giltiga PDF-krypteringsnycklar kunde läsas in.")

    cached = (normalized, tuple(fernets))
    _PDF_FERNET_CACHE = cached
    return cached[1]


def _encrypt_pdf_content(content: bytes) -> bytes:
    active_fernet = _get_pdf_fernets()[0]
    return active_fernet.encrypt(content)


def _decrypt_pdf_content(content: bytes) -> bytes:
    for fernet in _get_pdf_fernets():
        try:
            return fernet.decrypt(content)
        except InvalidToken:
            continue

    logger.warning(
        "Kunde inte dekryptera PDF-innehåll med konfigurerade nycklar; returnerar ursprungliga data."
    )
    return content

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
    )
}

_ENGINE: Optional[Engine] = None


def _is_truthy(value: Optional[str]) -> bool:
    # Return True when the provided string represents a truthy value.
    if value is None:
        return False

    return value.strip().lower() in {"1", "ja", "on", "sant", "true", "t", "yes", "y", "True", "TRUE", "Ja", "JA", "On", "ON", "Sant", "SANT"}


def _build_engine() -> Engine:
    # Create a SQLAlchemy engine based on configuration.
    db_url = os.getenv("DATABASE_URL")
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
                logger.warning("Attempt to recreate existing user hash %s", hashed_email)
                return False
            existing_pending = conn.execute(
                select(pending_users_table.c.id).where(
                    pending_users_table.c.personnummer == pnr_hash
                )
            ).first()
            if existing_pending:
                logger.warning("Pending user already exists for hash %s", pnr_hash)
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
            pnr_hash,
        )
        return False
    logger.info("Pending user created for hash %s", pnr_hash)
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
                logger.warning("Supervisor %s already exists", email_hash)
                return False

            existing_pending = conn.execute(
                select(pending_supervisors_table.c.id).where(
                    pending_supervisors_table.c.email == email_hash
                )
            ).first()
            if existing_pending:
                logger.warning(
                    "Pending supervisor already exists for %s", email_hash
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
            email_hash,
        )
        return False

    logger.info("Pending supervisor created for %s", email_hash)
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
                logger.warning("User %s already exists", personnummer_hash)
                return False
            row = conn.execute(
                select(
                    pending_users_table.c.email,
                    pending_users_table.c.username,
                    pending_users_table.c.personnummer,
                ).where(pending_users_table.c.personnummer == personnummer_hash)
            ).first()
            if not row:
                logger.warning("Pending user %s not found", personnummer_hash)
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
            personnummer_hash,
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
                logger.warning("Supervisor %s already activated", email_hash)
                return False

            row = conn.execute(
                select(
                    pending_supervisors_table.c.email,
                    pending_supervisors_table.c.name,
                ).where(pending_supervisors_table.c.email == email_hash)
            ).first()
            if not row:
                logger.warning(
                    "Pending supervisor %s not found during activation", email_hash
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
            email_hash,
        )
        return False

    logger.info("Supervisor %s activated", email_hash)
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
            logger.warning("Supervisor %s not found for linking", email_hash)
            return False, "missing_supervisor"

        user_row = conn.execute(
            select(users_table.c.id).where(
                users_table.c.personnummer == pnr_hash
            )
        ).first()
        if not user_row:
            logger.warning(
                "User %s not found when linking supervisor %s",
                pnr_hash,
                email_hash,
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
                email_hash,
                pnr_hash,
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
        email_hash,
        pnr_hash,
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
        logger.info("PDF %s raderades för %s", pdf_id, personnummer_hash)
    else:
        logger.warning("PDF %s kunde inte raderas för %s", pdf_id, personnummer_hash)
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
            personnummer_hash,
        )
    else:
        logger.warning(
            "PDF %s kunde inte uppdateras för %s",
            pdf_id,
            personnummer_hash,
        )
    return updated


def store_pdf_blob(
    personnummer_hash: str,
    filename: str,
    content: bytes,
    categories: Sequence[str] | None = None,
) -> int:
    # Store a PDF for the hashed personnummer and return its database id.
    encrypted_content = _encrypt_pdf_content(content)
    with get_engine().begin() as conn:
        result = conn.execute(
            insert(user_pdfs_table).values(
                personnummer=personnummer_hash,
                filename=filename,
                content=encrypted_content,
                categories=_serialize_categories(categories),
            )
        )
        pdf_id = result.inserted_primary_key[0]
    logger.info("Stored PDF %s for %s as id %s", filename, personnummer_hash, pdf_id)
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
    decrypted = _decrypt_pdf_content(row.content)
    return row.filename, decrypted


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
                personnummer_hash,
            )
            raise ValueError("Angivna uppgifter matchar ingen aktiv användare.")

        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        conn.execute(
            insert(password_resets_table).values(
                personnummer=personnummer_hash,
                email=email_hash,
                token_hash=token_hash,
            )
        )

    logger.info("Skapade återställningstoken för %s", personnummer_hash)
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
        search_term = f"%{search.lower()}%"
        conditions = []
        for column in table.c:
            if isinstance(column.type, String):
                conditions.append(func.lower(column).like(search_term))
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
