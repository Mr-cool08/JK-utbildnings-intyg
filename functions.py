"""Database helpers and utility functions for the Flask application."""

from __future__ import annotations

import hashlib
import logging
import os
import re
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    create_engine,
    delete,
    func,
    insert,
    select,
)
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url
from sqlalchemy.pool import StaticPool
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # or INFO in production
logger.propagate = True

load_dotenv(os.getenv("CONFIG_PATH", "/config/.env"))

APP_ROOT = os.path.abspath(os.path.dirname(__file__))
logger.debug("Application root directory: %s", APP_ROOT)

SALT = os.getenv("HASH_SALT", "static_salt")
if SALT == "static_salt":
    logger.warning(
        "Using default HASH_SALT; set HASH_SALT in environment for stronger security"
    )

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
    Column(
        "uploaded_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)

_ENGINE: Optional[Engine] = None


def _build_engine() -> Engine:
    """Create a SQLAlchemy engine based on configuration."""
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        db_path = os.getenv("DB_PATH", os.path.join(APP_ROOT, "database.db"))
        db_url = f"sqlite:///{db_path}"
    url = make_url(db_url)
    logger.debug("Creating engine for %s", db_url)
    engine_kwargs: Dict[str, Any] = {"future": True}

    if url.get_backend_name() == "sqlite":
        database = url.database or ""
        if database not in ("", ":memory:"):
            os.makedirs(os.path.dirname(database), exist_ok=True)
        connect_args = engine_kwargs.setdefault("connect_args", {})
        connect_args["check_same_thread"] = False
        if database in ("", ":memory:"):
            engine_kwargs["poolclass"] = StaticPool
    return create_engine(db_url, **engine_kwargs)


def reset_engine() -> None:
    """Reset the cached SQLAlchemy engine."""
    global _ENGINE
    _ENGINE = None


def get_engine() -> Engine:
    """Return a cached SQLAlchemy engine instance."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = _build_engine()
    return _ENGINE


def create_database() -> None:
    """Create required tables if they do not exist."""
    engine = get_engine()
    metadata.create_all(engine)
    logger.info("Database initialized")


def hash_value(value: str) -> str:
    """Return a strong deterministic hash of ``value`` using PBKDF2."""
    logger.debug("Hashing value")
    return hashlib.pbkdf2_hmac(
        "sha256", value.encode(), SALT.encode(), 200_000
    ).hex()


def hash_password(password: str) -> str:
    """Hash a password with Werkzeug's PBKDF2 implementation."""
    return generate_password_hash(password)


def verify_password(hashed: str, password: str) -> bool:
    """Verify a password against its hashed representation."""
    return check_password_hash(hashed, password)


def normalize_personnummer(pnr: str) -> str:
    """Normalize Swedish personal numbers to 12 digits."""
    logger.debug("Normalizing personnummer %s", pnr)
    digits = re.sub(r"\D", "", pnr)
    if len(digits) == 10:
        year = int(digits[:2])
        current_year = datetime.now().year % 100
        century = datetime.now().year // 100 - (1 if year > current_year else 0)
        digits = f"{century:02d}{digits}"
    if len(digits) != 12:
        logger.error("Invalid personnummer format: %s", pnr)
        raise ValueError("Ogiltigt personnummerformat.")
    logger.debug("Normalized personnummer to %s", digits)
    return digits


def _hash_personnummer(pnr: str) -> str:
    """Normalize and hash a personal identity number."""
    normalized = normalize_personnummer(pnr)
    return hash_value(normalized)


def check_password_user(email: str, password: str) -> bool:
    """Return True if ``email`` and ``password`` match a user."""
    hashed_email = hash_value(email)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.password).where(users_table.c.email == hashed_email)
        ).first()
    return bool(row and verify_password(row.password, password))


def check_personnummer_password(personnummer: str, password: str) -> bool:
    """Return True if the hashed personnummer and password match a user."""
    personnummer_hash = _hash_personnummer(personnummer)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.password).where(
                users_table.c.personnummer == personnummer_hash
            )
        ).first()
    return bool(row and verify_password(row.password, password))


def check_user_exists(email: str) -> bool:
    """Return True if a user with ``email`` exists."""
    hashed_email = hash_value(email)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.id).where(users_table.c.email == hashed_email)
        ).first()
    return row is not None


def get_username(email: str) -> Optional[str]:
    """Return the username associated with ``email`` or ``None``."""
    hashed_email = hash_value(email)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.username).where(users_table.c.email == hashed_email)
        ).first()
    return row.username if row else None


def check_pending_user(personnummer: str) -> bool:
    """Return True if a pending user with ``personnummer`` exists."""
    pnr_hash = _hash_personnummer(personnummer)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(pending_users_table.c.id).where(
                pending_users_table.c.personnummer == pnr_hash
            )
        ).first()
    return row is not None


def check_pending_user_hash(personnummer_hash: str) -> bool:
    """Return True if a pending user with ``personnummer_hash`` exists."""
    with get_engine().connect() as conn:
        row = conn.execute(
            select(pending_users_table.c.id).where(
                pending_users_table.c.personnummer == personnummer_hash
            )
        ).first()
    return row is not None


@lru_cache(maxsize=256)
def verify_certificate(personnummer: str) -> bool:
    """Return True if a certificate for ``personnummer`` is verified."""
    pnr_hash = _hash_personnummer(personnummer)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
    return row is not None


def admin_create_user(email: str, username: str, personnummer: str) -> bool:
    """Insert a new pending user row."""
    pnr_hash = _hash_personnummer(personnummer)
    hashed_email = hash_value(email)
    with get_engine().begin() as conn:
        existing_user = conn.execute(
            select(users_table.c.id).where(users_table.c.email == hashed_email)
        ).first()
        if existing_user:
            logger.warning("Attempt to recreate existing user %s", email)
            return False
        existing_pending = conn.execute(
            select(pending_users_table.c.id).where(
                pending_users_table.c.personnummer == pnr_hash
            )
        ).first()
        if existing_pending:
            logger.warning("Pending user already exists for %s", personnummer)
            return False
        conn.execute(
            insert(pending_users_table).values(
                email=hashed_email,
                username=username,
                personnummer=pnr_hash,
            )
        )
    logger.info("Pending user created for %s", personnummer)
    return True


def user_create_user(password: str, personnummer_hash: str) -> bool:
    """Move a pending user identified by ``personnummer_hash`` into users."""
    with get_engine().begin() as conn:
        existing = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == personnummer_hash)
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
    verify_certificate.cache_clear()
    logger.info("User %s created", row.username)
    return True


def get_user_info(personnummer: str):
    """Return database row for user identified by ``personnummer``."""
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


def store_pdf_blob(personnummer_hash: str, filename: str, content: bytes) -> int:
    """Store a PDF for the hashed personnummer and return its database id."""
    with get_engine().begin() as conn:
        result = conn.execute(
            insert(user_pdfs_table).values(
                personnummer=personnummer_hash,
                filename=filename,
                content=content,
            )
        )
        pdf_id = result.inserted_primary_key[0]
    logger.info("Stored PDF %s for %s as id %s", filename, personnummer_hash, pdf_id)
    return int(pdf_id)


def get_user_pdfs(personnummer_hash: str) -> List[Dict[str, Any]]:
    """Return metadata for all PDFs belonging to ``personnummer_hash``."""
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                user_pdfs_table.c.id,
                user_pdfs_table.c.filename,
                user_pdfs_table.c.uploaded_at,
            )
            .where(user_pdfs_table.c.personnummer == personnummer_hash)
            .order_by(user_pdfs_table.c.uploaded_at.desc(), user_pdfs_table.c.id.desc())
        )
        return [
            {
                "id": row.id,
                "filename": row.filename,
                "uploaded_at": row.uploaded_at,
            }
            for row in rows
        ]


def get_pdf_metadata(personnummer_hash: str, pdf_id: int) -> Optional[Dict[str, Any]]:
    """Return metadata for a single PDF without loading its content."""
    with get_engine().connect() as conn:
        row = conn.execute(
            select(
                user_pdfs_table.c.id,
                user_pdfs_table.c.filename,
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
        "uploaded_at": row.uploaded_at,
    }


def get_pdf_content(personnummer_hash: str, pdf_id: int) -> Optional[Tuple[str, bytes]]:
    """Return the filename and binary content for ``pdf_id``."""
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


def create_test_user() -> None:
    """Populate the database with a simple test user."""
    email = "test@example.com"
    username = "Test User"
    personnummer = "199001011234"
    if not check_user_exists(email):
        admin_create_user(email, username, personnummer)
        pnr_hash = _hash_personnummer(personnummer)
        user_create_user("password", pnr_hash)
