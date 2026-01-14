from __future__ import annotations

import logging
from functools import lru_cache
from typing import Optional

from sqlalchemy import delete, insert, select
from sqlalchemy.exc import IntegrityError

from functions.database import (
    pending_users_table,
    users_table,
    get_engine,
)
from functions.hashing import (
    _hash_personnummer,
    _is_valid_hash,
    hash_password,
    hash_value,
    normalize_email,
    verify_password,
)
from functions.logging import configure_module_logger, mask_hash


logger = configure_module_logger(__name__)
logger.setLevel(logging.DEBUG)


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
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
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
                logger.warning("User %s already exists", mask_hash(personnummer_hash))
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
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return None
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.username).where(
                users_table.c.personnummer == personnummer_hash
            )
        ).first()
    return row.username if row else None
