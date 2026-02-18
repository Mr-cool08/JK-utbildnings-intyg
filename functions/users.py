# Copyright (c) Liam Suorsa
from __future__ import annotations

import logging
from functools import lru_cache
from typing import Optional

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError

from functions.database import (
    application_requests_table,
    company_users_table,
    password_resets_table,
    pending_users_table,
    supervisor_connections_table,
    supervisor_link_requests_table,
    user_pdfs_table,
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
            select(users_table.c.password).where(users_table.c.personnummer == personnummer_hash)
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
            select(pending_users_table.c.id).where(pending_users_table.c.personnummer == pnr_hash)
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
                logger.warning("Attempt to recreate existing user hash %s", mask_hash(hashed_email))
                return False
            existing_pending = conn.execute(
                select(pending_users_table.c.id).where(
                    pending_users_table.c.personnummer == pnr_hash
                )
            ).first()
            if existing_pending:
                logger.warning("Pending user already exists for hash %s", mask_hash(pnr_hash))
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
                select(users_table.c.id).where(users_table.c.personnummer == personnummer_hash)
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
                logger.warning("Pending user %s not found", mask_hash(personnummer_hash))
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
            select(users_table.c.username).where(users_table.c.personnummer == personnummer_hash)
        ).first()
    return row.username if row else None


def admin_delete_user_account(personnummer: str) -> tuple[bool, dict[str, int]]:
    # Remove a user and all related records based on personnummer.
    pnr_hash = _hash_personnummer(personnummer)
    return _admin_delete_user_account_by_hash(pnr_hash)[:2]


def admin_delete_user_account_by_hash(
    personnummer_hash: str,
) -> tuple[bool, dict[str, int], Optional[str]]:
    # Remove a user and all related records based on hashed personnummer.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False, {}, None
    return _admin_delete_user_account_by_hash(personnummer_hash)


def _admin_delete_user_account_by_hash(
    personnummer_hash: str,
) -> tuple[bool, dict[str, int], Optional[str]]:
    username = None
    with get_engine().begin() as conn:
        user_row = conn.execute(
            select(users_table.c.id, users_table.c.username).where(
                users_table.c.personnummer == personnummer_hash
            )
        ).first()
        pending_row = conn.execute(
            select(pending_users_table.c.id, pending_users_table.c.username).where(
                pending_users_table.c.personnummer == personnummer_hash
            )
        ).first()
        if not user_row and not pending_row:
            return False, {}, None
        if user_row and user_row.username:
            username = user_row.username
        elif pending_row and pending_row.username:
            username = pending_row.username

        summary: dict[str, int] = {}
        summary["pdfs"] = (
            conn.execute(
                delete(user_pdfs_table).where(user_pdfs_table.c.personnummer == personnummer_hash)
            ).rowcount
            or 0
        )
        summary["password_resets"] = (
            conn.execute(
                delete(password_resets_table).where(
                    password_resets_table.c.personnummer == personnummer_hash
                )
            ).rowcount
            or 0
        )
        summary["supervisor_connections"] = (
            conn.execute(
                delete(supervisor_connections_table).where(
                    supervisor_connections_table.c.user_personnummer == personnummer_hash
                )
            ).rowcount
            or 0
        )
        summary["supervisor_link_requests"] = (
            conn.execute(
                delete(supervisor_link_requests_table).where(
                    supervisor_link_requests_table.c.user_personnummer == personnummer_hash
                )
            ).rowcount
            or 0
        )
        application_ids = [
            row.id
            for row in conn.execute(
                select(application_requests_table.c.id).where(
                    application_requests_table.c.personnummer_hash == personnummer_hash
                )
            ).fetchall()
        ]
        if application_ids:
            summary["company_users"] = (
                conn.execute(
                    delete(company_users_table).where(
                        company_users_table.c.created_via_application_id.in_(application_ids)
                    )
                ).rowcount
                or 0
            )
        else:
            summary["company_users"] = 0
        summary["applications"] = (
            conn.execute(
                delete(application_requests_table).where(
                    application_requests_table.c.personnummer_hash == personnummer_hash
                )
            ).rowcount
            or 0
        )
        summary["pending_users"] = (
            conn.execute(
                delete(pending_users_table).where(
                    pending_users_table.c.personnummer == personnummer_hash
                )
            ).rowcount
            or 0
        )
        summary["users"] = (
            conn.execute(
                delete(users_table).where(users_table.c.personnummer == personnummer_hash)
            ).rowcount
            or 0
        )

    verify_certificate.cache_clear()
    logger.info("Admin raderade konto för %s", mask_hash(personnummer_hash))
    return True, summary, username


def list_admin_accounts() -> list[dict[str, str]]:
    # Return a list of active and pending accounts for admin selection.
    results: list[dict[str, str]] = []
    with get_engine().connect() as conn:
        user_rows = conn.execute(
            select(users_table.c.username, users_table.c.personnummer).order_by(
                users_table.c.username.asc()
            )
        ).fetchall()
        pending_rows = conn.execute(
            select(pending_users_table.c.username, pending_users_table.c.personnummer).order_by(
                pending_users_table.c.username.asc()
            )
        ).fetchall()

    for row in user_rows:
        results.append(
            {
                "personnummer_hash": row.personnummer,
                "username": row.username,
                "status": "active",
            }
        )

    for row in pending_rows:
        results.append(
            {
                "personnummer_hash": row.personnummer,
                "username": row.username,
                "status": "pending",
            }
        )

    return results


def get_admin_password_status(
    personnummer: str,
    email: str | None = None,
) -> dict[str, str | bool] | None:
    # Return password and activation status for a standard account.
    pnr_hash = _hash_personnummer(personnummer)
    normalized_email = normalize_email(email) if email else None
    email_hash = hash_value(normalized_email) if normalized_email else None

    with get_engine().connect() as conn:
        active_conditions = [users_table.c.personnummer == pnr_hash]
        if email_hash:
            active_conditions.append(users_table.c.email == email_hash)
        active_user = conn.execute(
            select(users_table.c.personnummer).where(*active_conditions)
        ).first()
        if active_user:
            return {
                "account_exists": True,
                "password_created": True,
                "status": "active",
            }

        pending_conditions = [
            pending_users_table.c.personnummer == pnr_hash,
        ]
        if email_hash:
            pending_conditions.append(pending_users_table.c.email == email_hash)
        pending_user = conn.execute(
            select(pending_users_table.c.personnummer).where(*pending_conditions)
        ).first()
        if pending_user:
            return {
                "account_exists": True,
                "password_created": False,
                "status": "pending",
            }

    return None


def get_pending_user_personnummer_hash(
    personnummer: str,
    email: str | None = None,
) -> str | None:
    # Return pending account hash when personnummer exists, optionally constrained by email.
    pnr_hash = _hash_personnummer(personnummer)
    normalized_email = normalize_email(email) if email else None
    email_hash = hash_value(normalized_email) if normalized_email else None

    with get_engine().connect() as conn:
        conditions = [pending_users_table.c.personnummer == pnr_hash]
        if email_hash:
            conditions.append(pending_users_table.c.email == email_hash)
        pending_row = conn.execute(
            select(pending_users_table.c.personnummer).where(*conditions)
        ).first()

    if not pending_row:
        return None

    return str(pending_row.personnummer)

def admin_update_user_account(
    personnummer: str, email: str, username: str
) -> tuple[bool, dict[str, int] | None, str | None]:
    # Update user or pending user record by personnummer.
    pnr_hash = _hash_personnummer(personnummer)
    normalized_email = normalize_email(email)
    email_hash = hash_value(normalized_email)
    with get_engine().begin() as conn:
        user_row = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
        pending_row = conn.execute(
            select(pending_users_table.c.id).where(pending_users_table.c.personnummer == pnr_hash)
        ).first()
        if not user_row and not pending_row:
            return False, None, "missing_account"

        email_conflict = conn.execute(
            select(users_table.c.id).where(
                users_table.c.email == email_hash,
                users_table.c.personnummer != pnr_hash,
            )
        ).first()
        if email_conflict:
            return False, None, "email_in_use"

        pending_conflict = conn.execute(
            select(pending_users_table.c.id).where(
                pending_users_table.c.email == email_hash,
                pending_users_table.c.personnummer != pnr_hash,
            )
        ).first()
        if pending_conflict:
            return False, None, "email_in_use"

        summary: dict[str, int] = {}
        summary["users"] = (
            conn.execute(
                update(users_table)
                .where(users_table.c.personnummer == pnr_hash)
                .values(username=username, email=email_hash)
            ).rowcount
            or 0
        )
        summary["pending_users"] = (
            conn.execute(
                update(pending_users_table)
                .where(pending_users_table.c.personnummer == pnr_hash)
                .values(username=username, email=email_hash)
            ).rowcount
            or 0
        )

    logger.info(
        "Admin uppdaterade konto för %s",
        mask_hash(pnr_hash),
    )
    return True, summary, None
