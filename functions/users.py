from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone, timedelta
from functools import lru_cache
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError

from functions.db import (
    companies_table,
    company_users_table,
    get_engine,
    password_resets_table,
    pending_supervisors_table,
    pending_users_table,
    supervisor_connections_table,
    supervisor_link_requests_table,
    supervisors_table,
    users_table,
)
from functions.logging.logging_utils import configure_module_logger, mask_hash
from functions.security.hashing import (
    _hash_personnummer,
    _is_valid_hash,
    hash_password,
    hash_value,
    normalize_email,
    validate_orgnr,
    verify_password,
)


logger = configure_module_logger(__name__)
logger.setLevel(logging.DEBUG)


@lru_cache(maxsize=256)
def verify_certificate(personnummer: str) -> bool:
    # Return True if a certificate for ``personnummer`` is verified.
    pnr_hash = _hash_personnummer(personnummer)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
    return row is not None


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
            select(users_table.c.username).where(
                users_table.c.personnummer == personnummer_hash
            )
        ).first()
    return row.username if row else None


def check_pending_supervisor_hash(email_hash: str) -> bool:
    """Return ``True`` if a pending supervisor with ``email_hash`` exists."""
    if not _is_valid_hash(email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False
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
                logger.warning("Supervisor %s already activated", mask_hash(email_hash))
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


def get_supervisor_login_details_for_orgnr(
    orgnr: str,
) -> Optional[Dict[str, str]]:
    """Hämta inloggningsuppgifter för ett företagskonto via organisationsnummer."""

    normalized_orgnr = validate_orgnr(orgnr)

    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                company_users_table.c.email,
                company_users_table.c.name,
                company_users_table.c.updated_at,
                company_users_table.c.id,
            )
            .select_from(
                company_users_table.join(
                    companies_table,
                    company_users_table.c.company_id == companies_table.c.id,
                )
            )
            .where(
                companies_table.c.orgnr == normalized_orgnr,
                company_users_table.c.role == "foretagskonto",
            )
            .order_by(
                company_users_table.c.updated_at.desc(),
                company_users_table.c.id.desc(),
            )
        )
        rows = rows.fetchall()
    if not rows:
        return None

    candidates: list[tuple[str, str, str]] = []
    email_hashes: list[str] = []
    for row in rows:
        mapping = row._mapping
        try:
            normalized_email = normalize_email(mapping["email"])
        except ValueError:
            continue
        email_hash = hash_value(normalized_email)
        candidates.append((normalized_email, email_hash, mapping["name"]))
        email_hashes.append(email_hash)

    if not email_hashes:
        return None

    with get_engine().connect() as conn:
        supervisor_rows = conn.execute(
            select(supervisors_table.c.email, supervisors_table.c.name).where(
                supervisors_table.c.email.in_(email_hashes)
            )
        ).fetchall()

    names_by_hash = {row.email: row.name for row in supervisor_rows}

    for normalized_email, email_hash, fallback_name in candidates:
        supervisor_name = names_by_hash.get(email_hash)
        if supervisor_name is None:
            continue
        return {
            "email": normalized_email,
            "email_hash": email_hash,
            "name": supervisor_name or fallback_name,
            "orgnr": normalized_orgnr,
        }

    return None


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
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
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
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
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


def list_user_supervisor_connections(personnummer_hash: str) -> List[Dict[str, str]]:
    """Return connected supervisors for a given user hash."""
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return []
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                supervisor_connections_table.c.supervisor_email,
                supervisors_table.c.name,
            )
            .select_from(
                supervisor_connections_table.join(
                    supervisors_table,
                    supervisor_connections_table.c.supervisor_email
                    == supervisors_table.c.email,
                )
            )
            .where(supervisor_connections_table.c.user_personnummer == personnummer_hash)
            .order_by(supervisors_table.c.name.asc())
        )
        return [
            {"supervisor_email": row.supervisor_email, "supervisor_name": row.name}
            for row in rows
        ]


def list_user_link_requests(personnummer_hash: str) -> List[Dict[str, str]]:
    """Return pending supervisor link requests for a user."""
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return []
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                supervisor_link_requests_table.c.supervisor_email,
                supervisors_table.c.name,
            )
            .select_from(
                supervisor_link_requests_table.join(
                    supervisors_table,
                    supervisor_link_requests_table.c.supervisor_email
                    == supervisors_table.c.email,
                )
            )
            .where(supervisor_link_requests_table.c.user_personnummer == personnummer_hash)
            .order_by(supervisors_table.c.name.asc())
        )
        return [
            {"supervisor_email": row.supervisor_email, "supervisor_name": row.name}
            for row in rows
        ]


def create_supervisor_link_request(
    supervisor_email_hash: str, personnummer: str
) -> tuple[bool, str]:
    """Create a link request from a supervisor to a user."""
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False, "invalid_supervisor"
    pnr_hash = _hash_personnummer(personnummer)

    with get_engine().begin() as conn:
        supervisor_row = conn.execute(
            select(supervisors_table.c.id).where(
                supervisors_table.c.email == supervisor_email_hash
            )
        ).first()
        if not supervisor_row:
            logger.warning(
                "Supervisor %s not found for link request",
                mask_hash(supervisor_email_hash),
            )
            return False, "missing_supervisor"

        user_row = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
        if not user_row:
            logger.warning(
                "User %s not found for link request from %s",
                mask_hash(pnr_hash),
                mask_hash(supervisor_email_hash),
            )
            return False, "missing_user"

        existing_connection = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_connections_table.c.user_personnummer == pnr_hash,
            )
        ).first()
        if existing_connection:
            return False, "already_connected"

        existing_request = conn.execute(
            select(supervisor_link_requests_table.c.id).where(
                supervisor_link_requests_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_link_requests_table.c.user_personnummer == pnr_hash,
            )
        ).first()
        if existing_request:
            return False, "already_requested"

        conn.execute(
            insert(supervisor_link_requests_table).values(
                supervisor_email=supervisor_email_hash,
                user_personnummer=pnr_hash,
            )
        )

    logger.info(
        "Supervisor %s requested link with %s",
        mask_hash(supervisor_email_hash),
        mask_hash(pnr_hash),
    )
    return True, "created"


def user_accept_link_request(
    personnummer_hash: str, supervisor_email_hash: str
) -> bool:
    """Accept a supervisor link request and create the connection."""
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False

    with get_engine().begin() as conn:
        request_row = conn.execute(
            select(supervisor_link_requests_table.c.id).where(
                supervisor_link_requests_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_link_requests_table.c.user_personnummer
                == personnummer_hash,
            )
        ).first()
        if not request_row:
            return False

        existing_connection = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_connections_table.c.user_personnummer
                == personnummer_hash,
            )
        ).first()
        if not existing_connection:
            conn.execute(
                insert(supervisor_connections_table).values(
                    supervisor_email=supervisor_email_hash,
                    user_personnummer=personnummer_hash,
                )
            )

        conn.execute(
            delete(supervisor_link_requests_table).where(
                supervisor_link_requests_table.c.id == request_row.id
            )
        )
    return True


def user_reject_link_request(
    personnummer_hash: str, supervisor_email_hash: str
) -> bool:
    """Reject a supervisor link request."""
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(supervisor_link_requests_table).where(
                supervisor_link_requests_table.c.supervisor_email
                == supervisor_email_hash,
                supervisor_link_requests_table.c.user_personnummer
                == personnummer_hash,
            )
        )
    return result.rowcount > 0


def user_remove_supervisor_connection(
    personnummer_hash: str, supervisor_email_hash: str
) -> bool:
    """Remove a supervisor connection from the user side."""
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    if not _is_valid_hash(supervisor_email_hash):
        logger.warning("Avvisade ogiltig hash för e-post")
        return False
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
            logger.warning("Supervisor %s not found for linking", mask_hash(email_hash))
            return False, "missing_supervisor"

        user_row = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
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
        conn.execute(
            delete(supervisor_link_requests_table).where(
                supervisor_link_requests_table.c.supervisor_email == email_hash,
                supervisor_link_requests_table.c.user_personnummer == pnr_hash,
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


def _hash_token(token: str) -> str:
    return hash_value(token)


def create_password_reset_token(personnummer: str, email: str) -> str:
    # Skapa ett återställningstoken för en användare.
    personnummer_hash = _hash_personnummer(personnummer)
    normalized_email = normalize_email(email)
    email_hash = hash_value(normalized_email)

    with get_engine().begin() as conn:
        row = conn.execute(
            select(users_table.c.email).where(users_table.c.personnummer == personnummer_hash)
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

    logger.info("Skapade återställningstoken för %s", mask_hash(personnummer_hash))
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
