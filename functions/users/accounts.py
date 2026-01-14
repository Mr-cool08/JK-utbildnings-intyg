from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, insert, select
from sqlalchemy.exc import IntegrityError

from functions.db.engine import get_engine
from functions.db.schema import (
    companies_table,
    company_users_table,
    pending_supervisors_table,
    pending_users_table,
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


def admin_create_supervisor(email: str, name: str) -> bool:
    # Create a pending supervisor that needs to activate the account.
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
    # Return True if a pending supervisor with ``email_hash`` exists.
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
    # Move a pending supervisor into the active supervisor table.
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
    # Return True if a supervisor with ``email`` exists.
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
    # Return True if ``email`` and ``password`` match a supervisor.
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


def get_supervisor_login_details_for_orgnr(orgnr: str) -> Optional[Dict[str, str]]:
    # Hämta inloggningsuppgifter för ett företagskonto via organisationsnummer.
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
        ).fetchall()

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
    # Return the name of the supervisor identified by ``email_hash``.
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
    # Return the hashed e-mail used for supervisor tables.
    normalized = normalize_email(email)
    return hash_value(normalized)
