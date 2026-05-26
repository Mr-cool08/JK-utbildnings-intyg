# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError

from functions.database import (
    companies_table,
    company_users_table,
    pending_supervisors_table,
    supervisor_connections_table,
    supervisor_link_requests_table,
    supervisor_password_resets_table,
    supervisors_table,
    users_table,
    get_engine,
)
from functions.hashing import (
    _hash_personnummer,
    _is_valid_hash,
    email_lookup_values,
    hash_password,
    normalize_email,
    normalize_email_reference,
    validate_orgnr,
    verify_password,
)
from functions.logging import configure_module_logger, mask_email_reference, mask_hash


logger = configure_module_logger(__name__)
logger.setLevel(logging.DEBUG)


def _email_reference_values(value: str) -> tuple[str, ...]:
    reference = normalize_email_reference(value)
    if _is_valid_hash(reference):
        return (reference,)
    return email_lookup_values(reference)


def admin_create_supervisor(email: str, name: str) -> bool:
    # Create a pending supervisor that needs to activate the account.
    normalized_email = normalize_email(email)
    email_values = email_lookup_values(normalized_email)
    try:
        with get_engine().begin() as conn:
            existing_supervisor = conn.execute(
                select(supervisors_table.c.id).where(supervisors_table.c.email.in_(email_values))
            ).first()
            if existing_supervisor:
                logger.warning(
                    "Supervisor %s already exists",
                    mask_email_reference(normalized_email),
                )
                return False

            existing_pending = conn.execute(
                select(pending_supervisors_table.c.id).where(
                    pending_supervisors_table.c.email.in_(email_values)
                )
            ).first()
            if existing_pending:
                logger.warning(
                    "Pending supervisor already exists for %s",
                    mask_email_reference(normalized_email),
                )
                return False

            conn.execute(
                insert(pending_supervisors_table).values(
                    email=normalized_email,
                    name=name,
                )
            )
    except IntegrityError:
        logger.warning(
            "Pending supervisor already exists or was created concurrently for %s",
            mask_email_reference(normalized_email),
        )
        return False

    logger.info("Pending supervisor created for %s", mask_email_reference(normalized_email))
    return True


def check_pending_supervisor_hash(email_hash: str) -> bool:
    # Return ``True`` if a pending supervisor with ``email_hash`` exists.
    try:
        email_values = _email_reference_values(email_hash)
    except ValueError:
        logger.warning("Avvisade ogiltig e-postreferens")
        return False
    with get_engine().connect() as conn:
        row = conn.execute(
            select(pending_supervisors_table.c.id).where(
                pending_supervisors_table.c.email.in_(email_values)
            )
        ).first()
    return row is not None


def supervisor_activate_account(email_hash: str, password: str) -> bool:
    # Move a pending supervisor into the active supervisor table.
    if not password or len(password) < 8:
        raise ValueError("Lösenordet måste vara minst 8 tecken.")

    email_values = _email_reference_values(email_hash)
    try:
        with get_engine().begin() as conn:
            existing = conn.execute(
                select(supervisors_table.c.id).where(supervisors_table.c.email.in_(email_values))
            ).first()
            if existing:
                logger.warning(
                    "Supervisor %s already activated",
                    mask_email_reference(email_hash),
                )
                return False

            row = conn.execute(
                select(
                    pending_supervisors_table.c.email,
                    pending_supervisors_table.c.name,
                ).where(pending_supervisors_table.c.email.in_(email_values))
            ).first()
            if not row:
                logger.warning(
                    "Pending supervisor %s not found during activation",
                    mask_email_reference(email_hash),
                )
                return False

            conn.execute(
                delete(pending_supervisors_table).where(
                    pending_supervisors_table.c.email == row.email
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
            mask_email_reference(email_hash),
        )
        return False

    logger.info("Supervisor %s activated", mask_email_reference(row.email))
    return True


def supervisor_exists(email: str) -> bool:
    # Return ``True`` if a supervisor with ``email`` exists.
    email_values = email_lookup_values(email)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(supervisors_table.c.id).where(supervisors_table.c.email.in_(email_values))
        ).first()
    return row is not None


def verify_supervisor_credentials(email: str, password: str) -> bool:
    # Return ``True`` if ``email`` and ``password`` match a supervisor.
    try:
        email_values = _email_reference_values(email)
    except ValueError:
        return False
    with get_engine().connect() as conn:
        row = conn.execute(
            select(supervisors_table.c.password).where(supervisors_table.c.email.in_(email_values))
        ).first()
    if not row:
        return False
    return verify_password(row.password, password)


def get_supervisor_login_details_for_orgnr(
    orgnr: str,
) -> Optional[Dict[str, str]]:
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

    candidates: list[tuple[str, tuple[str, ...], str]] = []
    email_references: list[str] = []
    for row in rows:
        mapping = row._mapping
        stored_email = (mapping["email"] or "").strip()
        try:
            lookup_values = _email_reference_values(stored_email)
        except ValueError:
            continue
        login_email = (
            stored_email if _is_valid_hash(stored_email) else normalize_email(stored_email)
        )
        candidates.append((login_email, lookup_values, mapping["name"]))
        email_references.extend(lookup_values)

    if not email_references:
        return None

    with get_engine().connect() as conn:
        supervisor_rows = conn.execute(
            select(supervisors_table.c.email, supervisors_table.c.name).where(
                supervisors_table.c.email.in_(email_references)
            )
        ).fetchall()

    names_by_reference = {row.email: row.name for row in supervisor_rows}

    for normalized_email, lookup_values, fallback_name in candidates:
        for email_reference in lookup_values:
            supervisor_name = names_by_reference.get(email_reference)
            if supervisor_name is None:
                continue
            return {
                "email": normalized_email,
                "email_hash": email_reference,
                "name": supervisor_name or fallback_name,
                "orgnr": normalized_orgnr,
            }

    return None


def get_supervisor_name_by_hash(email_hash: str) -> Optional[str]:
    # Return the name of the supervisor identified by ``email_hash``.
    try:
        email_values = _email_reference_values(email_hash)
    except ValueError:
        return None
    with get_engine().connect() as conn:
        row = conn.execute(
            select(supervisors_table.c.name).where(supervisors_table.c.email.in_(email_values))
        ).first()
    if not row:
        return None
    return row.name


def _get_company_names_by_supervisor_hashes(
    supervisor_email_hashes: List[str],
) -> Dict[str, str]:
    # Match supervisor e-mail hashes to company names when available.
    unique_references: set[str] = set()
    for email_reference in supervisor_email_hashes:
        try:
            unique_references.update(_email_reference_values(email_reference))
        except ValueError:
            continue
    if not unique_references:
        return {}

    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                company_users_table.c.email,
                companies_table.c.name,
                company_users_table.c.updated_at,
                company_users_table.c.id,
            )
            .select_from(
                company_users_table.join(
                    companies_table,
                    company_users_table.c.company_id == companies_table.c.id,
                )
            )
            .where(company_users_table.c.role == "foretagskonto")
            .order_by(
                company_users_table.c.updated_at.desc(),
                company_users_table.c.id.desc(),
            )
        ).fetchall()

    company_names_by_hash: Dict[str, str] = {}
    for row in rows:
        try:
            lookup_values = email_lookup_values(row.email)
        except ValueError:
            continue

        for email_reference in lookup_values:
            if (
                email_reference not in unique_references
                or email_reference in company_names_by_hash
            ):
                continue
            company_names_by_hash[email_reference] = row.name

    return company_names_by_hash


def get_supervisor_email_hash(email: str) -> str:
    # Return the e-mail reference used for supervisor tables.
    normalized, legacy_hash = email_lookup_values(email)
    email_values = (normalized, legacy_hash)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(supervisors_table.c.email).where(supervisors_table.c.email.in_(email_values))
        ).first()
        if row:
            return row.email
        pending = conn.execute(
            select(pending_supervisors_table.c.email).where(
                pending_supervisors_table.c.email.in_(email_values)
            )
        ).first()
    return pending.email if pending else normalized


def list_supervisor_connections(email_hash: str) -> List[Dict[str, Any]]:
    # Return connected users for the given supervisor hash.
    try:
        email_values = _email_reference_values(email_hash)
    except ValueError:
        logger.warning("Avvisade ogiltig e-postreferens")
        return []
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                supervisor_connections_table.c.user_personnummer,
                users_table.c.username,
            )
            .select_from(
                supervisor_connections_table.join(
                    users_table,
                    supervisor_connections_table.c.user_personnummer == users_table.c.personnummer,
                )
            )
            .where(supervisor_connections_table.c.supervisor_email.in_(email_values))
            .order_by(users_table.c.username.asc())
        )

        return [
            {
                "personnummer_hash": row.user_personnummer,
                "username": row.username,
            }
            for row in rows
        ]


def supervisor_has_access(supervisor_email_hash: str, personnummer_hash: str) -> bool:
    # Return ``True`` if supervisor has access to the given user.
    try:
        email_values = _email_reference_values(supervisor_email_hash)
    except ValueError:
        logger.warning("Avvisade ogiltig e-postreferens")
        return False
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    with get_engine().connect() as conn:
        row = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email.in_(email_values),
                supervisor_connections_table.c.user_personnummer == personnummer_hash,
            )
        ).first()
    return row is not None


def supervisor_remove_connection(supervisor_email_hash: str, personnummer_hash: str) -> bool:
    # Remove a connection between supervisor and user.
    try:
        email_values = _email_reference_values(supervisor_email_hash)
    except ValueError:
        logger.warning("Avvisade ogiltig e-postreferens")
        return False
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(supervisor_connections_table).where(
                supervisor_connections_table.c.supervisor_email.in_(email_values),
                supervisor_connections_table.c.user_personnummer == personnummer_hash,
            )
        )
    return result.rowcount > 0


def list_user_supervisor_connections(personnummer_hash: str) -> List[Dict[str, Any]]:
    # Return connected supervisors for a given user hash.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return []
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                supervisor_connections_table.c.id,
                supervisor_connections_table.c.supervisor_email,
                supervisors_table.c.name,
            )
            .select_from(
                supervisor_connections_table.join(
                    supervisors_table,
                    supervisor_connections_table.c.supervisor_email == supervisors_table.c.email,
                )
            )
            .where(supervisor_connections_table.c.user_personnummer == personnummer_hash)
        ).fetchall()

    company_names_by_hash = _get_company_names_by_supervisor_hashes(
        [row.supervisor_email for row in rows]
    )
    connections = [
        {
            "connection_id": int(row.id),
            "supervisor_email": row.supervisor_email,
            "supervisor_name": company_names_by_hash.get(row.supervisor_email) or row.name,
        }
        for row in rows
    ]
    connections.sort(key=lambda connection: connection["supervisor_name"].casefold())
    return connections


def user_remove_supervisor_connection_by_id(
    personnummer_hash: str,
    connection_id: int,
) -> bool:
    # Remove a user-owned connection without exposing the supervisor e-mail reference.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    if connection_id <= 0:
        logger.warning("Avvisade ogiltigt kopplings-id")
        return False
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(supervisor_connections_table).where(
                supervisor_connections_table.c.id == connection_id,
                supervisor_connections_table.c.user_personnummer == personnummer_hash,
            )
        )
    return result.rowcount > 0


def list_user_link_requests(personnummer_hash: str) -> List[Dict[str, str]]:
    # Return pending supervisor link requests for a user.
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
                    supervisor_link_requests_table.c.supervisor_email == supervisors_table.c.email,
                )
            )
            .where(supervisor_link_requests_table.c.user_personnummer == personnummer_hash)
        ).fetchall()

    company_names_by_hash = _get_company_names_by_supervisor_hashes(
        [row.supervisor_email for row in rows]
    )
    requests = [
        {
            "supervisor_email": row.supervisor_email,
            "supervisor_name": company_names_by_hash.get(row.supervisor_email) or row.name,
        }
        for row in rows
    ]
    requests.sort(key=lambda request: request["supervisor_name"].casefold())
    return requests


def create_supervisor_link_request(
    supervisor_email_hash: str, personnummer: str
) -> tuple[bool, str]:
    # Create a link request from a supervisor to a user.
    try:
        email_values = _email_reference_values(supervisor_email_hash)
    except ValueError:
        logger.warning("Avvisade ogiltig e-postreferens")
        return False, "invalid_supervisor"
    pnr_hash = _hash_personnummer(personnummer)

    with get_engine().begin() as conn:
        supervisor_row = conn.execute(
            select(supervisors_table.c.email).where(supervisors_table.c.email.in_(email_values))
        ).first()
        if not supervisor_row:
            logger.warning(
                "Supervisor %s not found for link request",
                mask_email_reference(supervisor_email_hash),
            )
            return False, "missing_supervisor"
        supervisor_email_reference = supervisor_row.email

        user_row = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
        if not user_row:
            logger.warning(
                "User %s not found for link request from %s",
                mask_hash(pnr_hash),
                mask_email_reference(supervisor_email_reference),
            )
            return False, "missing_user"

        existing_connection = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email.in_(email_values),
                supervisor_connections_table.c.user_personnummer == pnr_hash,
            )
        ).first()
        if existing_connection:
            return False, "already_connected"

        existing_request = conn.execute(
            select(supervisor_link_requests_table.c.id).where(
                supervisor_link_requests_table.c.supervisor_email.in_(email_values),
                supervisor_link_requests_table.c.user_personnummer == pnr_hash,
            )
        ).first()
        if existing_request:
            return False, "already_requested"

        conn.execute(
            insert(supervisor_link_requests_table).values(
                supervisor_email=supervisor_email_reference,
                user_personnummer=pnr_hash,
            )
        )

    logger.info(
        "Supervisor %s requested link with %s",
        mask_email_reference(supervisor_email_reference),
        mask_hash(pnr_hash),
    )
    return True, "created"


def user_accept_link_request(personnummer_hash: str, supervisor_email_hash: str) -> bool:
    # Accept a supervisor link request and create the connection.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    try:
        email_values = _email_reference_values(supervisor_email_hash)
    except ValueError:
        logger.warning("Avvisade ogiltig e-postreferens")
        return False

    with get_engine().begin() as conn:
        request_row = conn.execute(
            select(
                supervisor_link_requests_table.c.id,
                supervisor_link_requests_table.c.supervisor_email,
            ).where(
                supervisor_link_requests_table.c.supervisor_email.in_(email_values),
                supervisor_link_requests_table.c.user_personnummer == personnummer_hash,
            )
        ).first()
        if not request_row:
            return False

        existing_connection = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email == request_row.supervisor_email,
                supervisor_connections_table.c.user_personnummer == personnummer_hash,
            )
        ).first()
        if not existing_connection:
            conn.execute(
                insert(supervisor_connections_table).values(
                    supervisor_email=request_row.supervisor_email,
                    user_personnummer=personnummer_hash,
                )
            )

        conn.execute(
            delete(supervisor_link_requests_table).where(
                supervisor_link_requests_table.c.id == request_row.id
            )
        )
    return True


def user_reject_link_request(personnummer_hash: str, supervisor_email_hash: str) -> bool:
    # Reject a supervisor link request.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    try:
        email_values = _email_reference_values(supervisor_email_hash)
    except ValueError:
        logger.warning("Avvisade ogiltig e-postreferens")
        return False
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(supervisor_link_requests_table).where(
                supervisor_link_requests_table.c.supervisor_email.in_(email_values),
                supervisor_link_requests_table.c.user_personnummer == personnummer_hash,
            )
        )
    return result.rowcount > 0


def user_remove_supervisor_connection(personnummer_hash: str, supervisor_email_hash: str) -> bool:
    # Remove a supervisor connection from the user side.
    if not _is_valid_hash(personnummer_hash):
        logger.warning("Avvisade ogiltig hash för personnummer")
        return False
    try:
        email_values = _email_reference_values(supervisor_email_hash)
    except ValueError:
        logger.warning("Avvisade ogiltig e-postreferens")
        return False
    with get_engine().begin() as conn:
        result = conn.execute(
            delete(supervisor_connections_table).where(
                supervisor_connections_table.c.supervisor_email.in_(email_values),
                supervisor_connections_table.c.user_personnummer == personnummer_hash,
            )
        )
    return result.rowcount > 0


def admin_link_supervisor_to_user(
    orgnr: str, personnummer: str
) -> tuple[bool, str, Optional[str]]:
    # Create a connection between a supervisor and a user.
    details = get_supervisor_login_details_for_orgnr(orgnr)
    if not details:
        logger.warning("Supervisor not found for orgnr %s", orgnr)
        return False, "missing_supervisor", None
    email_hash = details["email_hash"]
    email_values = _email_reference_values(email_hash)
    pnr_hash = _hash_personnummer(personnummer)

    with get_engine().begin() as conn:
        user_row = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == pnr_hash)
        ).first()
        if not user_row:
            logger.warning(
                "User %s not found when linking supervisor %s",
                mask_hash(pnr_hash),
                mask_email_reference(email_hash),
            )
            return False, "missing_user", email_hash

        existing = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email.in_(email_values),
                supervisor_connections_table.c.user_personnummer == pnr_hash,
            )
        ).first()
        if existing:
            logger.info(
                "Supervisor %s already connected to %s",
                mask_email_reference(email_hash),
                mask_hash(pnr_hash),
            )
            return False, "exists", email_hash

        conn.execute(
            insert(supervisor_connections_table).values(
                supervisor_email=email_hash,
                user_personnummer=pnr_hash,
            )
        )
        conn.execute(
            delete(supervisor_link_requests_table).where(
                supervisor_link_requests_table.c.supervisor_email.in_(email_values),
                supervisor_link_requests_table.c.user_personnummer == pnr_hash,
            )
        )

    logger.info(
        "Supervisor %s connected to user %s",
        mask_email_reference(email_hash),
        mask_hash(pnr_hash),
    )
    return True, "created", email_hash


def get_supervisor_overview(email_hash: str) -> Optional[Dict[str, Any]]:
    # Return supervisor info together with connected users.
    try:
        email_values = _email_reference_values(email_hash)
    except ValueError:
        return None
    with get_engine().connect() as conn:
        supervisor_row = conn.execute(
            select(supervisors_table.c.email, supervisors_table.c.name).where(
                supervisors_table.c.email.in_(email_values)
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
                    supervisor_connections_table.c.user_personnummer == users_table.c.personnummer,
                )
            )
            .where(supervisor_connections_table.c.supervisor_email.in_(email_values))
            .order_by(users_table.c.username.asc())
        )

        return {
            "name": supervisor_row.name,
            "email_hash": supervisor_row.email,
            "connections": [
                {
                    "personnummer_hash": row.user_personnummer,
                    "username": row.username,
                }
                for row in connections
            ],
        }


def admin_delete_supervisor_account(
    orgnr: str,
) -> tuple[bool, dict[str, int], str]:
    # Remove a supervisor account and related records based on orgnr.
    normalized_orgnr = validate_orgnr(orgnr)
    summary: dict[str, int] = {
        "company_users": 0,
        "supervisors": 0,
        "pending_supervisors": 0,
        "supervisor_connections": 0,
        "supervisor_link_requests": 0,
        "supervisor_password_resets": 0,
        "companies": 0,
    }
    with get_engine().begin() as conn:
        rows = conn.execute(
            select(company_users_table.c.email, company_users_table.c.company_id)
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
        ).fetchall()

        if not rows:
            return False, summary, normalized_orgnr

        email_references: list[str] = []
        company_ids = {row.company_id for row in rows if row.company_id is not None}
        for row in rows:
            try:
                email_references.extend(email_lookup_values(row.email))
            except ValueError:
                continue

        if company_ids:
            summary["company_users"] = (
                conn.execute(
                    delete(company_users_table).where(
                        company_users_table.c.company_id.in_(company_ids),
                        company_users_table.c.role == "foretagskonto",
                    )
                ).rowcount
                or 0
            )

        if email_references:
            summary["supervisors"] = (
                conn.execute(
                    delete(supervisors_table).where(
                        supervisors_table.c.email.in_(email_references)
                    )
                ).rowcount
                or 0
            )
            summary["pending_supervisors"] = (
                conn.execute(
                    delete(pending_supervisors_table).where(
                        pending_supervisors_table.c.email.in_(email_references)
                    )
                ).rowcount
                or 0
            )
            summary["supervisor_connections"] = (
                conn.execute(
                    delete(supervisor_connections_table).where(
                        supervisor_connections_table.c.supervisor_email.in_(email_references)
                    )
                ).rowcount
                or 0
            )
            summary["supervisor_link_requests"] = (
                conn.execute(
                    delete(supervisor_link_requests_table).where(
                        supervisor_link_requests_table.c.supervisor_email.in_(email_references)
                    )
                ).rowcount
                or 0
            )
            summary["supervisor_password_resets"] = (
                conn.execute(
                    delete(supervisor_password_resets_table).where(
                        supervisor_password_resets_table.c.email.in_(email_references)
                    )
                ).rowcount
                or 0
            )

        if company_ids:
            remaining = conn.execute(
                select(company_users_table.c.id).where(
                    company_users_table.c.company_id.in_(company_ids)
                )
            ).first()
            if not remaining:
                summary["companies"] = (
                    conn.execute(
                        delete(companies_table).where(companies_table.c.id.in_(company_ids))
                    ).rowcount
                    or 0
                )

    logger.info("Admin raderade företagskonto för %s", normalized_orgnr)
    return True, summary, normalized_orgnr
