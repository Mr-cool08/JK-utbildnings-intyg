# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

import logging
from functools import lru_cache
import os
from typing import Any, Optional

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError

from functions.database import (
    application_requests_table,
    company_users_table,
    organization_link_requests_table,
    password_resets_table,
    pending_supervisors_table,
    pending_users_table,
    supervisor_connections_table,
    supervisor_link_requests_table,
    supervisor_password_resets_table,
    supervisors_table,
    user_pdfs_table,
    users_table,
    get_engine,
)
from functions.hashing import (
    _hash_personnummer,
    _is_valid_hash,
    email_lookup_values,
    hash_password,
    normalize_email,
    verify_password,
)
from functions.logging import configure_module_logger, mask_hash
from functions.organization_links import update_organization_request_contact_details


logger = configure_module_logger(__name__)

# Allow overriding module log level via environment variable (e.g. LOG_LEVEL="DEBUG").
# If unset or invalid, keep the logger's configured level (from root/configure_root_logging).
_env_level = (os.getenv("LOG_LEVEL") or "").strip()
if _env_level:
    _level = None
    # Accept numeric levels or common level names.
    if _env_level.isdigit():
        try:
            _level = int(_env_level)
        except ValueError:
            _level = None
    else:
        _name = _env_level.upper()
        _level = {
            "CRITICAL": logging.CRITICAL,
            "FATAL": logging.FATAL,
            "ERROR": logging.ERROR,
            "WARN": logging.WARNING,
            "WARNING": logging.WARNING,
            "INFO": logging.INFO,
            "DEBUG": logging.DEBUG,
            "NOTSET": logging.NOTSET,
        }.get(_name)

    if isinstance(_level, int):
        logger.setLevel(_level)


def _is_legacy_email_hash(value: str | None) -> bool:
    return bool(value and _is_valid_hash(value))


def check_password_user(email: str, password: str) -> bool:
    # Return True if ``email`` and ``password`` match a user.
    email_values = email_lookup_values(email)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.password).where(users_table.c.email.in_(email_values))
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
    email_values = email_lookup_values(email)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.id).where(users_table.c.email.in_(email_values))
        ).first()
    return row is not None


def get_username(email: str) -> Optional[str]:
    # Return the username associated with ``email`` or ``None``.
    email_values = email_lookup_values(email)
    with get_engine().connect() as conn:
        row = conn.execute(
            select(users_table.c.username).where(users_table.c.email.in_(email_values))
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
    email_values = email_lookup_values(normalized_email)
    try:
        with get_engine().begin() as conn:
            existing_user = conn.execute(
                select(users_table.c.id).where(users_table.c.email.in_(email_values))
            ).first()
            if existing_user:
                logger.warning("Attempt to recreate existing user for e-post")
                return False
            existing_pending_email = conn.execute(
                select(pending_users_table.c.id).where(
                    pending_users_table.c.email.in_(email_values)
                )
            ).first()
            if existing_pending_email:
                logger.warning("Pending user already exists for e-post")
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
                    email=normalized_email,
                    username=username,
                    personnummer=pnr_hash,
                    orgnr_normalized="",
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
                    pending_users_table.c.orgnr_normalized,
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
                    orgnr_normalized=row.orgnr_normalized or "",
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
        summary["organization_link_requests"] = (
            conn.execute(
                delete(organization_link_requests_table).where(
                    organization_link_requests_table.c.user_personnummer == personnummer_hash
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


def list_legacy_email_references() -> dict[str, list[dict[str, Any]]]:
    # Return stored e-mail references that still use the legacy hash format.
    standard_accounts: list[dict[str, Any]] = []
    supervisor_references: dict[str, dict[str, Any]] = {}

    def add_standard(
        table_name: str,
        status: str,
        row_id: int,
        username: str,
        personnummer_hash: str,
        email_hash: str,
    ) -> None:
        standard_accounts.append(
            {
                "table": table_name,
                "status": status,
                "id": row_id,
                "username": username,
                "personnummer_hash": personnummer_hash,
                "email_hash": email_hash,
            }
        )

    def add_supervisor(email_hash: str, source: str, name: str | None = None) -> None:
        entry = supervisor_references.setdefault(
            email_hash,
            {
                "email_hash": email_hash,
                "name": "",
                "sources": {},
            },
        )
        if name and not entry["name"]:
            entry["name"] = name
        sources = entry["sources"]
        sources[source] = sources.get(source, 0) + 1

    with get_engine().connect() as conn:
        user_rows = conn.execute(
            select(
                users_table.c.id,
                users_table.c.username,
                users_table.c.personnummer,
                users_table.c.email,
            )
        ).fetchall()
        pending_rows = conn.execute(
            select(
                pending_users_table.c.id,
                pending_users_table.c.username,
                pending_users_table.c.personnummer,
                pending_users_table.c.email,
            )
        ).fetchall()
        supervisor_rows = conn.execute(
            select(supervisors_table.c.name, supervisors_table.c.email)
        ).fetchall()
        pending_supervisor_rows = conn.execute(
            select(pending_supervisors_table.c.name, pending_supervisors_table.c.email)
        ).fetchall()
        connection_rows = conn.execute(
            select(supervisor_connections_table.c.supervisor_email)
        ).fetchall()
        link_request_rows = conn.execute(
            select(supervisor_link_requests_table.c.supervisor_email)
        ).fetchall()
        supervisor_reset_rows = conn.execute(
            select(supervisor_password_resets_table.c.email)
        ).fetchall()
        organization_rows = conn.execute(
            select(organization_link_requests_table.c.handled_by_supervisor_email)
        ).fetchall()
        application_rows = conn.execute(
            select(
                application_requests_table.c.account_type,
                application_requests_table.c.name,
                application_requests_table.c.email,
            )
        ).fetchall()
        company_user_rows = conn.execute(
            select(
                company_users_table.c.role,
                company_users_table.c.name,
                company_users_table.c.email,
            )
        ).fetchall()

    for row in user_rows:
        if _is_legacy_email_hash(row.email):
            add_standard(
                users_table.name,
                "active",
                int(row.id),
                row.username,
                row.personnummer,
                row.email,
            )
    for row in pending_rows:
        if _is_legacy_email_hash(row.email):
            add_standard(
                pending_users_table.name,
                "pending",
                int(row.id),
                row.username,
                row.personnummer,
                row.email,
            )
    for row in supervisor_rows:
        if _is_legacy_email_hash(row.email):
            add_supervisor(row.email, supervisors_table.name, row.name)
    for row in pending_supervisor_rows:
        if _is_legacy_email_hash(row.email):
            add_supervisor(row.email, pending_supervisors_table.name, row.name)
    for row in connection_rows:
        if _is_legacy_email_hash(row.supervisor_email):
            add_supervisor(row.supervisor_email, supervisor_connections_table.name)
    for row in link_request_rows:
        if _is_legacy_email_hash(row.supervisor_email):
            add_supervisor(row.supervisor_email, supervisor_link_requests_table.name)
    for row in supervisor_reset_rows:
        if _is_legacy_email_hash(row.email):
            add_supervisor(row.email, supervisor_password_resets_table.name)
    for row in organization_rows:
        if _is_legacy_email_hash(row.handled_by_supervisor_email):
            add_supervisor(
                row.handled_by_supervisor_email,
                organization_link_requests_table.name,
            )
    for row in application_rows:
        if row.account_type == "foretagskonto" and _is_legacy_email_hash(row.email):
            add_supervisor(row.email, application_requests_table.name, row.name)
    for row in company_user_rows:
        if row.role == "foretagskonto" and _is_legacy_email_hash(row.email):
            add_supervisor(row.email, company_users_table.name, row.name)

    return {
        "standard_accounts": standard_accounts,
        "supervisor_references": sorted(
            supervisor_references.values(),
            key=lambda item: (item.get("name") or "", item["email_hash"]),
        ),
    }


def _replace_supervisor_pair_reference(
    conn,
    table,
    legacy_hash: str,
    normalized_email: str,
) -> int:
    changed = 0
    rows = conn.execute(
        select(table.c.id, table.c.user_personnummer).where(
            table.c.supervisor_email == legacy_hash
        )
    ).fetchall()
    for row in rows:
        existing = conn.execute(
            select(table.c.id).where(
                table.c.supervisor_email == normalized_email,
                table.c.user_personnummer == row.user_personnummer,
            )
        ).first()
        if existing:
            changed += conn.execute(delete(table).where(table.c.id == row.id)).rowcount or 0
            continue
        changed += (
            conn.execute(
                update(table)
                .where(table.c.id == row.id)
                .values(supervisor_email=normalized_email)
            ).rowcount
            or 0
        )
    return changed


def complete_legacy_email_reference(
    reference_type: str,
    email_hash: str,
    email: str,
    personnummer_hash: str | None = None,
) -> tuple[bool, dict[str, int] | None, str | None]:
    # Replace a legacy e-mail hash with a verified normalized plaintext address.
    if not _is_valid_hash(email_hash):
        return False, None, "invalid_hash"
    normalized_email = normalize_email(email)
    _, expected_hash = email_lookup_values(normalized_email)
    if expected_hash != email_hash:
        return False, None, "hash_mismatch"

    if reference_type == "standardkonto":
        return _complete_standard_legacy_email(
            email_hash,
            normalized_email,
            personnummer_hash,
        )
    if reference_type == "foretagskonto":
        return _complete_supervisor_legacy_email(email_hash, normalized_email)
    return False, None, "invalid_type"


def _complete_standard_legacy_email(
    email_hash: str,
    normalized_email: str,
    personnummer_hash: str | None,
) -> tuple[bool, dict[str, int] | None, str | None]:
    if personnummer_hash and not _is_valid_hash(personnummer_hash):
        return False, None, "invalid_personnummer"
    email_values = email_lookup_values(normalized_email)
    with get_engine().begin() as conn:
        user_conditions = [users_table.c.email == email_hash]
        pending_conditions = [pending_users_table.c.email == email_hash]
        if personnummer_hash:
            user_conditions.append(users_table.c.personnummer == personnummer_hash)
            pending_conditions.append(pending_users_table.c.personnummer == personnummer_hash)

        user_targets = conn.execute(
            select(users_table.c.personnummer).where(*user_conditions)
        ).fetchall()
        pending_targets = conn.execute(
            select(pending_users_table.c.personnummer).where(*pending_conditions)
        ).fetchall()
        target_personnummer = {
            row.personnummer for row in [*user_targets, *pending_targets]
        }
        if not target_personnummer:
            return False, None, "missing"

        active_conflict = conn.execute(
            select(users_table.c.id).where(
                users_table.c.email.in_(email_values),
                users_table.c.personnummer.not_in(target_personnummer),
            )
        ).first()
        pending_conflict = conn.execute(
            select(pending_users_table.c.id).where(
                pending_users_table.c.email.in_(email_values),
                pending_users_table.c.personnummer.not_in(target_personnummer),
            )
        ).first()
        if active_conflict or pending_conflict:
            return False, None, "email_in_use"

        summary: dict[str, int] = {}
        summary["users"] = (
            conn.execute(
                update(users_table).where(*user_conditions).values(email=normalized_email)
            ).rowcount
            or 0
        )
        summary["pending_users"] = (
            conn.execute(
                update(pending_users_table)
                .where(*pending_conditions)
                .values(email=normalized_email)
            ).rowcount
            or 0
        )
        summary["password_resets"] = (
            conn.execute(
                update(password_resets_table)
                .where(
                    password_resets_table.c.email == email_hash,
                    password_resets_table.c.personnummer.in_(target_personnummer),
                )
                .values(email=normalized_email)
            ).rowcount
            or 0
        )
        summary["organization_link_requests"] = (
            conn.execute(
                update(organization_link_requests_table)
                .where(
                    organization_link_requests_table.c.user_email == email_hash,
                    organization_link_requests_table.c.user_personnummer.in_(
                        target_personnummer
                    ),
                )
                .values(user_email=normalized_email)
            ).rowcount
            or 0
        )
        summary["application_requests"] = (
            conn.execute(
                update(application_requests_table)
                .where(
                    application_requests_table.c.email == email_hash,
                    application_requests_table.c.personnummer_hash.in_(
                        target_personnummer
                    ),
                )
                .values(email=normalized_email)
            ).rowcount
            or 0
        )

    logger.info("Admin kompletterade e-posthash för standardkonto")
    return True, summary, None


def _complete_supervisor_legacy_email(
    email_hash: str,
    normalized_email: str,
) -> tuple[bool, dict[str, int] | None, str | None]:
    email_values = email_lookup_values(normalized_email)
    with get_engine().begin() as conn:
        existing_total = 0
        for query in (
            select(supervisors_table.c.id).where(supervisors_table.c.email == email_hash),
            select(pending_supervisors_table.c.id).where(
                pending_supervisors_table.c.email == email_hash
            ),
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email == email_hash
            ),
            select(supervisor_link_requests_table.c.id).where(
                supervisor_link_requests_table.c.supervisor_email == email_hash
            ),
            select(supervisor_password_resets_table.c.id).where(
                supervisor_password_resets_table.c.email == email_hash
            ),
            select(organization_link_requests_table.c.id).where(
                organization_link_requests_table.c.handled_by_supervisor_email == email_hash
            ),
            select(application_requests_table.c.id).where(
                application_requests_table.c.account_type == "foretagskonto",
                application_requests_table.c.email == email_hash,
            ),
            select(company_users_table.c.id).where(
                company_users_table.c.role == "foretagskonto",
                company_users_table.c.email == email_hash,
            ),
        ):
            if conn.execute(query).first():
                existing_total += 1
        if not existing_total:
            return False, None, "missing"

        active_conflict = conn.execute(
            select(supervisors_table.c.id).where(
                supervisors_table.c.email.in_(email_values),
                supervisors_table.c.email != email_hash,
            )
        ).first()
        pending_conflict = conn.execute(
            select(pending_supervisors_table.c.id).where(
                pending_supervisors_table.c.email.in_(email_values),
                pending_supervisors_table.c.email != email_hash,
            )
        ).first()
        if active_conflict or pending_conflict:
            return False, None, "email_in_use"

        try:
            summary = {
                "supervisors": conn.execute(
                    update(supervisors_table)
                    .where(supervisors_table.c.email == email_hash)
                    .values(email=normalized_email)
                ).rowcount
                or 0,
                "pending_supervisors": conn.execute(
                    update(pending_supervisors_table)
                    .where(pending_supervisors_table.c.email == email_hash)
                    .values(email=normalized_email)
                ).rowcount
                or 0,
                "application_requests": conn.execute(
                    update(application_requests_table)
                    .where(
                        application_requests_table.c.account_type == "foretagskonto",
                        application_requests_table.c.email == email_hash,
                    )
                    .values(email=normalized_email)
                ).rowcount
                or 0,
                "company_users": conn.execute(
                    update(company_users_table)
                    .where(
                        company_users_table.c.role == "foretagskonto",
                        company_users_table.c.email == email_hash,
                    )
                    .values(email=normalized_email)
                ).rowcount
                or 0,
                "supervisor_connections": _replace_supervisor_pair_reference(
                    conn,
                    supervisor_connections_table,
                    email_hash,
                    normalized_email,
                ),
                "supervisor_link_requests": _replace_supervisor_pair_reference(
                    conn,
                    supervisor_link_requests_table,
                    email_hash,
                    normalized_email,
                ),
                "supervisor_password_resets": conn.execute(
                    update(supervisor_password_resets_table)
                    .where(supervisor_password_resets_table.c.email == email_hash)
                    .values(email=normalized_email)
                ).rowcount
                or 0,
                "organization_link_requests": conn.execute(
                    update(organization_link_requests_table)
                    .where(
                        organization_link_requests_table.c.handled_by_supervisor_email
                        == email_hash
                    )
                    .values(handled_by_supervisor_email=normalized_email)
                ).rowcount
                or 0,
            }
        except IntegrityError:
            return False, None, "email_in_use"

    logger.info("Admin kompletterade e-posthash för företagskonto")
    return True, summary, None


def get_admin_password_status(
    personnummer: str,
    email: str | None = None,
) -> dict[str, str | bool] | None:
    # Return password and activation status for a standard account.
    pnr_hash = _hash_personnummer(personnummer)
    normalized_email = normalize_email(email) if email else None
    email_values = email_lookup_values(normalized_email) if normalized_email else None

    with get_engine().connect() as conn:
        active_conditions = [users_table.c.personnummer == pnr_hash]
        if email_values:
            active_conditions.append(users_table.c.email.in_(email_values))
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
        if email_values:
            pending_conditions.append(pending_users_table.c.email.in_(email_values))
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
    email_values = email_lookup_values(normalized_email) if normalized_email else None

    with get_engine().connect() as conn:
        conditions = [pending_users_table.c.personnummer == pnr_hash]
        if email_values:
            conditions.append(pending_users_table.c.email.in_(email_values))
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
    email_values = email_lookup_values(normalized_email)
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
                users_table.c.email.in_(email_values),
                users_table.c.personnummer != pnr_hash,
            )
        ).first()
        if email_conflict:
            return False, None, "email_in_use"

        pending_conflict = conn.execute(
            select(pending_users_table.c.id).where(
                pending_users_table.c.email.in_(email_values),
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
                .values(username=username, email=normalized_email)
            ).rowcount
            or 0
        )
        summary["pending_users"] = (
            conn.execute(
                update(pending_users_table)
                .where(pending_users_table.c.personnummer == pnr_hash)
                .values(username=username, email=normalized_email)
            ).rowcount
            or 0
        )

    logger.info(
        "Admin uppdaterade konto för %s",
        mask_hash(pnr_hash),
    )
    summary["organization_link_requests"] = update_organization_request_contact_details(
        pnr_hash,
        username,
        normalized_email,
    )
    return True, summary, None
