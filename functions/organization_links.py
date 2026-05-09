from __future__ import annotations

import logging
from typing import Any, Callable

from sqlalchemy import func, insert, select, update
from sqlalchemy.exc import IntegrityError

from functions.database import (
    companies_table,
    company_users_table,
    get_engine,
    organization_link_requests_table,
    pending_users_table,
    supervisor_connections_table,
    users_table,
)
from functions.hashing import (
    _is_valid_hash,
    hash_value,
    normalize_email,
    normalize_personnummer,
    validate_orgnr,
)
from functions.logging import configure_module_logger, mask_hash


logger = configure_module_logger(__name__)
logger.setLevel(logging.DEBUG)


def register_standard_account(
    name: str,
    email: str,
    personnummer: str,
    orgnr: str | None = None,
    *,
    before_commit: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    # Skapa ett väntande privatkonto och registrera eventuell org-förfrågan.
    cleaned_name = (name or "").strip()
    if not cleaned_name:
        raise ValueError("Namn saknas. Ange ditt fullständiga namn.")

    normalized_email = normalize_email(email)
    normalized_personnummer = normalize_personnummer(personnummer)
    normalized_orgnr = validate_orgnr(orgnr) if (orgnr or "").strip() else ""
    email_hash = hash_value(normalized_email)
    personnummer_hash = hash_value(normalized_personnummer)

    result: dict[str, Any] = {}

    with get_engine().begin() as conn:
        existing_user_by_personnummer = conn.execute(
            select(users_table.c.id).where(users_table.c.personnummer == personnummer_hash)
        ).first()
        existing_pending_by_personnummer = conn.execute(
            select(pending_users_table.c.id).where(
                pending_users_table.c.personnummer == personnummer_hash
            )
        ).first()
        if existing_user_by_personnummer or existing_pending_by_personnummer:
            raise ValueError("Det finns redan ett privatkonto med detta personnummer.")

        existing_user_by_email = conn.execute(
            select(users_table.c.id).where(users_table.c.email == email_hash)
        ).first()
        existing_pending_by_email = conn.execute(
            select(pending_users_table.c.id).where(pending_users_table.c.email == email_hash)
        ).first()
        if existing_user_by_email or existing_pending_by_email:
            raise ValueError("E-postadressen används redan för ett befintligt konto.")

        try:
            conn.execute(
                insert(pending_users_table).values(
                    username=cleaned_name,
                    email=email_hash,
                    personnummer=personnummer_hash,
                    orgnr_normalized=normalized_orgnr,
                )
            )
        except IntegrityError as exc:
            raise ValueError("Kontot kunde inte skapas just nu. Försök igen senare.") from exc

        if normalized_orgnr:
            try:
                conn.execute(
                    insert(organization_link_requests_table).values(
                        orgnr_normalized=normalized_orgnr,
                        user_personnummer=personnummer_hash,
                        user_name=cleaned_name,
                        user_email=normalized_email,
                    )
                )
            except IntegrityError:
                conn.execute(
                    update(organization_link_requests_table)
                    .where(
                        organization_link_requests_table.c.orgnr_normalized == normalized_orgnr,
                        organization_link_requests_table.c.user_personnummer
                        == personnummer_hash,
                    )
                    .values(
                        user_name=cleaned_name,
                        user_email=normalized_email,
                        status="pending",
                        handled_by_supervisor_email=None,
                        handled_at=None,
                    )
                )

        result = {
            "email": normalized_email,
            "personnummer_hash": personnummer_hash,
            "orgnr_normalized": normalized_orgnr,
            "organization_request_created": bool(normalized_orgnr),
        }
        if before_commit is not None:
            before_commit(result)

    logger.info("Registrerade väntande privatkonto %s", mask_hash(personnummer_hash))
    return result


def get_public_organization_overview(orgnr: str) -> dict[str, Any]:
    # Returnera publik översikt för organisationsnummer.
    normalized_orgnr = validate_orgnr(orgnr)
    with get_engine().connect() as conn:
        user_count = conn.execute(
            select(func.count()).select_from(users_table).where(
                users_table.c.orgnr_normalized == normalized_orgnr
            )
        ).scalar_one()

        company_row = conn.execute(
            select(companies_table.c.name)
            .select_from(
                companies_table.join(
                    company_users_table,
                    company_users_table.c.company_id == companies_table.c.id,
                )
            )
            .where(
                companies_table.c.orgnr == normalized_orgnr,
                company_users_table.c.role == "foretagskonto",
            )
            .order_by(companies_table.c.updated_at.desc(), companies_table.c.id.desc())
        ).first()

    return {
        "orgnr": normalized_orgnr,
        "user_count": int(user_count or 0),
        "company_name": company_row.name if company_row else None,
    }


def list_pending_organization_link_requests(orgnr: str) -> list[dict[str, str]]:
    # Lista väntande org-förfrågningar för ett organisationsnummer.
    normalized_orgnr = validate_orgnr(orgnr)
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(
                organization_link_requests_table.c.id,
                organization_link_requests_table.c.user_personnummer,
                organization_link_requests_table.c.user_name,
                organization_link_requests_table.c.user_email,
                organization_link_requests_table.c.created_at,
                users_table.c.id.label("active_user_id"),
                pending_users_table.c.id.label("pending_user_id"),
            )
            .select_from(
                organization_link_requests_table.outerjoin(
                    users_table,
                    organization_link_requests_table.c.user_personnummer == users_table.c.personnummer,
                ).outerjoin(
                    pending_users_table,
                    organization_link_requests_table.c.user_personnummer
                    == pending_users_table.c.personnummer,
                )
            )
            .where(
                organization_link_requests_table.c.orgnr_normalized == normalized_orgnr,
                organization_link_requests_table.c.status == "pending",
            )
            .order_by(organization_link_requests_table.c.created_at.asc())
        ).fetchall()

    requests: list[dict[str, str]] = []
    for row in rows:
        account_status = "missing"
        if row.active_user_id is not None:
            account_status = "active"
        elif row.pending_user_id is not None:
            account_status = "pending"
        requests.append(
            {
                "id": str(row.id),
                "user_personnummer": row.user_personnummer,
                "user_name": row.user_name,
                "user_email": row.user_email,
                "account_status": account_status,
            }
        )
    return requests


def approve_organization_link_request(
    request_id: int,
    supervisor_email_hash: str,
    orgnr: str,
) -> tuple[bool, dict[str, str] | None, str]:
    # Godkänn en org-förfrågan och skapa kopplingen direkt.
    if not _is_valid_hash(supervisor_email_hash):
        return False, None, "invalid_supervisor"

    normalized_orgnr = validate_orgnr(orgnr)
    with get_engine().begin() as conn:
        request_row = conn.execute(
            select(
                organization_link_requests_table.c.id,
                organization_link_requests_table.c.orgnr_normalized,
                organization_link_requests_table.c.user_personnummer,
                organization_link_requests_table.c.user_name,
                organization_link_requests_table.c.user_email,
                organization_link_requests_table.c.status,
            ).where(
                organization_link_requests_table.c.id == request_id,
                organization_link_requests_table.c.orgnr_normalized == normalized_orgnr,
            )
        ).first()
        if not request_row:
            return False, None, "missing_request"
        if request_row.status != "pending":
            return False, None, "handled_request"
        account_exists = conn.execute(
            select(users_table.c.id)
            .where(users_table.c.personnummer == request_row.user_personnummer)
            .union_all(
                select(pending_users_table.c.id).where(
                    pending_users_table.c.personnummer == request_row.user_personnummer
                )
            )
        ).first()
        if not account_exists:
            return False, None, "missing_user"

        existing_connection = conn.execute(
            select(supervisor_connections_table.c.id).where(
                supervisor_connections_table.c.supervisor_email == supervisor_email_hash,
                supervisor_connections_table.c.user_personnummer == request_row.user_personnummer,
            )
        ).first()
        if not existing_connection:
            conn.execute(
                insert(supervisor_connections_table).values(
                    supervisor_email=supervisor_email_hash,
                    user_personnummer=request_row.user_personnummer,
                )
            )

        conn.execute(
            update(organization_link_requests_table)
            .where(organization_link_requests_table.c.id == request_row.id)
            .values(
                status="approved",
                handled_by_supervisor_email=supervisor_email_hash,
                handled_at=func.now(),
            )
        )

    return (
        True,
        {
            "id": str(request_row.id),
            "orgnr_normalized": request_row.orgnr_normalized,
            "user_personnummer": request_row.user_personnummer,
            "user_name": request_row.user_name,
            "user_email": request_row.user_email,
        },
        "approved",
    )


def reject_organization_link_request(
    request_id: int,
    supervisor_email_hash: str,
    orgnr: str,
) -> tuple[bool, dict[str, str] | None, str]:
    # Avslå en org-förfrågan.
    if not _is_valid_hash(supervisor_email_hash):
        return False, None, "invalid_supervisor"

    normalized_orgnr = validate_orgnr(orgnr)
    with get_engine().begin() as conn:
        request_row = conn.execute(
            select(
                organization_link_requests_table.c.id,
                organization_link_requests_table.c.orgnr_normalized,
                organization_link_requests_table.c.user_personnummer,
                organization_link_requests_table.c.user_name,
                organization_link_requests_table.c.user_email,
                organization_link_requests_table.c.status,
            ).where(
                organization_link_requests_table.c.id == request_id,
                organization_link_requests_table.c.orgnr_normalized == normalized_orgnr,
            )
        ).first()
        if not request_row:
            return False, None, "missing_request"
        if request_row.status != "pending":
            return False, None, "handled_request"

        conn.execute(
            update(organization_link_requests_table)
            .where(organization_link_requests_table.c.id == request_row.id)
            .values(
                status="rejected",
                handled_by_supervisor_email=supervisor_email_hash,
                handled_at=func.now(),
            )
        )

    return (
        True,
        {
            "id": str(request_row.id),
            "orgnr_normalized": request_row.orgnr_normalized,
            "user_personnummer": request_row.user_personnummer,
            "user_name": request_row.user_name,
            "user_email": request_row.user_email,
        },
        "rejected",
    )


def delete_organization_link_requests_for_user(personnummer_hash: str) -> int:
    # Ta bort org-förfrågningar för ett privatkonto.
    if not _is_valid_hash(personnummer_hash):
        return 0
    with get_engine().begin() as conn:
        result = conn.execute(
            organization_link_requests_table.delete().where(
                organization_link_requests_table.c.user_personnummer == personnummer_hash
            )
        )
    return result.rowcount or 0


def update_organization_request_contact_details(
    personnummer_hash: str,
    user_name: str,
    user_email: str,
) -> int:
    # Uppdatera namn och e-post i öppna org-förfrågningar för användaren.
    if not _is_valid_hash(personnummer_hash):
        return 0
    normalized_email = normalize_email(user_email)
    with get_engine().begin() as conn:
        result = conn.execute(
            update(organization_link_requests_table)
            .where(organization_link_requests_table.c.user_personnummer == personnummer_hash)
            .values(user_name=user_name, user_email=normalized_email)
        )
    return result.rowcount or 0


def get_account_orgnr(personnummer_hash: str) -> str:
    # Hämta registrerat organisationsnummer för ett privatkonto.
    if not _is_valid_hash(personnummer_hash):
        return ""

    with get_engine().connect() as conn:
        active_row = conn.execute(
            select(users_table.c.orgnr_normalized).where(
                users_table.c.personnummer == personnummer_hash
            )
        ).first()
        if active_row and active_row.orgnr_normalized:
            return active_row.orgnr_normalized

        pending_row = conn.execute(
            select(pending_users_table.c.orgnr_normalized).where(
                pending_users_table.c.personnummer == personnummer_hash
            )
        ).first()
        if pending_row and pending_row.orgnr_normalized:
            return pending_row.orgnr_normalized

    return ""


# Copyright (c) Liam Suorsa and Mika Suorsa
