# Copyright (c) Liam Suorsa
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import Connection, case, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from functions.database import (
    application_requests_table,
    companies_table,
    company_users_table,
    pending_users_table,
    users_table,
    pending_supervisors_table,
    supervisors_table,
    get_engine,
)
from functions.hashing import (
    hash_value,
    normalize_email,
    normalize_personnummer,
    validate_orgnr,
)
from functions.logging import configure_module_logger, mask_hash


logger = configure_module_logger(__name__)
logger.setLevel(logging.DEBUG)


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
    personnummer: Optional[str] = None,
) -> int:
    allowed_types = {"standard", "foretagskonto"}
    normalized_type = (account_type or "").strip().lower()
    if normalized_type not in allowed_types:
        raise ValueError("Ogiltig kontotyp.")

    cleaned_name = (name or "").strip()
    if not cleaned_name:
        raise ValueError(
            "Namn saknas. Ange ditt fullständiga namn så att vi kan behandla ansökan."
        )

    normalized_email = normalize_email(email)
    personnummer_hash: Optional[str] = None
    if normalized_type == "standard":
        cleaned_personnummer = (personnummer or "").strip()
        if not cleaned_personnummer:
            raise ValueError(
                "Personnummer krävs för standardkonton. Ange personnumret i formatet ÅÅMMDDXXXX."
            )
        try:
            normalized_personnummer = normalize_personnummer(cleaned_personnummer)
        except ValueError as exc:
            raise ValueError(
                "Ogiltigt personnummer. Kontrollera att du skrivit ÅÅMMDDXXXX."
            ) from exc
        personnummer_hash = hash_value(normalized_personnummer)
    raw_orgnr = (orgnr or "").strip()
    if normalized_type == "standard" and raw_orgnr == "":
        validated_orgnr = ""
    else:
        validated_orgnr = validate_orgnr(raw_orgnr)
    cleaned_company = (company_name or "").strip()
    if normalized_type == "foretagskonto" and not cleaned_company:
        raise ValueError(
            "Företagsnamn krävs för företagskonton. Ange namnet precis som det ska visas i portalen och på fakturan."
        )

    cleaned_comment = _clean_optional_text(comment)
    cleaned_invoice_address = _clean_optional_text(invoice_address, max_length=1000)
    cleaned_invoice_contact = _clean_optional_text(invoice_contact, max_length=255)
    cleaned_invoice_reference = _clean_optional_text(invoice_reference, max_length=255)

    if normalized_type == "foretagskonto":
        if not cleaned_invoice_address:
            raise ValueError(
                "Fakturaadress krävs för företagskonton. Lägg till gatuadress, postnummer och ort så att vi kan fakturera rätt."
            )
        if not cleaned_invoice_contact:
            raise ValueError(
                "Kontaktperson för fakturering krävs för företagskonton. Skriv vem vi kan kontakta om fakturan."
            )
        if not cleaned_invoice_reference:
            raise ValueError(
                "Märkning för fakturering krävs för företagskonton. Lägg till eventuell referens eller beställningskod."
            )
    else:
        cleaned_invoice_address = None
        cleaned_invoice_contact = None
        cleaned_invoice_reference = None

    stored_company = cleaned_company if cleaned_company else ""

    with get_engine().begin() as conn:
        # Prevent duplicate pending applications for the same email + orgnr combination.
        pending_query = select(application_requests_table).where(
            application_requests_table.c.email == normalized_email,
            application_requests_table.c.status == "pending",
            application_requests_table.c.account_type == normalized_type,
        )
        if validated_orgnr:
            pending_query = pending_query.where(
                application_requests_table.c.orgnr_normalized == validated_orgnr
            )
        else:
            pending_query = pending_query.where(
                application_requests_table.c.orgnr_normalized == ""
            )
        existing_pending = conn.execute(pending_query).first()
        if existing_pending:
            raise ValueError(
                "Du har redan skickat samma typ av ansökan. Vänta på beslut eller kontakta support om du behöver ändra uppgifterna."
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
                personnummer_hash=personnummer_hash,
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


def approve_application_request(application_id: int, reviewer: str) -> Dict[str, Any]:
    # Approve an application request and create the corresponding company and company user.
    normalized_reviewer = (reviewer or "").strip() or "okänd"

    pending_supervisor_created = False
    supervisor_activation_required = False
    supervisor_email_hash: Optional[str] = None
    user_activation_required = False
    user_personnummer_hash: Optional[str] = None

    with get_engine().connect() as conn:
        application = conn.execute(
            select(application_requests_table).where(
                application_requests_table.c.id == application_id
            )
        ).first()
    if not application:
        raise ValueError("Ansökan hittades inte.")
    if application.status != "pending":
        raise ValueError("Ansökan är redan hanterad.")
    if application.account_type == "standard":
        stored_personnummer_hash = (application.personnummer_hash or "").strip()
        if not stored_personnummer_hash:
            logger.warning(
                "Standardansökan %s saknar personnummer och kan inte aktiveras",
                application_id,
            )
            with get_engine().begin() as conn:
                conn.execute(
                    update(application_requests_table)
                    .where(application_requests_table.c.id == application.id)
                    .values(
                        decision_reason=(
                            "Personnummer saknas för standardkontot. "
                            "Komplettera ansökan innan den godkänns."
                        )
                    )
                )
            raise ValueError("Ansökan saknar personnummer och kan inte godkännas.")

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

        stored_orgnr = (application.orgnr_normalized or "").strip()
        company_id: Optional[int]
        created: bool = False
        if stored_orgnr:
            validated_orgnr = validate_orgnr(stored_orgnr)
            company_id, created, company_display = _ensure_company(
                conn,
                validated_orgnr,
                application.company_name,
                application.invoice_address,
                application.invoice_contact,
                application.invoice_reference,
            )
        else:
            validated_orgnr = ""
            company_id = None
            company_display = (application.company_name or "").strip()

        normalized_email = normalize_email(application.email)
        existing_user = conn.execute(
            select(company_users_table.c.id).where(
                company_users_table.c.email == normalized_email
            )
        ).first()
        if existing_user:
            raise ValueError("E-postadressen är redan registrerad.")

        try:
            result = conn.execute(
                insert(company_users_table).values(
                    company_id=company_id,
                    role=application.account_type,
                    name=application.name,
                    email=normalized_email,
                    created_via_application_id=application.id,
                )
            )
        except IntegrityError as exc:
            raise ValueError("E-postadressen är redan registrerad.") from exc
        user_id = result.inserted_primary_key[0]

        if application.account_type == "standard":
            stored_personnummer_hash = (application.personnummer_hash or "").strip()
            user_personnummer_hash = stored_personnummer_hash
            email_hash = hash_value(normalized_email)
            existing_user = conn.execute(
                select(users_table.c.id).where(
                    users_table.c.personnummer == stored_personnummer_hash
                )
            ).first()
            existing_email_user = conn.execute(
                select(users_table.c.id).where(users_table.c.email == email_hash)
            ).first()
            pending_user = conn.execute(
                select(pending_users_table.c.id).where(
                    pending_users_table.c.personnummer == stored_personnummer_hash
                )
            ).first()
            pending_email = conn.execute(
                select(pending_users_table.c.id).where(
                    pending_users_table.c.email == email_hash
                )
            ).first()

            if not existing_user and not existing_email_user:
                if pending_user or pending_email:
                    user_activation_required = True
                else:
                    try:
                        conn.execute(
                            insert(pending_users_table).values(
                                username=application.name,
                                email=email_hash,
                                personnummer=stored_personnummer_hash,
                            )
                        )
                    except IntegrityError:
                        logger.info(
                            "Pending standardkonto finns redan för %s",
                            mask_hash(stored_personnummer_hash),
                        )
                    user_activation_required = True

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
        "company_id": int(company_id) if company_id is not None else None,
        "user_id": int(user_id),
        "orgnr": validated_orgnr,
        "email": normalized_email,
        "supervisor_email": normalized_email if application.account_type == "foretagskonto" else None,
        "account_type": application.account_type,
        "name": application.name,
        "company_name": company_display,
        "company_created": created if company_id is not None else False,
        "invoice_address": application.invoice_address,
        "invoice_contact": application.invoice_contact,
        "invoice_reference": application.invoice_reference,
        "user_activation_required": user_activation_required,
        "user_personnummer_hash": user_personnummer_hash,
        "pending_supervisor_created": pending_supervisor_created,
        "supervisor_activation_required": supervisor_activation_required,
        "supervisor_email_hash": supervisor_email_hash,
    }


def reject_application_request(
    application_id: int, reviewer: str, reason: str | None = None
) -> Dict[str, Any]:
    normalized_reviewer = (reviewer or "").strip() or "okänd"
    normalized_reason = (reason or "").strip()
    decision_reason = normalized_reason or "Ingen motivering angiven."

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

        stored_orgnr = (application.orgnr_normalized or "").strip()
        if stored_orgnr:
            validated_orgnr = validate_orgnr(stored_orgnr)
        else:
            validated_orgnr = ""

        company_display = (application.company_name or "").strip()
        if not company_display and validated_orgnr:
            existing_company = conn.execute(
                select(companies_table.c.name).where(
                    companies_table.c.orgnr == validated_orgnr
                )
            ).first()
            if existing_company and existing_company.name:
                company_display = existing_company.name
            else:
                company_display = f"organisationsnummer {validated_orgnr}"
        if not company_display:
            company_display = "standardkontot"

        conn.execute(
            update(application_requests_table)
            .where(application_requests_table.c.id == application.id)
            .values(
                status="rejected",
                reviewed_by=normalized_reviewer,
                reviewed_at=func.now(),
                decision_reason=decision_reason,
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
        "decision_reason": decision_reason,
    }


def list_companies_for_invoicing() -> List[Dict[str, Any]]:
    # Returnerar företag med företagskonton och deras fakturauppgifter.
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
