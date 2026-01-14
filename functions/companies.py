from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import case, func, insert, select, update
from sqlalchemy.engine import Connection

from functions.db import companies_table, company_users_table, get_engine


def ensure_company(
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


def list_companies_for_invoicing() -> List[Dict[str, Any]]:
    """Returnerar företag med företagskonton och deras fakturauppgifter."""

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
