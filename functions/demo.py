# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

import logging
import os
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from functions.dates import add_months_to_date
from functions.database import (
    APP_ROOT,
    application_requests_table,
    companies_table,
    company_users_table,
    create_database,
    get_engine,
    metadata,
    organization_link_requests_table,
    password_resets_table,
    pending_supervisors_table,
    pending_users_table,
    schema_migrations_table,
    supervisor_connections_table,
    supervisor_link_requests_table,
    supervisor_password_resets_table,
    supervisors_table,
    user_pdfs_table,
    users_table,
)
from functions.hashing import (
    email_lookup_values,
    hash_password,
    hash_value,
    normalize_email,
    normalize_personnummer,
    validate_orgnr,
)
from functions.requests import as_bool


logger = logging.getLogger(__name__)


DEMO_PDF_DEFINITIONS: list[dict[str, Any]] = [
    {
        "filename": "demo-arbetsmiljo-grund.pdf",
        "expires_in_months": 6,
        "categories": ["arbetsmiljo-sakerhet"],
    },
    {
        "filename": "demo-hlr.pdf",
        "expires_in_days": 14,
        "categories": ["arbetsmiljo-sakerhet"],
    },
    {
        "filename": "demo-hlr-utgatt.pdf",
        "source_filename": "demo-hlr.pdf",
        "expires_in_days": -30,
        "categories": ["arbetsmiljo-sakerhet"],
    },
]


def _demo_pdf_dir() -> Path:
    return Path(APP_ROOT) / "demo_assets" / "pdfs"


def _demo_expiry_date(definition: dict[str, Any], today: date) -> date:
    months = definition.get("expires_in_months")
    if months is not None:
        return add_months_to_date(today, months)
    return today + timedelta(days=definition["expires_in_days"])


def _read_demo_pdf(definition: dict[str, Any]) -> bytes:
    source_filename = definition.get("source_filename", definition["filename"])
    pdf_path = _demo_pdf_dir() / str(source_filename)
    if not pdf_path.is_file():
        raise FileNotFoundError(f"Demo-PDF saknas: {pdf_path}")
    return pdf_path.read_bytes()


def _serialize_categories(categories: list[str] | tuple[str, ...] | None) -> str:
    if not categories:
        return ""
    return ",".join(category.strip() for category in categories if category.strip())


def _insert_demo_pdfs(
    conn,
    personnummer_hash: str,
    today: date,
    filenames: set[str] | None = None,
) -> None:
    for definition in DEMO_PDF_DEFINITIONS:
        if filenames is not None and definition["filename"] not in filenames:
            continue
        conn.execute(
            insert(user_pdfs_table).values(
                personnummer=personnummer_hash,
                filename=definition["filename"],
                content=_read_demo_pdf(definition),
                categories=_serialize_categories(definition.get("categories")),
                expires_on=_demo_expiry_date(definition, today),
                uploaded_at=func.now(),
                note="",
            )
        )


def _remove_demo_standard_account(
    conn,
    personnummer_hash: str,
    email_values: tuple[str, ...],
) -> None:
    user_hashes = {
        row.personnummer
        for row in conn.execute(
            select(users_table.c.personnummer).where(
                (users_table.c.personnummer == personnummer_hash)
                | (users_table.c.email.in_(email_values))
            )
        )
    }
    pending_hashes = {
        row.personnummer
        for row in conn.execute(
            select(pending_users_table.c.personnummer).where(
                (pending_users_table.c.personnummer == personnummer_hash)
                | (pending_users_table.c.email.in_(email_values))
            )
        )
    }
    personnummer_hashes = user_hashes | pending_hashes | {personnummer_hash}

    conn.execute(
        delete(user_pdfs_table).where(
            user_pdfs_table.c.personnummer.in_(personnummer_hashes)
        )
    )
    conn.execute(
        delete(password_resets_table).where(
            password_resets_table.c.personnummer.in_(personnummer_hashes)
        )
    )
    conn.execute(
        delete(supervisor_connections_table).where(
            supervisor_connections_table.c.user_personnummer.in_(personnummer_hashes)
        )
    )
    conn.execute(
        delete(supervisor_link_requests_table).where(
            supervisor_link_requests_table.c.user_personnummer.in_(personnummer_hashes)
        )
    )
    conn.execute(
        delete(organization_link_requests_table).where(
            organization_link_requests_table.c.user_personnummer.in_(personnummer_hashes)
        )
    )
    conn.execute(
        delete(application_requests_table).where(
            application_requests_table.c.personnummer_hash.in_(personnummer_hashes)
        )
    )
    conn.execute(
        delete(pending_users_table).where(
            (pending_users_table.c.personnummer.in_(personnummer_hashes))
            | (pending_users_table.c.email.in_(email_values))
        )
    )
    conn.execute(
        delete(users_table).where(
            (users_table.c.personnummer.in_(personnummer_hashes))
            | (users_table.c.email.in_(email_values))
        )
    )


def _remove_demo_supervisor(conn, email_values: tuple[str, ...], orgnr: str) -> None:
    company_ids = {
        row.id
        for row in conn.execute(
            select(companies_table.c.id).where(companies_table.c.orgnr == orgnr)
        )
    }

    conn.execute(
        delete(supervisor_connections_table).where(
            supervisor_connections_table.c.supervisor_email.in_(email_values)
        )
    )
    conn.execute(
        delete(supervisor_link_requests_table).where(
            supervisor_link_requests_table.c.supervisor_email.in_(email_values)
        )
    )
    conn.execute(
        delete(supervisor_password_resets_table).where(
            supervisor_password_resets_table.c.email.in_(email_values)
        )
    )
    conn.execute(
        delete(organization_link_requests_table).where(
            organization_link_requests_table.c.handled_by_supervisor_email.in_(email_values)
        )
    )
    conn.execute(
        delete(company_users_table).where(
            (company_users_table.c.email.in_(email_values))
            | company_users_table.c.company_id.in_(company_ids)
        )
    )
    conn.execute(
        delete(application_requests_table).where(
            (application_requests_table.c.email.in_(email_values))
            | (application_requests_table.c.orgnr_normalized == orgnr)
        )
    )
    conn.execute(
        delete(pending_supervisors_table).where(
            pending_supervisors_table.c.email.in_(email_values)
        )
    )
    conn.execute(delete(supervisors_table).where(supervisors_table.c.email.in_(email_values)))

    if company_ids:
        remaining_company_users = conn.execute(
            select(company_users_table.c.id).where(
                company_users_table.c.company_id.in_(company_ids)
            )
        ).first()
        if not remaining_company_users:
            conn.execute(delete(companies_table).where(companies_table.c.id.in_(company_ids)))


def ensure_demo_data(
    *,
    user_email: str,
    user_name: str,
    user_personnummer: str,
    user_password: str,
    supervisor_email: str,
    supervisor_name: str,
    supervisor_password: str,
    supervisor_orgnr: str,
) -> bool:
    normalized_user_email = normalize_email(user_email)
    user_email_values = email_lookup_values(normalized_user_email)
    normalized_personnummer = normalize_personnummer(user_personnummer)
    personnummer_hash = hash_value(normalized_personnummer)

    normalized_supervisor_email = normalize_email(supervisor_email)
    supervisor_email_values = email_lookup_values(normalized_supervisor_email)
    normalized_orgnr = validate_orgnr(supervisor_orgnr)
    company_name = supervisor_name.strip() or "Demoforetagskonto"

    with get_engine().begin() as conn:
        _remove_demo_standard_account(conn, personnummer_hash, user_email_values)
        _remove_demo_supervisor(conn, supervisor_email_values, normalized_orgnr)

        conn.execute(
            insert(users_table).values(
                username=user_name,
                email=normalized_user_email,
                password=hash_password(user_password),
                personnummer=personnummer_hash,
                orgnr_normalized="",
            )
        )

        conn.execute(
            insert(supervisors_table).values(
                name=supervisor_name,
                email=normalized_supervisor_email,
                password=hash_password(supervisor_password),
                created_at=func.now(),
            )
        )

        company_result = conn.execute(
            insert(companies_table).values(
                name=company_name,
                orgnr=normalized_orgnr,
                created_at=func.now(),
                updated_at=func.now(),
            )
        )
        company_id = company_result.inserted_primary_key[0]

        conn.execute(
            insert(company_users_table).values(
                company_id=company_id,
                role="foretagskonto",
                name=supervisor_name,
                email=normalized_supervisor_email,
                created_at=func.now(),
                updated_at=func.now(),
            )
        )

        conn.execute(
            insert(supervisor_connections_table).values(
                supervisor_email=normalized_supervisor_email,
                user_personnummer=personnummer_hash,
                created_at=func.now(),
            )
        )

        _insert_demo_pdfs(conn, personnummer_hash, date.today())

    return True


def ensure_demo_certificates(user_personnummer: str) -> bool:
    personnummer_hash = hash_value(normalize_personnummer(user_personnummer))
    filenames = {definition["filename"] for definition in DEMO_PDF_DEFINITIONS}

    with get_engine().begin() as conn:
        demo_user = conn.execute(
            select(users_table.c.personnummer).where(
                users_table.c.personnummer == personnummer_hash
            )
        ).first()
        if demo_user is None:
            return False

        existing_filenames = {
            row.filename
            for row in conn.execute(
                select(user_pdfs_table.c.filename).where(
                    user_pdfs_table.c.personnummer == personnummer_hash,
                    user_pdfs_table.c.filename.in_(filenames),
                )
            )
        }
        missing_filenames = filenames - existing_filenames
        if missing_filenames:
            _insert_demo_pdfs(
                conn,
                personnummer_hash,
                date.today(),
                missing_filenames,
            )

    return True


def _ensure_demo_user_once(
    *,
    user_email: str,
    user_name: str,
    user_personnummer: str,
    user_password: str,
) -> bool:
    normalized_email = normalize_email(user_email)
    email_values = email_lookup_values(normalized_email)
    personnummer_hash = hash_value(normalize_personnummer(user_personnummer))
    filenames = {definition["filename"] for definition in DEMO_PDF_DEFINITIONS}

    with get_engine().begin() as conn:
        if conn.dialect.name == "sqlite":
            conn.execute(
                update(users_table)
                .where(users_table.c.personnummer == personnummer_hash)
                .values(username=users_table.c.username)
            )
        user = conn.execute(
            select(users_table.c.email).where(
                users_table.c.personnummer == personnummer_hash
            ).with_for_update()
        ).first()
        if user is not None and user.email not in email_values:
            logger.warning(
                "Demointyg skapades inte eftersom personnummer tillhör ett annat konto."
            )
            return False
        if user is None:
            email_conflict = conn.execute(
                select(users_table.c.id).where(users_table.c.email.in_(email_values))
            ).first()
            pending_conflict = conn.execute(
                select(pending_users_table.c.id).where(
                    (pending_users_table.c.personnummer == personnummer_hash)
                    | pending_users_table.c.email.in_(email_values)
                )
            ).first()
            if email_conflict or pending_conflict:
                logger.warning(
                    "Demokontot skapades inte eftersom personnummer eller e-post "
                    "redan används."
                )
                return False

            conn.execute(
                insert(users_table).values(
                    username=user_name,
                    email=normalized_email,
                    password=hash_password(user_password),
                    personnummer=personnummer_hash,
                    orgnr_normalized="",
                )
            )

        existing_filenames = {
            row.filename
            for row in conn.execute(
                select(user_pdfs_table.c.filename).where(
                    user_pdfs_table.c.personnummer == personnummer_hash,
                    user_pdfs_table.c.filename.in_(filenames),
                )
            )
        }
        missing_filenames = filenames - existing_filenames
        if missing_filenames:
            _insert_demo_pdfs(
                conn,
                personnummer_hash,
                date.today(),
                missing_filenames,
            )

    return True


def ensure_demo_user(
    *,
    user_email: str,
    user_name: str,
    user_personnummer: str,
    user_password: str,
) -> bool:
    try:
        return _ensure_demo_user_once(
            user_email=user_email,
            user_name=user_name,
            user_personnummer=user_personnummer,
            user_password=user_password,
        )
    except IntegrityError:
        logger.info("Demokontot skapades samtidigt av en annan process. Försöker igen.")
        return _ensure_demo_user_once(
            user_email=user_email,
            user_name=user_name,
            user_personnummer=user_personnummer,
            user_password=user_password,
        )


def reset_demo_database(demo_defaults: dict[str, str]) -> bool:
    if not as_bool(os.getenv("ENABLE_DEMO_MODE")):
        return False

    create_database()
    with get_engine().begin() as conn:
        for table in reversed(metadata.sorted_tables):
            if table.name == schema_migrations_table.name:
                continue
            conn.execute(delete(table))

    ensure_demo_data(**demo_defaults)
    return True


# Copyright (c) Liam Suorsa and Mika Suorsa
