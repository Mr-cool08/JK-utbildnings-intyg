# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

from calendar import monthrange
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
import os

from sqlalchemy import select, update

from config_loader import load_environment
from course_categories import labels_for_slugs
from functions import company_users_table, companies_table, supervisor_connections_table
from functions import create_database, get_engine, user_pdfs_table, users_table
from functions.emails import service as email_service
from functions.hashing import _is_valid_hash, email_lookup_values, normalize_email
from functions.logging import bootstrap_logging, mask_email_reference, mask_hash


load_environment()
logger = bootstrap_logging(__name__)


@dataclass(frozen=True)
class ReminderJobResult:
    candidate_certificates: int
    skipped_current_month: int
    sent_private_emails: int
    sent_supervisor_emails: int
    updated_certificates: int
    failed_emails: int
    unresolved_private_recipients: int
    unresolved_supervisor_recipients: int

    @property
    def had_failures(self) -> bool:
        return self.failed_emails > 0


def _add_months_to_date(base_date: date, months: int) -> date:
    absolute_month = (base_date.year * 12) + (base_date.month - 1) + months
    target_year, target_month_index = divmod(absolute_month, 12)
    target_month = target_month_index + 1
    target_day = min(base_date.day, monthrange(target_year, target_month)[1])
    return date(target_year, target_month, target_day)


def _current_reminder_month(today: date) -> str:
    return today.strftime("%Y-%m")


def _reminders_enabled() -> bool:
    return os.getenv("CERTIFICATE_EXPIRY_REMINDERS_ENABLED", "").strip().lower() == "true"


def _get_reminder_months() -> int:
    raw_value = os.getenv("CERTIFICATE_EXPIRY_REMINDER_MONTHS", "6").strip() or "6"
    try:
        months = int(raw_value)
    except ValueError as exc:
        raise ValueError(
            "CERTIFICATE_EXPIRY_REMINDER_MONTHS måste vara ett heltal."
        ) from exc
    if months <= 0:
        raise ValueError("CERTIFICATE_EXPIRY_REMINDER_MONTHS måste vara större än 0.")
    return months


def _deserialize_categories(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []
    return [part for part in raw_value.split(",") if part]


def _certificate_display_name(filename: str, raw_categories: str | None) -> str:
    category_labels = labels_for_slugs(_deserialize_categories(raw_categories))
    if category_labels:
        return category_labels[0]
    return filename


def _normalize_delivery_email(email_reference: str | None) -> str | None:
    if not email_reference:
        return None
    normalized_reference = email_reference.strip().lower()
    if not normalized_reference or _is_valid_hash(normalized_reference):
        return None
    try:
        return normalize_email(normalized_reference)
    except ValueError:
        return None


def _iter_email_reference_values(email_reference: str | None) -> tuple[str, ...]:
    if not email_reference:
        return tuple()
    normalized_reference = email_reference.strip().lower()
    if not normalized_reference:
        return tuple()
    if _is_valid_hash(normalized_reference):
        return (normalized_reference,)
    return email_lookup_values(normalized_reference)


def _fetch_expiring_certificate_rows(today: date, cutoff_date: date) -> tuple[list, int]:
    current_month = _current_reminder_month(today)
    query = (
        select(
            user_pdfs_table.c.id,
            user_pdfs_table.c.personnummer,
            user_pdfs_table.c.filename,
            user_pdfs_table.c.categories,
            user_pdfs_table.c.expires_on,
            user_pdfs_table.c.last_expiry_reminder_month,
            users_table.c.username,
            users_table.c.email,
        )
        .select_from(
            user_pdfs_table.join(
                users_table,
                user_pdfs_table.c.personnummer == users_table.c.personnummer,
            )
        )
        .where(
            user_pdfs_table.c.expires_on.is_not(None),
            user_pdfs_table.c.expires_on >= today,
            user_pdfs_table.c.expires_on < cutoff_date,
        )
        .order_by(
            user_pdfs_table.c.expires_on.asc(),
            users_table.c.username.asc(),
            user_pdfs_table.c.id.asc(),
        )
    )
    with get_engine().connect() as conn:
        rows = conn.execute(query).fetchall()

    eligible_rows = []
    skipped_current_month = 0
    for row in rows:
        if row.last_expiry_reminder_month == current_month:
            skipped_current_month += 1
            continue
        eligible_rows.append(row)
    return eligible_rows, skipped_current_month


def _fetch_connection_rows(personnummer_hashes: set[str]) -> list:
    if not personnummer_hashes:
        return []
    query = select(
        supervisor_connections_table.c.supervisor_email,
        supervisor_connections_table.c.user_personnummer,
    ).where(supervisor_connections_table.c.user_personnummer.in_(tuple(personnummer_hashes)))
    with get_engine().connect() as conn:
        return conn.execute(query).fetchall()


def _fetch_company_rows(supervisor_references: set[str]) -> list:
    if not supervisor_references:
        return []

    lookup_references: set[str] = set()
    for reference in supervisor_references:
        lookup_references.update(_iter_email_reference_values(reference))

    if not lookup_references:
        return []

    query = (
        select(
            company_users_table.c.email,
            company_users_table.c.name,
            companies_table.c.name.label("company_name"),
        )
        .select_from(
            company_users_table.outerjoin(
                companies_table,
                company_users_table.c.company_id == companies_table.c.id,
            )
        )
        .where(
            company_users_table.c.role == "foretagskonto",
            company_users_table.c.email.in_(tuple(lookup_references)),
        )
    )
    with get_engine().connect() as conn:
        return conn.execute(query).fetchall()


def _index_company_rows(company_rows: list) -> dict[str, dict[str, str | None]]:
    indexed: dict[str, dict[str, str | None]] = {}
    for row in company_rows:
        base_record = {
            "email_reference": row.email,
            "resolved_email": _normalize_delivery_email(row.email),
            "company_name": (row.company_name or row.name or "Företagskonto").strip()
            or "Företagskonto",
        }
        for reference in _iter_email_reference_values(row.email):
            indexed[reference] = base_record
    return indexed


def _resolve_company_recipient(
    supervisor_reference: str,
    indexed_company_rows: dict[str, dict[str, str | None]],
) -> dict[str, str | None] | None:
    for reference in _iter_email_reference_values(supervisor_reference):
        company_row = indexed_company_rows.get(reference)
        if not company_row:
            continue
        resolved_email = company_row["resolved_email"] or _normalize_delivery_email(
            supervisor_reference
        )
        return {
            "email_reference": supervisor_reference,
            "resolved_email": resolved_email,
            "company_name": company_row["company_name"],
        }
    return None


def _sort_certificates(certificates: list[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        certificates,
        key=lambda certificate: (
            certificate["expires_on"],
            certificate["display_name"].casefold(),
        ),
    )


def _sort_supervisor_user_groups(
    users_by_personnummer: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    user_groups = []
    for entry in users_by_personnummer.values():
        user_groups.append(
            {
                "user_name": entry["user_name"],
                "certificates": _sort_certificates(list(entry["certificates"])),
            }
        )
    return sorted(user_groups, key=lambda entry: str(entry["user_name"]).casefold())


def _update_last_reminder_month(pdf_ids: list[int], current_month: str) -> int:
    if not pdf_ids:
        return 0

    updated_count = 0
    chunk_size = 500
    with get_engine().begin() as conn:
        for index in range(0, len(pdf_ids), chunk_size):
            chunk = pdf_ids[index : index + chunk_size]
            result = conn.execute(
                update(user_pdfs_table)
                .where(user_pdfs_table.c.id.in_(tuple(chunk)))
                .values(last_expiry_reminder_month=current_month)
            )
            updated_count += int(result.rowcount or 0)
    return updated_count


def run_expiry_reminder_job(
    *,
    today: date | None = None,
    reminder_months: int | None = None,
) -> ReminderJobResult:
    if not _reminders_enabled():
        logger.info("Utgångspåminnelser är avstängda. Avslutar utan utskick.")
        return ReminderJobResult(0, 0, 0, 0, 0, 0, 0, 0)

    today = today or date.today()
    reminder_months = reminder_months if reminder_months is not None else _get_reminder_months()
    cutoff_date = _add_months_to_date(today, reminder_months)
    current_month = _current_reminder_month(today)

    logger.info("Startar kontroll av intyg som snart går ut")

    expiring_rows, skipped_current_month = _fetch_expiring_certificate_rows(today, cutoff_date)
    if skipped_current_month:
        logger.info(
            "Hoppade över intyg som redan påmints denna månad: %s",
            skipped_current_month,
        )

    if not expiring_rows:
        logger.info("Inga intyg behöver påminnas")
        logger.info("Utgångspåminnelsejobb klart")
        return ReminderJobResult(0, skipped_current_month, 0, 0, 0, 0, 0, 0)

    owner_hashes = {row.personnummer for row in expiring_rows}
    connection_rows = _fetch_connection_rows(owner_hashes)
    connections_by_owner: dict[str, set[str]] = defaultdict(set)
    supervisor_references: set[str] = set()
    for row in connection_rows:
        connections_by_owner[row.user_personnummer].add(row.supervisor_email)
        supervisor_references.add(row.supervisor_email)

    company_rows = _fetch_company_rows(supervisor_references)
    indexed_company_rows = _index_company_rows(company_rows)

    intended_tokens_by_pdf: dict[int, set[str]] = defaultdict(set)
    private_batches: dict[str, dict[str, object]] = {}
    supervisor_batches: dict[str, dict[str, object]] = {}
    unresolved_private_tokens: set[str] = set()
    unresolved_supervisor_tokens: set[str] = set()

    for row in expiring_rows:
        certificate_summary = {
            "display_name": _certificate_display_name(row.filename, row.categories),
            "expires_on": row.expires_on.isoformat(),
        }

        private_token = f"private:{row.personnummer}"
        intended_tokens_by_pdf[row.id].add(private_token)
        private_email = _normalize_delivery_email(row.email)
        if private_email:
            batch = private_batches.setdefault(
                private_token,
                {
                    "owner_hash": row.personnummer,
                    "recipient_name": row.username,
                    "resolved_email": private_email,
                    "certificates": [],
                },
            )
            batch["certificates"].append(certificate_summary)
        else:
            unresolved_private_tokens.add(private_token)

        for supervisor_reference in sorted(connections_by_owner.get(row.personnummer, set())):
            supervisor_token = f"supervisor:{supervisor_reference}"
            intended_tokens_by_pdf[row.id].add(supervisor_token)
            company_recipient = _resolve_company_recipient(
                supervisor_reference,
                indexed_company_rows,
            )
            if not company_recipient or not company_recipient["resolved_email"]:
                unresolved_supervisor_tokens.add(supervisor_token)
                continue

            batch = supervisor_batches.setdefault(
                supervisor_token,
                {
                    "email_reference": supervisor_reference,
                    "resolved_email": company_recipient["resolved_email"],
                    "company_name": company_recipient["company_name"],
                    "users": {},
                },
            )
            users = batch["users"]
            user_entry = users.setdefault(
                row.personnummer,
                {
                    "user_name": row.username,
                    "certificates": [],
                },
            )
            user_entry["certificates"].append(certificate_summary)

    for token in sorted(unresolved_private_tokens):
        owner_hash = token.split(":", 1)[1]
        logger.warning(
            "Hoppade över privatkonto utan leveransbar e-post (%s)",
            mask_hash(owner_hash),
        )

    for token in sorted(unresolved_supervisor_tokens):
        supervisor_reference = token.split(":", 1)[1]
        logger.warning(
            "Hoppade över företagskonto utan leveransbar e-post (%s)",
            mask_email_reference(supervisor_reference),
        )

    if not private_batches and not supervisor_batches:
        logger.info("Inga leveransbara mottagare hittades")
        logger.info("Utgångspåminnelsejobb klart")
        return ReminderJobResult(
            len(expiring_rows),
            skipped_current_month,
            0,
            0,
            0,
            0,
            len(unresolved_private_tokens),
            len(unresolved_supervisor_tokens),
        )

    success_tokens: set[str] = set()
    sent_private_emails = 0
    sent_supervisor_emails = 0
    failed_emails = 0

    for token, batch in private_batches.items():
        try:
            email_service.send_certificate_expiry_summary_email(
                batch["resolved_email"],
                batch["recipient_name"],
                _sort_certificates(list(batch["certificates"])),
                months=reminder_months,
            )
        except Exception:
            failed_emails += 1
            logger.exception(
                "Misslyckades att skicka utgångspåminnelse till privatkonto (%s)",
                mask_hash(str(batch["owner_hash"])),
            )
            continue

        success_tokens.add(token)
        sent_private_emails += 1
        logger.info("Skickade utgångspåminnelse till privatkonto")

    for token, batch in supervisor_batches.items():
        try:
            email_service.send_supervisor_expiry_summary_email(
                batch["resolved_email"],
                str(batch["company_name"]),
                _sort_supervisor_user_groups(batch["users"]),
                months=reminder_months,
            )
        except Exception:
            failed_emails += 1
            logger.exception(
                "Misslyckades att skicka utgångspåminnelse till företagskonto (%s)",
                mask_email_reference(str(batch["email_reference"])),
            )
            continue

        success_tokens.add(token)
        sent_supervisor_emails += 1
        logger.info("Skickade utgångspåminnelse till företagskonto")

    successful_pdf_ids = [
        pdf_id
        for pdf_id, intended_tokens in intended_tokens_by_pdf.items()
        if intended_tokens and intended_tokens.issubset(success_tokens)
    ]
    updated_certificates = _update_last_reminder_month(successful_pdf_ids, current_month)

    logger.info(
        "Utgångspåminnelsejobb klart: %s intyg, %s privatmejl, %s företagsmejl, %s uppdaterade intyg",
        len(expiring_rows),
        sent_private_emails,
        sent_supervisor_emails,
        updated_certificates,
    )
    return ReminderJobResult(
        len(expiring_rows),
        skipped_current_month,
        sent_private_emails,
        sent_supervisor_emails,
        updated_certificates,
        failed_emails,
        len(unresolved_private_tokens),
        len(unresolved_supervisor_tokens),
    )


def main() -> int:
    if not _reminders_enabled():
        logger.info("Utgångspåminnelser är avstängda. Avslutar utan utskick.")
        return 0

    try:
        reminder_months = _get_reminder_months()
    except ValueError as exc:
        logger.error("Ogiltig konfiguration för utgångspåminnelser: %s", str(exc))
        return 1

    create_database()
    result = run_expiry_reminder_job(reminder_months=reminder_months)
    return 1 if result.had_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())


# Copyright (c) Liam Suorsa and Mika Suorsa
