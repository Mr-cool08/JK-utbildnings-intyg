# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

from calendar import monthrange
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from html import escape
import os

from sqlalchemy import select, update

from config_loader import load_environment
from course_categories import labels_for_slugs
from functions import company_users_table, companies_table, supervisor_connections_table
from functions import create_database, get_engine, user_pdfs_table, users_table
from functions.emails import service as email_service
from functions.hashing import _is_valid_hash, email_lookup_values
from functions.logging import bootstrap_logging, mask_email, mask_email_reference, mask_hash


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
    skipped_duplicate_guard: int = 0

    @property
    def had_failures(self) -> bool:
        return self.failed_emails > 0


@dataclass(frozen=True)
class InvalidEmailReference:
    recipient_type: str
    email_reference: str
    reason: str


@dataclass(frozen=True)
class ReminderAdminIssue:
    issue_type: str
    recipient_type: str
    reason: str
    account_payload: dict[str, object]


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


def _get_duplicate_guard_minutes() -> int:
    raw_value = (
        os.getenv("CERTIFICATE_EXPIRY_REMINDER_DUPLICATE_GUARD_MINUTES", "60").strip()
        or "60"
    )
    try:
        minutes = int(raw_value)
    except ValueError as exc:
        raise ValueError(
            "CERTIFICATE_EXPIRY_REMINDER_DUPLICATE_GUARD_MINUTES måste vara ett heltal."
        ) from exc
    if minutes < 0:
        raise ValueError(
            "CERTIFICATE_EXPIRY_REMINDER_DUPLICATE_GUARD_MINUTES får inte vara negativ."
        )
    return minutes


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
        return email_service.normalize_valid_email(normalized_reference)
    except ValueError:
        return None


def _get_invalid_email_reason(email_reference: str | None) -> str | None:
    if not email_reference:
        return None

    normalized_reference = email_reference.strip().lower()
    if not normalized_reference or _is_valid_hash(normalized_reference):
        return None

    try:
        email_service.normalize_valid_email(normalized_reference)
    except ValueError as exc:
        return str(exc)
    return None


def _iter_email_reference_values(email_reference: str | None) -> tuple[str, ...]:
    if not email_reference:
        return tuple()
    normalized_reference = email_reference.strip().lower()
    if not normalized_reference:
        return tuple()
    if _is_valid_hash(normalized_reference):
        return (normalized_reference,)
    try:
        normalized_email = email_service.normalize_valid_email(normalized_reference)
    except ValueError:
        return tuple()
    return email_lookup_values(normalized_email)


def _record_invalid_email_reference(
    invalid_references: dict[tuple[str, str], InvalidEmailReference],
    recipient_type: str,
    email_reference: str | None,
) -> None:
    reason = _get_invalid_email_reason(email_reference)
    if not reason or not email_reference:
        return

    normalized_reference = email_reference.strip().lower()
    invalid_references[(recipient_type, normalized_reference)] = InvalidEmailReference(
        recipient_type=recipient_type,
        email_reference=normalized_reference,
        reason=reason,
    )


def _log_invalid_email_references(
    invalid_references: dict[tuple[str, str], InvalidEmailReference],
) -> None:
    if not invalid_references:
        return

    recipient_labels = {
        "private": "privatkonto",
        "supervisor": "företagskonto",
    }
    summary_lines = []
    for invalid_reference in sorted(
        invalid_references.values(),
        key=lambda item: (item.recipient_type, item.email_reference),
    ):
        recipient_label = recipient_labels.get(
            invalid_reference.recipient_type,
            invalid_reference.recipient_type,
        )
        summary_lines.append(
            f"- {recipient_label}: "
            f"{mask_email_reference(invalid_reference.email_reference)} "
            f"({invalid_reference.reason})"
        )

    logger.error(
        "Ogiltiga e-postadresser upptäcktes i utgångspåminnelsejobbet:\n%s",
        "\n".join(summary_lines),
        extra={"skip_error_email": True},
    )


def _normalize_reference_key(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized or None


def _iter_reference_lookup_keys(reference: str | None) -> tuple[str, ...]:
    normalized_keys = []
    seen: set[str] = set()
    candidates = []

    normalized_reference = _normalize_reference_key(reference)
    if normalized_reference is not None:
        candidates.append(normalized_reference)
    candidates.extend(_iter_email_reference_values(reference))

    for candidate in candidates:
        normalized_candidate = _normalize_reference_key(candidate)
        if normalized_candidate is None or normalized_candidate in seen:
            continue
        seen.add(normalized_candidate)
        normalized_keys.append(normalized_candidate)
    return tuple(normalized_keys)


def _normalize_admin_recipients() -> list[str]:
    raw_value = os.getenv("ADMIN_EMAIL", "")
    recipients = []
    for candidate in raw_value.split(","):
        normalized_candidate = candidate.strip()
        if not normalized_candidate:
            continue
        try:
            recipients.append(email_service.normalize_valid_email(normalized_candidate))
        except ValueError:
            logger.warning(
                "ADMIN_EMAIL innehaller en ogiltig adress som hoppas over: %s",
                mask_email(normalized_candidate),
            )
    return recipients


def _format_value_for_admin(value: object | None) -> str:
    if value is None:
        return "saknas"
    text = str(value).strip()
    return text or "saknas"


def _format_categories_for_admin(raw_categories: str | None) -> str:
    labels = labels_for_slugs(_deserialize_categories(raw_categories))
    if labels:
        return ", ".join(labels)
    return _format_value_for_admin(raw_categories)


def _format_certificate_rows_for_admin(rows: list) -> list[dict[str, str]]:
    formatted_rows = []
    for row in rows:
        formatted_rows.append(
            {
                "pdf_id": str(row.id),
                "filename": _format_value_for_admin(row.filename),
                "categories": _format_categories_for_admin(row.categories),
                "expires_on": _format_value_for_admin(row.expires_on),
                "uploaded_at": _format_value_for_admin(row.uploaded_at),
                "last_expiry_reminder_month": _format_value_for_admin(
                    row.last_expiry_reminder_month
                ),
                "last_expiry_reminder_sent_at": _format_value_for_admin(
                    row.last_expiry_reminder_sent_at
                ),
                "note": _format_value_for_admin(row.note),
            }
        )
    return formatted_rows


def _normalize_reminder_timestamp(value: object | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _was_recently_reminded(
    last_sent_at: object | None,
    *,
    now: datetime,
    duplicate_guard_window: timedelta,
) -> bool:
    if duplicate_guard_window <= timedelta(0):
        return False
    normalized_timestamp = _normalize_reminder_timestamp(last_sent_at)
    if normalized_timestamp is None:
        return False
    return normalized_timestamp > now - duplicate_guard_window


def _build_private_issue_reason(email_reference: str | None) -> str:
    invalid_reason = _get_invalid_email_reason(email_reference)
    if invalid_reason:
        return f"Ogiltig e-postadress i users.email ({invalid_reason})"
    if not email_reference:
        return "Saknar e-postadress i users.email."
    normalized_reference = email_reference.strip().lower()
    if _is_valid_hash(normalized_reference):
        return "users.email innehaller en hash i stallet for en leveransbar e-postadress."
    return "Privatkontot saknar leveransbar e-postadress."


def _build_supervisor_issue_reason(supervisor_reference: str, company_row) -> str:
    company_email = getattr(company_row, "email", None) if company_row is not None else None
    invalid_reason = _get_invalid_email_reason(company_email)
    if invalid_reason:
        return f"Ogiltig e-postadress i company_users.email ({invalid_reason})"
    if company_row is None:
        normalized_reference = supervisor_reference.strip().lower()
        if _is_valid_hash(normalized_reference):
            return (
                "supervisor_connections.supervisor_email innehaller en hash och inget "
                "matchande foretagskonto kunde hittas."
            )
        return (
            "Inget matchande foretagskonto hittades for "
            "supervisor_connections.supervisor_email."
        )
    if not company_email:
        return "Saknar e-postadress i company_users.email."
    normalized_company_email = company_email.strip().lower()
    if _is_valid_hash(normalized_company_email):
        return (
            "company_users.email innehaller en hash i stallet for en "
            "leveransbar e-postadress."
        )
    return "Foretagskontot saknar leveransbar e-postadress."


def _build_private_admin_issue(
    owner_hash: str,
    reason: str,
    expiring_rows_by_owner: dict[str, list],
) -> ReminderAdminIssue:
    account_rows = expiring_rows_by_owner.get(owner_hash, [])
    primary_row = account_rows[0] if account_rows else None
    account_payload = {
        "owner_hash": owner_hash,
        "username": _format_value_for_admin(getattr(primary_row, "username", None)),
        "email": _format_value_for_admin(getattr(primary_row, "email", None)),
        "orgnr_normalized": _format_value_for_admin(
            getattr(primary_row, "orgnr_normalized", None)
        ),
        "certificates": _format_certificate_rows_for_admin(account_rows),
    }
    return ReminderAdminIssue(
        issue_type="private",
        recipient_type="privatkonto",
        reason=reason,
        account_payload=account_payload,
    )


def _build_supervisor_admin_issue(
    supervisor_reference: str,
    reason: str,
    owners_by_supervisor: dict[str, set[str]],
    expiring_rows_by_owner: dict[str, list],
    company_rows_by_reference: dict[str, object],
) -> ReminderAdminIssue:
    normalized_reference = _normalize_reference_key(supervisor_reference)
    company_row = (
        company_rows_by_reference.get(normalized_reference)
        if normalized_reference is not None
        else None
    )
    linked_accounts = []
    for owner_hash in sorted(owners_by_supervisor.get(supervisor_reference, set())):
        account_rows = expiring_rows_by_owner.get(owner_hash, [])
        primary_row = account_rows[0] if account_rows else None
        linked_accounts.append(
            {
                "owner_hash": owner_hash,
                "username": _format_value_for_admin(getattr(primary_row, "username", None)),
                "email": _format_value_for_admin(getattr(primary_row, "email", None)),
                "orgnr_normalized": _format_value_for_admin(
                    getattr(primary_row, "orgnr_normalized", None)
                ),
                "certificates": _format_certificate_rows_for_admin(account_rows),
            }
        )

    account_payload = {
        "supervisor_reference": _format_value_for_admin(supervisor_reference),
        "company_user_id": _format_value_for_admin(
            getattr(company_row, "company_user_id", None)
        ),
        "company_id": _format_value_for_admin(getattr(company_row, "company_id", None)),
        "company_user_name": _format_value_for_admin(getattr(company_row, "name", None)),
        "company_user_email": _format_value_for_admin(getattr(company_row, "email", None)),
        "company_name": _format_value_for_admin(
            getattr(company_row, "company_name", None)
        ),
        "company_orgnr": _format_value_for_admin(
            getattr(company_row, "company_orgnr", None)
        ),
        "invoice_address": _format_value_for_admin(
            getattr(company_row, "invoice_address", None)
        ),
        "invoice_contact": _format_value_for_admin(
            getattr(company_row, "invoice_contact", None)
        ),
        "invoice_reference": _format_value_for_admin(
            getattr(company_row, "invoice_reference", None)
        ),
        "created_via_application_id": _format_value_for_admin(
            getattr(company_row, "created_via_application_id", None)
        ),
        "company_user_created_at": _format_value_for_admin(
            getattr(company_row, "company_user_created_at", None)
        ),
        "company_user_updated_at": _format_value_for_admin(
            getattr(company_row, "company_user_updated_at", None)
        ),
        "company_created_at": _format_value_for_admin(
            getattr(company_row, "company_created_at", None)
        ),
        "company_updated_at": _format_value_for_admin(
            getattr(company_row, "company_updated_at", None)
        ),
        "linked_accounts": linked_accounts,
    }
    return ReminderAdminIssue(
        issue_type="supervisor",
        recipient_type="foretagskonto",
        reason=reason,
        account_payload=account_payload,
    )


def _render_admin_kv_list(items: list[tuple[str, str]]) -> str:
    return "".join(
        f"<li><strong>{escape(label)}:</strong> {escape(value)}</li>"
        for label, value in items
    )


def _render_admin_certificate_list(certificates: list[dict[str, str]]) -> str:
    if not certificates:
        return "<p>Inga berorda intyg hittades.</p>"
    items = []
    for certificate in certificates:
        items.append(
            "<li>"
            f"<strong>PDF-ID:</strong> {escape(certificate['pdf_id'])} | "
            f"<strong>Filnamn:</strong> {escape(certificate['filename'])} | "
            f"<strong>Kategorier:</strong> {escape(certificate['categories'])} | "
            f"<strong>Gar ut:</strong> {escape(certificate['expires_on'])} | "
            f"<strong>Uppladdad:</strong> {escape(certificate['uploaded_at'])} | "
            f"<strong>last_expiry_reminder_month:</strong> "
            f"{escape(certificate['last_expiry_reminder_month'])} | "
            f"<strong>last_expiry_reminder_sent_at:</strong> "
            f"{escape(certificate['last_expiry_reminder_sent_at'])} | "
            f"<strong>Anteckning:</strong> {escape(certificate['note'])}"
            "</li>"
        )
    return f"<ul>{''.join(items)}</ul>"


def _render_private_admin_issue(issue: ReminderAdminIssue) -> str:
    payload = issue.account_payload
    account_items = [
        ("Problem", issue.reason),
        ("Kontotyp", issue.recipient_type),
        ("Personnummer-hash", _format_value_for_admin(payload.get("owner_hash"))),
        ("Namn", _format_value_for_admin(payload.get("username"))),
        ("E-post i users.email", _format_value_for_admin(payload.get("email"))),
        (
            "Organisationsnummer",
            _format_value_for_admin(payload.get("orgnr_normalized")),
        ),
    ]
    return (
        "<section style='margin-top:24px;'>"
        "<h2 style='margin:0 0 12px 0;font-size:20px;'>Privatkonto som kraver manuell atgard</h2>"
        f"<ul>{_render_admin_kv_list(account_items)}</ul>"
        "<p><strong>Berorda intyg:</strong></p>"
        f"{_render_admin_certificate_list(list(payload.get('certificates', [])))}"
        "</section>"
    )


def _render_supervisor_admin_issue(issue: ReminderAdminIssue) -> str:
    payload = issue.account_payload
    company_items = [
        ("Problem", issue.reason),
        ("Kontotyp", issue.recipient_type),
        (
            "supervisor_connections.supervisor_email",
            _format_value_for_admin(payload.get("supervisor_reference")),
        ),
        ("company_users.id", _format_value_for_admin(payload.get("company_user_id"))),
        ("company_users.company_id", _format_value_for_admin(payload.get("company_id"))),
        ("company_users.name", _format_value_for_admin(payload.get("company_user_name"))),
        (
            "company_users.email",
            _format_value_for_admin(payload.get("company_user_email")),
        ),
        ("companies.name", _format_value_for_admin(payload.get("company_name"))),
        ("companies.orgnr", _format_value_for_admin(payload.get("company_orgnr"))),
        (
            "companies.invoice_address",
            _format_value_for_admin(payload.get("invoice_address")),
        ),
        (
            "companies.invoice_contact",
            _format_value_for_admin(payload.get("invoice_contact")),
        ),
        (
            "companies.invoice_reference",
            _format_value_for_admin(payload.get("invoice_reference")),
        ),
        (
            "company_users.created_via_application_id",
            _format_value_for_admin(payload.get("created_via_application_id")),
        ),
        (
            "company_users.created_at",
            _format_value_for_admin(payload.get("company_user_created_at")),
        ),
        (
            "company_users.updated_at",
            _format_value_for_admin(payload.get("company_user_updated_at")),
        ),
        ("companies.created_at", _format_value_for_admin(payload.get("company_created_at"))),
        ("companies.updated_at", _format_value_for_admin(payload.get("company_updated_at"))),
    ]

    linked_account_sections = []
    for account in payload.get("linked_accounts", []):
        linked_account_items = [
            ("Personnummer-hash", _format_value_for_admin(account.get("owner_hash"))),
            ("Namn", _format_value_for_admin(account.get("username"))),
            ("E-post i users.email", _format_value_for_admin(account.get("email"))),
            (
                "Organisationsnummer",
                _format_value_for_admin(account.get("orgnr_normalized")),
            ),
        ]
        linked_account_sections.append(
            "<div style='margin-top:16px;padding:12px;border:1px solid #e2e8f0;border-radius:8px;'>"
            "<p style='margin:0 0 8px 0;'><strong>Anslutet konto</strong></p>"
            f"<ul>{_render_admin_kv_list(linked_account_items)}</ul>"
            "<p><strong>Berorda intyg:</strong></p>"
            f"{_render_admin_certificate_list(list(account.get('certificates', [])))}"
            "</div>"
        )

    return (
        "<section style='margin-top:24px;'>"
        "<h2 style='margin:0 0 12px 0;font-size:20px;'>Foretagskonto som kraver manuell atgard</h2>"
        f"<ul>{_render_admin_kv_list(company_items)}</ul>"
        f"{''.join(linked_account_sections) or '<p>Inga anslutna konton hittades.</p>'}"
        "</section>"
    )


def _send_admin_issue_report(
    issues: list[ReminderAdminIssue],
    *,
    today: date,
    reminder_months: int,
) -> None:
    if not issues:
        return

    recipients = _normalize_admin_recipients()
    if not recipients:
        logger.warning(
            "ADMIN_EMAIL saknas eller ar ogiltig; kan inte skicka adminrapport for utgangspaminnelser."
        )
        return

    private_issue_count = sum(1 for issue in issues if issue.issue_type == "private")
    supervisor_issue_count = len(issues) - private_issue_count
    issue_sections = []
    for issue in issues:
        if issue.issue_type == "private":
            issue_sections.append(_render_private_admin_issue(issue))
        else:
            issue_sections.append(_render_supervisor_admin_issue(issue))

    content = (
        "<p>Hej,</p>"
        "<p>Utgangspaminnelsejobbet kraver manuell uppfoljning. Minst ett konto "
        "kunde inte fa sitt paminnelsemejl eller hoppades over.</p>"
        f"<p><strong>Kordatum:</strong> {escape(str(today))}<br>"
        f"<strong>Paminnelsefonster:</strong> {escape(str(reminder_months))} manader<br>"
        f"<strong>Privatkonton att folja upp:</strong> {private_issue_count}<br>"
        f"<strong>Foretagskonton att folja upp:</strong> {supervisor_issue_count}</p>"
        f"{''.join(issue_sections)}"
        "<p>Kontrollera uppgifterna ovan och uppdatera databasen manuellt vid behov.</p>"
    )
    body = email_service.format_email_html(
        "Manuell uppfoljning kravs for utgangspaminnelser",
        content,
        accent_color="#b91c1c",
    )
    subject = "Manuell uppfoljning kravs for utgangspaminnelser"
    for recipient in recipients:
        try:
            email_service.send_email(recipient, subject, body)
        except Exception:
            logger.warning(
                "Misslyckades att skicka adminrapport for utgangspaminnelser till %s",
                recipient,
                exc_info=True,
            )


def _fetch_expiring_certificate_rows(
    today: date,
    cutoff_date: date,
    *,
    now: datetime,
    duplicate_guard_window: timedelta,
) -> tuple[list, int, int]:
    current_month = _current_reminder_month(today)
    query = (
        select(
            user_pdfs_table.c.id,
            user_pdfs_table.c.personnummer,
            user_pdfs_table.c.filename,
            user_pdfs_table.c.categories,
            user_pdfs_table.c.expires_on,
            user_pdfs_table.c.uploaded_at,
            user_pdfs_table.c.last_expiry_reminder_month,
            user_pdfs_table.c.last_expiry_reminder_sent_at,
            user_pdfs_table.c.note,
            users_table.c.username,
            users_table.c.email,
            users_table.c.orgnr_normalized,
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
    skipped_duplicate_guard = 0
    for row in rows:
        if row.last_expiry_reminder_month == current_month:
            skipped_current_month += 1
            continue
        if _was_recently_reminded(
            row.last_expiry_reminder_sent_at,
            now=now,
            duplicate_guard_window=duplicate_guard_window,
        ):
            skipped_duplicate_guard += 1
            continue
        eligible_rows.append(row)
    return eligible_rows, skipped_current_month, skipped_duplicate_guard


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
        lookup_references.update(_iter_reference_lookup_keys(reference))

    if not lookup_references:
        return []

    query = (
        select(
            company_users_table.c.id.label("company_user_id"),
            company_users_table.c.company_id,
            company_users_table.c.role,
            company_users_table.c.email,
            company_users_table.c.name,
            company_users_table.c.created_via_application_id,
            company_users_table.c.created_at.label("company_user_created_at"),
            company_users_table.c.updated_at.label("company_user_updated_at"),
            companies_table.c.name.label("company_name"),
            companies_table.c.orgnr.label("company_orgnr"),
            companies_table.c.invoice_address,
            companies_table.c.invoice_contact,
            companies_table.c.invoice_reference,
            companies_table.c.created_at.label("company_created_at"),
            companies_table.c.updated_at.label("company_updated_at"),
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


def _build_company_rows_by_reference(
    supervisor_references: set[str],
    company_rows: list,
) -> dict[str, object]:
    rows_by_reference = {
        normalized_reference: row
        for row in company_rows
        for normalized_reference in _iter_reference_lookup_keys(row.email)
        if normalized_reference is not None
    }

    for supervisor_reference in supervisor_references:
        normalized_supervisor_reference = _normalize_reference_key(supervisor_reference)
        if (
            normalized_supervisor_reference is None
            or normalized_supervisor_reference in rows_by_reference
        ):
            continue
        for lookup_key in _iter_reference_lookup_keys(supervisor_reference):
            company_row = rows_by_reference.get(lookup_key)
            if company_row is None:
                continue
            rows_by_reference[normalized_supervisor_reference] = company_row
            break
    return rows_by_reference


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


def _update_last_reminder_month(
    pdf_ids: list[int],
    current_month: str,
    sent_at: datetime,
) -> int:
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
                .values(
                    last_expiry_reminder_month=current_month,
                    last_expiry_reminder_sent_at=sent_at,
                )
            )
            updated_count += int(result.rowcount or 0)
    return updated_count


def run_expiry_reminder_job(
    *,
    today: date | None = None,
    reminder_months: int | None = None,
    duplicate_guard_minutes: int | None = None,
    now: datetime | None = None,
) -> ReminderJobResult:
    if not _reminders_enabled():
        logger.info("Utgångspåminnelser är avstängda. Avslutar utan utskick.")
        return ReminderJobResult(0, 0, 0, 0, 0, 0, 0, 0)

    today = today or date.today()
    reminder_months = reminder_months if reminder_months is not None else _get_reminder_months()
    duplicate_guard_minutes = (
        duplicate_guard_minutes
        if duplicate_guard_minutes is not None
        else _get_duplicate_guard_minutes()
    )
    now = now or datetime.now(timezone.utc)
    duplicate_guard_window = timedelta(minutes=duplicate_guard_minutes)
    cutoff_date = _add_months_to_date(today, reminder_months)
    current_month = _current_reminder_month(today)

    logger.info("Startar kontroll av intyg som snart går ut")

    expiring_rows, skipped_current_month, skipped_duplicate_guard = _fetch_expiring_certificate_rows(
        today,
        cutoff_date,
        now=now,
        duplicate_guard_window=duplicate_guard_window,
    )
    if skipped_current_month:
        logger.info(
            "Hoppade över intyg som redan påmints denna månad: %s",
            skipped_current_month,
        )
    if skipped_duplicate_guard:
        logger.info(
            "Hoppade över intyg som påmints för nyligen enligt dublettskyddet: %s",
            skipped_duplicate_guard,
        )

    if not expiring_rows:
        logger.info("Inga intyg behöver påminnas")
        logger.info("Utgångspåminnelsejobb klart")
        return ReminderJobResult(0, skipped_current_month, 0, 0, 0, 0, 0, 0, skipped_duplicate_guard)

    owner_hashes = {row.personnummer for row in expiring_rows}
    expiring_rows_by_owner: dict[str, list] = defaultdict(list)
    for row in expiring_rows:
        expiring_rows_by_owner[row.personnummer].append(row)
    connection_rows = _fetch_connection_rows(owner_hashes)
    connections_by_owner: dict[str, set[str]] = defaultdict(set)
    owners_by_supervisor: dict[str, set[str]] = defaultdict(set)
    supervisor_references: set[str] = set()
    for row in connection_rows:
        connections_by_owner[row.user_personnummer].add(row.supervisor_email)
        owners_by_supervisor[row.supervisor_email].add(row.user_personnummer)
        supervisor_references.add(row.supervisor_email)

    company_rows = _fetch_company_rows(supervisor_references)
    indexed_company_rows = _index_company_rows(company_rows)
    company_rows_by_reference = _build_company_rows_by_reference(
        supervisor_references,
        company_rows,
    )

    intended_tokens_by_pdf: dict[int, set[str]] = defaultdict(set)
    private_batches: dict[str, dict[str, object]] = {}
    supervisor_batches: dict[str, dict[str, object]] = {}
    unresolved_private_tokens: set[str] = set()
    unresolved_supervisor_tokens: set[str] = set()
    invalid_email_references: dict[tuple[str, str], InvalidEmailReference] = {}
    admin_issues: list[ReminderAdminIssue] = []

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
            _record_invalid_email_reference(
                invalid_email_references,
                "private",
                row.email,
            )

        for supervisor_reference in sorted(connections_by_owner.get(row.personnummer, set())):
            supervisor_token = f"supervisor:{supervisor_reference}"
            intended_tokens_by_pdf[row.id].add(supervisor_token)
            company_recipient = _resolve_company_recipient(
                supervisor_reference,
                indexed_company_rows,
            )
            if not company_recipient or not company_recipient["resolved_email"]:
                unresolved_supervisor_tokens.add(supervisor_token)
                _record_invalid_email_reference(
                    invalid_email_references,
                    "supervisor",
                    (
                        company_recipient["email_reference"]
                        if company_recipient
                        else supervisor_reference
                    ),
                )
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

    for token in sorted(unresolved_private_tokens):
        owner_hash = token.split(":", 1)[1]
        admin_issues.append(
            _build_private_admin_issue(
                owner_hash,
                _build_private_issue_reason(
                    getattr(
                        expiring_rows_by_owner.get(owner_hash, [None])[0],
                        "email",
                        None,
                    )
                ),
                expiring_rows_by_owner,
            )
        )

    for token in sorted(unresolved_supervisor_tokens):
        supervisor_reference = token.split(":", 1)[1]
        admin_issues.append(
            _build_supervisor_admin_issue(
                supervisor_reference,
                _build_supervisor_issue_reason(
                    supervisor_reference,
                    company_rows_by_reference.get(
                        _normalize_reference_key(supervisor_reference)
                    ),
                ),
                owners_by_supervisor,
                expiring_rows_by_owner,
                company_rows_by_reference,
            )
        )

    _log_invalid_email_references(invalid_email_references)

    if not private_batches and not supervisor_batches:
        _send_admin_issue_report(
            admin_issues,
            today=today,
            reminder_months=reminder_months,
        )
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
            skipped_duplicate_guard,
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
        except Exception as exc:
            failed_emails += 1
            logger.exception(
                "Misslyckades att skicka utgångspåminnelse till privatkonto (%s)",
                mask_hash(str(batch["owner_hash"])),
                extra={"skip_error_email": True},
            )
            admin_issues.append(
                _build_private_admin_issue(
                    str(batch["owner_hash"]),
                    f"Utskick misslyckades: {type(exc).__name__}: {exc}",
                    expiring_rows_by_owner,
                )
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
        except Exception as exc:
            failed_emails += 1
            logger.exception(
                "Misslyckades att skicka utgångspåminnelse till företagskonto (%s)",
                mask_email_reference(str(batch["email_reference"])),
                extra={"skip_error_email": True},
            )
            admin_issues.append(
                _build_supervisor_admin_issue(
                    str(batch["email_reference"]),
                    f"Utskick misslyckades: {type(exc).__name__}: {exc}",
                    owners_by_supervisor,
                    expiring_rows_by_owner,
                    company_rows_by_reference,
                )
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
    updated_certificates = _update_last_reminder_month(
        successful_pdf_ids,
        current_month,
        now,
    )
    _send_admin_issue_report(
        admin_issues,
        today=today,
        reminder_months=reminder_months,
    )

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
        skipped_duplicate_guard,
    )


def main() -> int:
    if not _reminders_enabled():
        logger.info("Utgångspåminnelser är avstängda. Avslutar utan utskick.")
        return 0

    try:
        reminder_months = _get_reminder_months()
        duplicate_guard_minutes = _get_duplicate_guard_minutes()
    except ValueError as exc:
        logger.error("Ogiltig konfiguration för utgångspåminnelser: %s", str(exc))
        return 1

    create_database()
    result = run_expiry_reminder_job(
        reminder_months=reminder_months,
        duplicate_guard_minutes=duplicate_guard_minutes,
    )
    return 1 if result.had_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())


# Copyright (c) Liam Suorsa and Mika Suorsa
