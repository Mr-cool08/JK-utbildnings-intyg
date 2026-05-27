# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

from datetime import date

from sqlalchemy import select, update

from course_categories import COURSE_CATEGORIES
import functions
from scripts import send_expiry_reminders as expiry_reminders


def _set_reminder_config(monkeypatch, *, enabled: bool, months: str = "6") -> None:
    monkeypatch.setenv(
        "CERTIFICATE_EXPIRY_REMINDERS_ENABLED",
        "true" if enabled else "false",
    )
    monkeypatch.setenv("CERTIFICATE_EXPIRY_REMINDER_MONTHS", months)


def _personnummer_hash(personnummer: str) -> str:
    return functions.hash_value(functions.normalize_personnummer(personnummer))


def _create_active_user(
    empty_db,
    *,
    personnummer: str,
    email: str,
    username: str,
) -> str:
    personnummer_hash = _personnummer_hash(personnummer)
    with empty_db.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username=username,
                email=functions.normalize_email(email),
                password=functions.hash_password("StarktLosen123"),
                personnummer=personnummer_hash,
            )
        )
    return personnummer_hash


def _create_company_account(
    empty_db,
    *,
    email: str,
    company_name: str,
    orgnr: str = "5569668337",
) -> str:
    normalized_email = functions.normalize_email(email)
    normalized_orgnr = functions.validate_orgnr(orgnr)
    with empty_db.begin() as conn:
        company_id = conn.execute(
            functions.companies_table.insert().values(
                name=company_name,
                orgnr=normalized_orgnr,
            )
        ).inserted_primary_key[0]
        conn.execute(
            functions.company_users_table.insert().values(
                company_id=company_id,
                role="foretagskonto",
                name=company_name,
                email=normalized_email,
            )
        )
        conn.execute(
            functions.supervisors_table.insert().values(
                name=company_name,
                email=normalized_email,
                password=functions.hash_password("StarktLosen123"),
            )
        )
    return normalized_email


def _connect_company_account(empty_db, *, supervisor_reference: str, personnummer_hash: str) -> None:
    with empty_db.begin() as conn:
        conn.execute(
            functions.supervisor_connections_table.insert().values(
                supervisor_email=supervisor_reference,
                user_personnummer=personnummer_hash,
            )
        )


def _store_certificate(
    empty_db,
    *,
    personnummer_hash: str,
    filename: str,
    expires_on: date | None,
    categories: list[str] | None = None,
    last_reminder_month: str | None = None,
) -> int:
    pdf_id = functions.store_pdf_blob(
        personnummer_hash,
        filename,
        b"%PDF-1.4 test",
        categories or [],
        expires_on=expires_on,
    )
    if last_reminder_month is not None:
        with empty_db.begin() as conn:
            conn.execute(
                update(functions.user_pdfs_table)
                .where(functions.user_pdfs_table.c.id == pdf_id)
                .values(last_expiry_reminder_month=last_reminder_month)
            )
    return pdf_id


def _capture_email_calls(monkeypatch):
    private_calls = []
    supervisor_calls = []

    def _fake_private_email(to_email, recipient_name, expiring_certificates, *, months=6):
        private_calls.append(
            {
                "to_email": to_email,
                "recipient_name": recipient_name,
                "expiring_certificates": expiring_certificates,
                "months": months,
            }
        )

    def _fake_supervisor_email(to_email, company_name, expiring_by_user, *, months=6):
        supervisor_calls.append(
            {
                "to_email": to_email,
                "company_name": company_name,
                "expiring_by_user": expiring_by_user,
                "months": months,
            }
        )

    monkeypatch.setattr(
        expiry_reminders.email_service,
        "send_certificate_expiry_summary_email",
        _fake_private_email,
    )
    monkeypatch.setattr(
        expiry_reminders.email_service,
        "send_supervisor_expiry_summary_email",
        _fake_supervisor_email,
    )
    return private_calls, supervisor_calls


def test_expiry_reminders_include_certificates_with_less_than_six_months_left(
    empty_db,
    monkeypatch,
):
    _set_reminder_config(monkeypatch, enabled=True)
    private_calls, supervisor_calls = _capture_email_calls(monkeypatch)
    today = date(2026, 5, 27)
    personnummer_hash = _create_active_user(
        empty_db,
        personnummer="19900101-1234",
        email="anna@example.com",
        username="Anna",
    )
    _store_certificate(
        empty_db,
        personnummer_hash=personnummer_hash,
        filename="truckkort.pdf",
        expires_on=date(2026, 8, 10),
        categories=[COURSE_CATEGORIES[0][0]],
    )

    result = expiry_reminders.run_expiry_reminder_job(today=today, reminder_months=6)

    assert result.candidate_certificates == 1
    assert len(private_calls) == 1
    assert supervisor_calls == []
    assert private_calls[0]["expiring_certificates"] == [
        {
            "display_name": COURSE_CATEGORIES[0][1],
            "expires_on": "2026-08-10",
        }
    ]


def test_expiry_reminders_exclude_certificates_with_more_than_six_months_left(
    empty_db,
    monkeypatch,
):
    _set_reminder_config(monkeypatch, enabled=True)
    private_calls, _ = _capture_email_calls(monkeypatch)
    today = date(2026, 5, 27)
    personnummer_hash = _create_active_user(
        empty_db,
        personnummer="19900202-1234",
        email="erik@example.com",
        username="Erik",
    )
    _store_certificate(
        empty_db,
        personnummer_hash=personnummer_hash,
        filename="framtid.pdf",
        expires_on=date(2026, 12, 1),
    )

    result = expiry_reminders.run_expiry_reminder_job(today=today, reminder_months=6)

    assert result.candidate_certificates == 0
    assert private_calls == []


def test_expiry_reminders_exclude_certificates_without_expiry_date(empty_db, monkeypatch):
    _set_reminder_config(monkeypatch, enabled=True)
    private_calls, _ = _capture_email_calls(monkeypatch)
    today = date(2026, 5, 27)
    personnummer_hash = _create_active_user(
        empty_db,
        personnummer="19900303-1234",
        email="lisa@example.com",
        username="Lisa",
    )
    _store_certificate(
        empty_db,
        personnummer_hash=personnummer_hash,
        filename="utan-datum.pdf",
        expires_on=None,
    )

    result = expiry_reminders.run_expiry_reminder_job(today=today, reminder_months=6)

    assert result.candidate_certificates == 0
    assert private_calls == []


def test_expiry_reminders_do_not_repeat_same_certificate_in_same_month(
    empty_db,
    monkeypatch,
):
    _set_reminder_config(monkeypatch, enabled=True)
    private_calls, _ = _capture_email_calls(monkeypatch)
    today = date(2026, 5, 27)
    personnummer_hash = _create_active_user(
        empty_db,
        personnummer="19900404-1234",
        email="maria@example.com",
        username="Maria",
    )
    _store_certificate(
        empty_db,
        personnummer_hash=personnummer_hash,
        filename="redan-pamind.pdf",
        expires_on=date(2026, 8, 10),
        last_reminder_month="2026-05",
    )

    result = expiry_reminders.run_expiry_reminder_job(today=today, reminder_months=6)

    assert result.candidate_certificates == 0
    assert result.skipped_current_month == 1
    assert private_calls == []


def test_expiry_reminders_send_single_private_summary_email(empty_db, monkeypatch):
    _set_reminder_config(monkeypatch, enabled=True)
    private_calls, _ = _capture_email_calls(monkeypatch)
    today = date(2026, 5, 27)
    personnummer_hash = _create_active_user(
        empty_db,
        personnummer="19900505-1234",
        email="olle@example.com",
        username="Olle",
    )
    first_pdf_id = _store_certificate(
        empty_db,
        personnummer_hash=personnummer_hash,
        filename="forsta.pdf",
        expires_on=date(2026, 8, 10),
    )
    second_pdf_id = _store_certificate(
        empty_db,
        personnummer_hash=personnummer_hash,
        filename="andra.pdf",
        expires_on=date(2026, 9, 1),
    )

    result = expiry_reminders.run_expiry_reminder_job(today=today, reminder_months=6)

    assert result.sent_private_emails == 1
    assert len(private_calls) == 1
    assert len(private_calls[0]["expiring_certificates"]) == 2

    with empty_db.connect() as conn:
        rows = conn.execute(
            select(
                functions.user_pdfs_table.c.id,
                functions.user_pdfs_table.c.last_expiry_reminder_month,
            ).where(functions.user_pdfs_table.c.id.in_((first_pdf_id, second_pdf_id)))
        ).fetchall()

    assert {row.id for row in rows} == {first_pdf_id, second_pdf_id}
    assert {row.last_expiry_reminder_month for row in rows} == {"2026-05"}


def test_expiry_reminders_send_single_company_summary_email_for_connected_users(
    empty_db,
    monkeypatch,
):
    _set_reminder_config(monkeypatch, enabled=True)
    _, supervisor_calls = _capture_email_calls(monkeypatch)
    today = date(2026, 5, 27)

    anna_hash = _create_active_user(
        empty_db,
        personnummer="19900606-1234",
        email="anna.foretag@example.com",
        username="Anna Andersson",
    )
    erik_hash = _create_active_user(
        empty_db,
        personnummer="19900707-1234",
        email="erik.foretag@example.com",
        username="Erik Eriksson",
    )
    supervisor_reference = _create_company_account(
        empty_db,
        email="foretag@example.com",
        company_name="Företag AB",
    )
    _connect_company_account(
        empty_db,
        supervisor_reference=supervisor_reference,
        personnummer_hash=anna_hash,
    )
    _connect_company_account(
        empty_db,
        supervisor_reference=supervisor_reference,
        personnummer_hash=erik_hash,
    )
    _store_certificate(
        empty_db,
        personnummer_hash=anna_hash,
        filename="anna.pdf",
        expires_on=date(2026, 8, 10),
    )
    _store_certificate(
        empty_db,
        personnummer_hash=erik_hash,
        filename="erik.pdf",
        expires_on=date(2026, 9, 15),
    )

    result = expiry_reminders.run_expiry_reminder_job(today=today, reminder_months=6)

    assert result.sent_supervisor_emails == 1
    assert len(supervisor_calls) == 1
    assert supervisor_calls[0]["company_name"] == "Företag AB"
    assert {entry["user_name"] for entry in supervisor_calls[0]["expiring_by_user"]} == {
        "Anna Andersson",
        "Erik Eriksson",
    }


def test_expiry_reminders_do_not_send_when_disabled(empty_db, monkeypatch):
    _set_reminder_config(monkeypatch, enabled=False)
    private_calls, supervisor_calls = _capture_email_calls(monkeypatch)
    today = date(2026, 5, 27)
    personnummer_hash = _create_active_user(
        empty_db,
        personnummer="19900808-1234",
        email="stina@example.com",
        username="Stina",
    )
    _store_certificate(
        empty_db,
        personnummer_hash=personnummer_hash,
        filename="disabled.pdf",
        expires_on=date(2026, 8, 10),
    )

    result = expiry_reminders.run_expiry_reminder_job(today=today, reminder_months=6)

    assert result == expiry_reminders.ReminderJobResult(0, 0, 0, 0, 0, 0, 0, 0)
    assert private_calls == []
    assert supervisor_calls == []


def test_expiry_reminders_only_mark_month_after_all_recipients_succeed(
    empty_db,
    monkeypatch,
):
    _set_reminder_config(monkeypatch, enabled=True)
    private_calls = []
    today = date(2026, 5, 27)
    personnummer_hash = _create_active_user(
        empty_db,
        personnummer="19900909-1234",
        email="sam@example.com",
        username="Sam",
    )
    supervisor_reference = _create_company_account(
        empty_db,
        email="sam.foretag@example.com",
        company_name="Sam AB",
    )
    _connect_company_account(
        empty_db,
        supervisor_reference=supervisor_reference,
        personnummer_hash=personnummer_hash,
    )
    pdf_id = _store_certificate(
        empty_db,
        personnummer_hash=personnummer_hash,
        filename="sam.pdf",
        expires_on=date(2026, 8, 10),
    )

    def _fake_private_email(to_email, recipient_name, expiring_certificates, *, months=6):
        private_calls.append((to_email, recipient_name, expiring_certificates, months))

    def _failing_supervisor_email(*_args, **_kwargs):
        raise RuntimeError("smtp-fel")

    monkeypatch.setattr(
        expiry_reminders.email_service,
        "send_certificate_expiry_summary_email",
        _fake_private_email,
    )
    monkeypatch.setattr(
        expiry_reminders.email_service,
        "send_supervisor_expiry_summary_email",
        _failing_supervisor_email,
    )

    result = expiry_reminders.run_expiry_reminder_job(today=today, reminder_months=6)

    with empty_db.connect() as conn:
        row = conn.execute(
            select(functions.user_pdfs_table.c.last_expiry_reminder_month).where(
                functions.user_pdfs_table.c.id == pdf_id
            )
        ).first()

    assert len(private_calls) == 1
    assert result.failed_emails == 1
    assert row is not None
    assert row.last_expiry_reminder_month is None


# Copyright (c) Liam Suorsa and Mika Suorsa
