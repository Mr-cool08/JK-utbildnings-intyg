# Copyright (c) Liam Suorsa and Mika Suorsa
import pytest

import functions


@pytest.fixture
def fresh_app_db(empty_db):
    # Reset any cached data for deterministic tests.
    return empty_db


def test_application_approval_creates_company_and_user(fresh_app_db):
    application_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Test Företagskonto",
        email="applicant@example.com",
        orgnr="556966-8337",
        company_name="Testbolag AB",
        comment="Vill komma igång",
        invoice_address="Testvägen 1\n123 45 Teststad",
        invoice_contact="Anna Andersson",
        invoice_reference="Ref 123",
    )

    result = functions.approve_application_request(application_id, "admin")

    assert result["company_created"] is True
    assert result["account_type"] == "foretagskonto"
    assert result["orgnr"] == "5569668337"
    assert result["company_name"] == "Testbolag AB"
    assert result["pending_supervisor_created"] is True
    assert result["supervisor_activation_required"] is True
    assert result["supervisor_email_hash"] == functions.hash_value(
        functions.normalize_email("applicant@example.com")
    )

    with fresh_app_db.connect() as conn:
        company = conn.execute(functions.companies_table.select()).first()
        assert company is not None
        assert company.name == "Testbolag AB"

        user = conn.execute(functions.company_users_table.select()).first()
        assert user is not None
        assert user.email == "applicant@example.com"
        assert user.company_id == company.id
        assert user.role == "foretagskonto"

        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select()
        ).first()
        assert pending_supervisor is not None
        assert pending_supervisor.email == functions.hash_value(
            functions.normalize_email("applicant@example.com")
        )
        assert pending_supervisor.name == "Test Företagskonto"

        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == "approved"
        assert application.reviewed_by == "admin"
        assert application.invoice_address == "Testvägen 1\n123 45 Teststad"
        assert application.invoice_contact == "Anna Andersson"
        assert application.invoice_reference == "Ref 123"


def test_application_rejection_stores_reason(fresh_app_db):
    application_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Företagskonto Test",
        email="foretagskonto@example.com",
        orgnr="5569668337",
        company_name="Handledarbolaget",
        comment="Behöver åtkomst",
        invoice_address="Bolagsgatan 2",
        invoice_contact="Björn", 
        invoice_reference="Order 77",
    )

    result = functions.reject_application_request(
        application_id, "admin"
    )


    assert result["account_type"] == "foretagskonto"
    assert result["company_name"] == "Handledarbolaget"

    with fresh_app_db.connect() as conn:
        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == "rejected"
        assert application.reviewed_by == "admin"


def test_approval_reuses_existing_company(fresh_app_db):
    foretagskonto_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Företagskonton",
        email="foretagskonto@example.com",
        orgnr="5569668337",
        company_name="Bolaget AB",
        comment=None,
        invoice_address="Bolagsvägen 3",
        invoice_contact="Carina Kontakt",
        invoice_reference="Fakt 2024",
    )
    user_id = functions.create_application_request(
        account_type="standard",
        name="Första Användaren",
        email="first@example.com",
        orgnr="",
        company_name="",
        comment=None,
        invoice_address=None,
        invoice_contact=None,
        invoice_reference=None,
        personnummer="9001011234",
    )

    foretagskonto_result = functions.approve_application_request(
        foretagskonto_id, "admin"
    )
    user_result = functions.approve_application_request(user_id, "admin")

    assert foretagskonto_result["company_created"] is True
    assert user_result["company_created"] is False
    assert user_result["company_id"] is None
    assert user_result["company_name"] == ""
    assert foretagskonto_result["pending_supervisor_created"] is True
    assert foretagskonto_result["supervisor_activation_required"] is True
    assert user_result["pending_supervisor_created"] is False
    assert user_result["supervisor_activation_required"] is False
    assert user_result["supervisor_email_hash"] is None
    assert user_result["user_activation_required"] is True
    assert user_result["user_personnummer_hash"] == functions.hash_value("9001011234")

    with fresh_app_db.connect() as conn:
        companies = conn.execute(functions.companies_table.select()).fetchall()
        assert len(companies) == 1

        users = conn.execute(functions.company_users_table.select()).fetchall()
        emails = {row.email for row in users}
        assert emails == {"first@example.com", "foretagskonto@example.com"}

        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select()
        ).fetchall()
        assert len(pending_supervisor) == 1


def test_foretagskonto_and_standard_can_share_email(fresh_app_db):
    foretagskonto_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Företagskonto",
        email="shared@example.com",
        orgnr="5569668337",
        company_name="Delat Bolag",
        comment=None,
        invoice_address="Faktura 1",
        invoice_contact="Kontakt 1",
        invoice_reference="Ref 1",
    )
    standard_id = functions.create_application_request(
        account_type="standard",
        name="Standardkonto",
        email="shared@example.com",
        orgnr="",
        company_name="",
        comment=None,
        invoice_address=None,
        invoice_contact=None,
        invoice_reference=None,
        personnummer="9001011234",
    )

    foretagskonto_result = functions.approve_application_request(
        foretagskonto_id, "admin"
    )
    standard_result = functions.approve_application_request(standard_id, "admin")

    assert foretagskonto_result["account_type"] == "foretagskonto"
    assert standard_result["account_type"] == "standard"

    with fresh_app_db.connect() as conn:
        users = conn.execute(
            functions.company_users_table.select().where(
                functions.company_users_table.c.email == "shared@example.com"
            )
        ).fetchall()
        assert len(users) == 2
        roles = {row.role for row in users}
        assert roles == {"foretagskonto", "standard"}


def test_foretagskonto_application_rejects_duplicate_orgnr(fresh_app_db):
    first_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Företagskonto Ett",
        email="foretag1@example.com",
        orgnr="5569668337",
        company_name="Bolag Ett",
        comment=None,
        invoice_address="Adress 1",
        invoice_contact="Kontakt 1",
        invoice_reference="Ref 1",
    )
    functions.approve_application_request(first_id, "admin")

    with pytest.raises(ValueError, match="Det finns redan ett företagskonto"):
        functions.create_application_request(
            account_type="foretagskonto",
            name="Företagskonto Två",
            email="foretag2@example.com",
            orgnr="5569668337",
            company_name="Bolag Två",
            comment=None,
            invoice_address="Adress 2",
            invoice_contact="Kontakt 2",
            invoice_reference="Ref 2",
        )


def test_missing_invoice_fields_for_foretagskonto_raises(fresh_app_db):
    with pytest.raises(ValueError):
        functions.create_application_request(
            account_type="foretagskonto",
            name="Test",
            email="missing@example.com",
            orgnr="5569668337",
            company_name="Bolaget",
            comment=None,
            invoice_address=None,
            invoice_contact="Kontakt",
            invoice_reference="Ref",
        )


@pytest.mark.usefixtures("fresh_app_db")
def test_standard_application_requires_personnummer():
    with pytest.raises(ValueError):
        functions.create_application_request(
            account_type="standard",
            name="Test",
            email="user@example.com",
            orgnr="",
            company_name="",
            comment=None,
            personnummer="",
        )


def test_standard_application_rejects_duplicate_personnummer(fresh_app_db):
    functions.create_application_request(
        account_type="standard",
        name="Första",
        email="first@example.com",
        orgnr="",
        company_name="",
        comment=None,
        personnummer="9001011234",
    )

    with pytest.raises(ValueError, match="Det finns redan ett standardkonto"):
        functions.create_application_request(
            account_type="standard",
            name="Andra",
            email="second@example.com",
            orgnr="",
            company_name="",
            comment=None,
            personnummer="9001011234",
        )


def test_list_companies_for_invoicing(fresh_app_db):
    foretagskonto_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Företagskonto 1",
        email="foretagskonto1@example.com",
        orgnr="5569668337",
        company_name="Bolag 1",
        comment=None,
        invoice_address="Adress 1",
        invoice_contact="Kontakt 1",
        invoice_reference="Ref 1",
    )
    user_id = functions.create_application_request(
        account_type="standard",
        name="Användare 1",
        email="user1@example.com",
        orgnr="",
        company_name="",
        comment=None,
        personnummer="9012311234",
    )

    functions.approve_application_request(foretagskonto_id, "admin")
    functions.approve_application_request(user_id, "admin")

    companies = functions.list_companies_for_invoicing()
    assert len(companies) == 1
    company = companies[0]
    assert company["name"] == "Bolag 1"
    assert company["orgnr"] == "5569668337"
    assert company["invoice_address"] == "Adress 1"
    assert company["invoice_contact"] == "Kontakt 1"
    assert company["invoice_reference"] == "Ref 1"
    assert company["foretagskonto_count"] == 1
    assert company["user_count"] == 1


def test_standard_application_without_orgnr_can_be_godkannas(fresh_app_db):
    application_id = functions.create_application_request(
        account_type="standard",
        name="Organisationslös Användare",
        email="utan-orgnr@example.com",
        orgnr="",
        company_name="",
        comment="",
        personnummer="8801011234",
    )

    with fresh_app_db.connect() as conn:
        stored = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert stored is not None
        assert stored.orgnr_normalized == ""

    result = functions.approve_application_request(application_id, "admin")
    assert result["company_id"] is None
    assert result["orgnr"] == ""
    assert result["company_created"] is False
    assert result["pending_supervisor_created"] is False
    assert result["supervisor_activation_required"] is False
    assert result["supervisor_email_hash"] is None
    assert result["user_activation_required"] is True
    assert result["user_personnummer_hash"] == functions.hash_value("8801011234")

    with fresh_app_db.connect() as conn:
        user = conn.execute(functions.company_users_table.select()).first()
        assert user is not None
        assert user.email == "utan-orgnr@example.com"
        assert user.company_id is None

        pending_user = conn.execute(functions.pending_users_table.select()).first()
        assert pending_user is not None
        assert pending_user.personnummer == functions.hash_value("8801011234")

        companies = conn.execute(functions.companies_table.select()).fetchall()
        assert companies == []

        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select()
        ).fetchall()
        assert pending_supervisor == []


def test_standard_application_rejects_orgnr(fresh_app_db):
    with pytest.raises(
        ValueError,
        match="Standardkonton kan inte kopplas till organisationsnummer i ansökan.",
    ):
        functions.create_application_request(
            account_type="standard",
            name="Orgnummer Standard",
            email="standard-orgnr@example.com",
            orgnr="556966-8337",
            company_name="",
            comment="",
            personnummer="8801011234",
        )

        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == "approved"
        assert application.reviewed_by == "admin"
