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
        orgnr="556016-0680",
        company_name="Testbolag AB",
        comment="Vill komma igång",
        invoice_address="Testvägen 1\n123 45 Teststad",
        invoice_contact="Anna Andersson",
        invoice_reference="Ref 123",
    )

    result = functions.approve_application_request(application_id, "admin")

    assert result["company_created"] is True
    assert result["account_type"] == "foretagskonto"
    assert result["orgnr"] == "5560160680"
    assert result["company_name"] == "Testbolag AB"

    with fresh_app_db.connect() as conn:
        company = conn.execute(functions.companies_table.select()).first()
        assert company is not None
        assert company.name == "Testbolag AB"

        user = conn.execute(functions.company_users_table.select()).first()
        assert user is not None
        assert user.email == "applicant@example.com"
        assert user.company_id == company.id
        assert user.role == "foretagskonto"

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
        orgnr="5560160680",
        company_name="Handledarbolaget",
        comment="Behöver åtkomst",
        invoice_address="Bolagsgatan 2",
        invoice_contact="Björn", 
        invoice_reference="Order 77",
    )

    result = functions.reject_application_request(
        application_id, "admin", "Behörigheterna kan inte styrkas."
    )

    assert result["reason"] == "Behörigheterna kan inte styrkas."
    assert result["account_type"] == "foretagskonto"
    assert result["company_name"] == "Handledarbolaget"

    with fresh_app_db.connect() as conn:
        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == "rejected"
        assert application.decision_reason == "Behörigheterna kan inte styrkas."
        assert application.reviewed_by == "admin"


def test_approval_reuses_existing_company(fresh_app_db):
    foretagskonto_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Företagskonton",
        email="foretagskonto@example.com",
        orgnr="5560160680",
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
        orgnr="5560160680",
        company_name="",
        comment=None,
        invoice_address=None,
        invoice_contact=None,
        invoice_reference=None,
    )

    foretagskonto_result = functions.approve_application_request(
        foretagskonto_id, "admin"
    )
    user_result = functions.approve_application_request(user_id, "admin")

    assert foretagskonto_result["company_created"] is True
    assert user_result["company_created"] is False
    assert foretagskonto_result["company_id"] == user_result["company_id"]
    assert user_result["company_name"] == "Bolaget AB"

    with fresh_app_db.connect() as conn:
        companies = conn.execute(functions.companies_table.select()).fetchall()
        assert len(companies) == 1

        users = conn.execute(functions.company_users_table.select()).fetchall()
        emails = {row.email for row in users}
        assert emails == {"first@example.com", "foretagskonto@example.com"}


def test_missing_invoice_fields_for_foretagskonto_raises(fresh_app_db):
    with pytest.raises(ValueError):
        functions.create_application_request(
            account_type="foretagskonto",
            name="Test",
            email="missing@example.com",
            orgnr="5560160680",
            company_name="Bolaget",
            comment=None,
            invoice_address=None,
            invoice_contact="Kontakt",
            invoice_reference="Ref",
        )


def test_list_companies_for_invoicing(fresh_app_db):
    foretagskonto_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Företagskonto 1",
        email="foretagskonto1@example.com",
        orgnr="5560160680",
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
        orgnr="5560160680",
        company_name="",
        comment=None,
    )

    functions.approve_application_request(foretagskonto_id, "admin")
    functions.approve_application_request(user_id, "admin")

    companies = functions.list_companies_for_invoicing()
    assert len(companies) == 1
    company = companies[0]
    assert company["name"] == "Bolag 1"
    assert company["orgnr"] == "5560160680"
    assert company["invoice_address"] == "Adress 1"
    assert company["invoice_contact"] == "Kontakt 1"
    assert company["invoice_reference"] == "Ref 1"
    assert company["foretagskonto_count"] == 1
    assert company["user_count"] == 2


def test_standard_application_without_orgnr_can_be_skapat_men_inte_godkannas(fresh_app_db):
    application_id = functions.create_application_request(
        account_type="standard",
        name="Organisationslös Användare",
        email="utan-orgnr@example.com",
        orgnr="",
        company_name="",
        comment="",
    )

    with fresh_app_db.connect() as conn:
        stored = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert stored is not None
        assert stored.orgnr_normalized == ""

    with pytest.raises(ValueError) as exc:
        functions.approve_application_request(application_id, "admin")
    assert "saknar organisationsnummer" in str(exc.value)
