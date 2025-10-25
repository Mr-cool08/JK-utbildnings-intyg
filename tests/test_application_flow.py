import pytest

import functions


@pytest.fixture
def fresh_app_db(empty_db):
    # Reset any cached data for deterministic tests.
    return empty_db


def test_application_approval_creates_company_and_user(fresh_app_db):
    application_id = functions.create_application_request(
        account_type="handledare",
        name="Test Handledare",
        email="applicant@example.com",
        orgnr="556016-0680",
        company_name="Testbolag AB",
        comment="Vill komma igång",
    )

    result = functions.approve_application_request(application_id, "admin")

    assert result["company_created"] is True
    assert result["account_type"] == "handledare"
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
        assert user.role == "handledare"

        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == "approved"
        assert application.reviewed_by == "admin"


def test_application_rejection_stores_reason(fresh_app_db):
    application_id = functions.create_application_request(
        account_type="handledare",
        name="Handledare Test",
        email="handledare@example.com",
        orgnr="5560160680",
        company_name="Handledarbolaget",
        comment="Behöver åtkomst",
    )

    result = functions.reject_application_request(
        application_id, "admin", "Behörigheterna kan inte styrkas."
    )

    assert result["reason"] == "Behörigheterna kan inte styrkas."
    assert result["account_type"] == "handledare"
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
    handledare_id = functions.create_application_request(
        account_type="handledare",
        name="Handledaren",
        email="handledare@example.com",
        orgnr="5560160680",
        company_name="Bolaget AB",
        comment=None,
    )
    user_id = functions.create_application_request(
        account_type="user",
        name="Första Användaren",
        email="first@example.com",
        orgnr="5560160680",
        company_name="",
        comment=None,
    )

    handledare_result = functions.approve_application_request(
        handledare_id, "admin"
    )
    user_result = functions.approve_application_request(user_id, "admin")

    assert handledare_result["company_created"] is True
    assert user_result["company_created"] is False
    assert handledare_result["company_id"] == user_result["company_id"]
    assert user_result["company_name"] == "Bolaget AB"

    with fresh_app_db.connect() as conn:
        companies = conn.execute(functions.companies_table.select()).fetchall()
        assert len(companies) == 1

        users = conn.execute(functions.company_users_table.select()).fetchall()
        emails = {row.email for row in users}
        assert emails == {"first@example.com", "handledare@example.com"}
