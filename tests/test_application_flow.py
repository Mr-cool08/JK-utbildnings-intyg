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
    assert foretagskonto_result["pending_supervisor_created"] is True
    assert foretagskonto_result["supervisor_activation_required"] is True
    assert user_result["supervisor_activation_required"] is False
    assert user_result["supervisor_email_hash"] is None

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


def test_approve_foretagskonto_with_existing_activated_supervisor(fresh_app_db):
    """Test that approving foretagskonto with existing activated supervisor doesn't create pending supervisor."""
    email = "activated-supervisor@example.com"
    email_hash = functions.hash_value(functions.normalize_email(email))

    # Create an activated supervisor first
    with fresh_app_db.connect() as conn:
        conn.execute(
            functions.supervisors_table.insert().values(
                email=email_hash,
                name='Activated Supervisor',
                password=functions.hash_password('SecurePass123'),
            )
        )

    # Create and approve application for same email
    application_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Activated Supervisor",
        email=email,
        orgnr="556016-0680",
        company_name="Activated Company AB",
        comment=None,
        invoice_address="Aktiverad Väg 1",
        invoice_contact="Kontakt",
        invoice_reference="Ref 456",
    )

    result = functions.approve_application_request(application_id, "admin")

    assert result["pending_supervisor_created"] is False
    assert result["supervisor_activation_required"] is False
    assert result["supervisor_email_hash"] == email_hash

    # Verify no new pending supervisor was created
    with fresh_app_db.connect() as conn:
        pending_supervisors = conn.execute(
            functions.pending_supervisors_table.select()
        ).fetchall()
        assert len(pending_supervisors) == 0


def test_approve_foretagskonto_with_existing_pending_supervisor(fresh_app_db):
    """Test that approving foretagskonto with existing pending supervisor updates the name."""
    email = "pending-supervisor@example.com"
    email_hash = functions.hash_value(functions.normalize_email(email))

    # Create a pending supervisor with old name
    with fresh_app_db.connect() as conn:
        conn.execute(
            functions.pending_supervisors_table.insert().values(
                email=email_hash,
                name='Old Name',
            )
        )

    # Approve application with new name
    application_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Updated Name",
        email=email,
        orgnr="556016-0680",
        company_name="Pending Company AB",
        comment=None,
        invoice_address="Pending Väg 1",
        invoice_contact="Kontakt",
        invoice_reference="Ref 789",
    )

    result = functions.approve_application_request(application_id, "admin")

    assert result["pending_supervisor_created"] is False
    assert result["supervisor_activation_required"] is True
    assert result["supervisor_email_hash"] == email_hash

    # Verify pending supervisor name was updated
    with fresh_app_db.connect() as conn:
        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select().where(
                functions.pending_supervisors_table.c.email == email_hash
            )
        ).first()
        assert pending_supervisor.name == "Updated Name"


def test_approve_foretagskonto_with_pending_supervisor_empty_name_no_update(fresh_app_db):
    """Test that empty name doesn't override existing pending supervisor name."""
    email = "pending-keep-name@example.com"
    email_hash = functions.hash_value(functions.normalize_email(email))

    # Create a pending supervisor with a name
    with fresh_app_db.connect() as conn:
        conn.execute(
            functions.pending_supervisors_table.insert().values(
                email=email_hash,
                name='Keep This Name',
            )
        )

    # Approve application with empty name
    application_id = functions.create_application_request(
        account_type="foretagskonto",
        name="   ",  # Empty after strip
        email=email,
        orgnr="556016-0680",
        company_name="Keep Name Company AB",
        comment=None,
        invoice_address="Keep Väg 1",
        invoice_contact="Kontakt",
        invoice_reference="Ref 999",
    )

    result = functions.approve_application_request(application_id, "admin")

    assert result["supervisor_activation_required"] is True

    # Verify pending supervisor name was NOT updated
    with fresh_app_db.connect() as conn:
        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select().where(
                functions.pending_supervisors_table.c.email == email_hash
            )
        ).first()
        assert pending_supervisor.name == "Keep This Name"


def test_approve_standard_account_no_supervisor_fields(fresh_app_db):
    """Test that standard accounts don't create supervisor-related data."""
    application_id = functions.create_application_request(
        account_type="standard",
        name="Standard User",
        email="standard-user@example.com",
        orgnr="556016-0680",
        company_name="",
        comment=None,
    )

    result = functions.approve_application_request(application_id, "admin")

    assert result["account_type"] == "standard"
    assert result["pending_supervisor_created"] is False
    assert result["supervisor_activation_required"] is False
    assert result["supervisor_email_hash"] is None

    # Verify no pending supervisor was created
    with fresh_app_db.connect() as conn:
        pending_supervisors = conn.execute(
            functions.pending_supervisors_table.select()
        ).fetchall()
        assert len(pending_supervisors) == 0


def test_approve_multiple_standard_accounts_no_supervisor_pollution(fresh_app_db):
    """Test that multiple standard accounts don't create supervisors."""
    app1_id = functions.create_application_request(
        account_type="standard",
        name="User One",
        email="user1@example.com",
        orgnr="556016-0680",
        company_name="",
        comment=None,
    )

    app2_id = functions.create_application_request(
        account_type="standard",
        name="User Two",
        email="user2@example.com",
        orgnr="556016-0680",
        company_name="",
        comment=None,
    )

    result1 = functions.approve_application_request(app1_id, "admin")
    result2 = functions.approve_application_request(app2_id, "admin")

    assert result1["supervisor_email_hash"] is None
    assert result2["supervisor_email_hash"] is None

    # Verify no pending supervisors were created
    with fresh_app_db.connect() as conn:
        pending_supervisors = conn.execute(
            functions.pending_supervisors_table.select()
        ).fetchall()
        assert len(pending_supervisors) == 0


def test_approve_foretagskonto_creates_company_user_and_pending_supervisor(fresh_app_db):
    """Test the complete flow: company + user + pending supervisor creation."""
    email = "complete-flow@example.com"
    application_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Complete Flow User",
        email=email,
        orgnr="556016-0680",
        company_name="Complete Flow AB",
        comment="Testing complete flow",
        invoice_address="Flow Street 1\n12345 FlowCity",
        invoice_contact="Flow Contact",
        invoice_reference="Flow-REF-001",
    )

    result = functions.approve_application_request(application_id, "admin")

    # Verify all three entities were created
    assert result["company_created"] is True
    assert result["pending_supervisor_created"] is True
    assert result["supervisor_activation_required"] is True

    email_hash = functions.hash_value(functions.normalize_email(email))

    with fresh_app_db.connect() as conn:
        # Verify company
        company = conn.execute(
            functions.companies_table.select().where(
                functions.companies_table.c.id == result["company_id"]
            )
        ).first()
        assert company is not None
        assert company.name == "Complete Flow AB"
        assert company.orgnr == "5560160680"

        # Verify user
        user = conn.execute(
            functions.company_users_table.select().where(
                functions.company_users_table.c.id == result["user_id"]
            )
        ).first()
        assert user is not None
        assert user.email == email
        assert user.company_id == result["company_id"]
        assert user.role == "foretagskonto"

        # Verify pending supervisor
        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select().where(
                functions.pending_supervisors_table.c.email == email_hash
            )
        ).first()
        assert pending_supervisor is not None
        assert pending_supervisor.name == "Complete Flow User"


def test_approve_foretagskonto_email_normalization(fresh_app_db):
    """Test that email is normalized for supervisor hash."""
    # Create application with uppercase email
    email = "UPPERCASE@EXAMPLE.COM"
    application_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Uppercase Test",
        email=email,
        orgnr="556016-0680",
        company_name="Uppercase Company",
        comment=None,
        invoice_address="Upper Street",
        invoice_contact="Contact",
        invoice_reference="REF",
    )

    result = functions.approve_application_request(application_id, "admin")

    # Email should be normalized to lowercase
    normalized_email = functions.normalize_email(email)
    expected_hash = functions.hash_value(normalized_email)

    assert result["supervisor_email_hash"] == expected_hash
    assert result["email"] == normalized_email.lower()

    with fresh_app_db.connect() as conn:
        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select().where(
                functions.pending_supervisors_table.c.email == expected_hash
            )
        ).first()
        assert pending_supervisor is not None


def test_approve_foretagskonto_supervisor_hash_consistency(fresh_app_db):
    """Test that supervisor hash is consistent with user email hash."""
    email = "consistency-test@example.com"
    application_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Consistency Test",
        email=email,
        orgnr="556016-0680",
        company_name="Consistency Company",
        comment=None,
        invoice_address="Consistency Street",
        invoice_contact="Contact",
        invoice_reference="REF",
    )

    result = functions.approve_application_request(application_id, "admin")

    normalized_email = functions.normalize_email(email)
    expected_hash = functions.hash_value(normalized_email)

    assert result["supervisor_email_hash"] == expected_hash

    with fresh_app_db.connect() as conn:
        # Verify user email matches normalized email
        user = conn.execute(
            functions.company_users_table.select().where(
                functions.company_users_table.c.id == result["user_id"]
            )
        ).first()
        assert user.email == normalized_email

        # Verify pending supervisor uses the same hash
        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select().where(
                functions.pending_supervisors_table.c.email == expected_hash
            )
        ).first()
        assert pending_supervisor is not None


def test_approve_foretagskonto_return_value_completeness(fresh_app_db):
    """Test that all expected fields are present in the return value."""
    application_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Return Value Test",
        email="return-test@example.com",
        orgnr="556016-0680",
        company_name="Return Company",
        comment=None,
        invoice_address="Return Street",
        invoice_contact="Return Contact",
        invoice_reference="Return Ref",
    )

    result = functions.approve_application_request(application_id, "admin")

    # Verify all required fields are present
    required_fields = [
        "company_id",
        "user_id",
        "orgnr",
        "email",
        "account_type",
        "name",
        "company_name",
        "company_created",
        "invoice_address",
        "invoice_contact",
        "invoice_reference",
        "pending_supervisor_created",
        "supervisor_activation_required",
        "supervisor_email_hash",
    ]

    for field in required_fields:
        assert field in result, f"Missing field: {field}"

    # Verify field types
    assert isinstance(result["company_id"], int)
    assert isinstance(result["user_id"], int)
    assert isinstance(result["orgnr"], str)
    assert isinstance(result["email"], str)
    assert isinstance(result["company_created"], bool)
    assert isinstance(result["pending_supervisor_created"], bool)
    assert isinstance(result["supervisor_activation_required"], bool)
    assert isinstance(result["supervisor_email_hash"], str)


def test_approve_standard_account_return_value_completeness(fresh_app_db):
    """Test that standard account approval has correct return fields."""
    application_id = functions.create_application_request(
        account_type="standard",
        name="Standard Return Test",
        email="standard-return@example.com",
        orgnr="556016-0680",
        company_name="",
        comment=None,
    )

    result = functions.approve_application_request(application_id, "admin")

    # Verify supervisor fields for standard account
    assert result["pending_supervisor_created"] is False
    assert result["supervisor_activation_required"] is False
    assert result["supervisor_email_hash"] is None


def test_approve_multiple_foretagskonto_same_company_multiple_pending_supervisors(fresh_app_db):
    """Test that multiple foretagskonto accounts for same company create multiple pending supervisors."""
    orgnr = "556016-0680"

    # Create first foretagskonto
    app1_id = functions.create_application_request(
        account_type="foretagskonto",
        name="First Supervisor",
        email="first-supervisor@example.com",
        orgnr=orgnr,
        company_name="Shared Company",
        comment=None,
        invoice_address="Shared Street",
        invoice_contact="Contact",
        invoice_reference="Ref",
    )

    # Create second foretagskonto with different email
    app2_id = functions.create_application_request(
        account_type="foretagskonto",
        name="Second Supervisor",
        email="second-supervisor@example.com",
        orgnr=orgnr,
        company_name="Shared Company",
        comment=None,
        invoice_address="Shared Street",
        invoice_contact="Contact",
        invoice_reference="Ref",
    )

    result1 = functions.approve_application_request(app1_id, "admin")
    result2 = functions.approve_application_request(app2_id, "admin")

    # Both should create pending supervisors
    assert result1["pending_supervisor_created"] is True
    assert result2["pending_supervisor_created"] is True

    # Company should not be created twice
    assert result1["company_created"] is True
    assert result2["company_created"] is False
    assert result1["company_id"] == result2["company_id"]

    # Verify two distinct pending supervisors
    with fresh_app_db.connect() as conn:
        pending_supervisors = conn.execute(
            functions.pending_supervisors_table.select()
        ).fetchall()
        assert len(pending_supervisors) == 2

        emails = {ps.email for ps in pending_supervisors}
        assert len(emails) == 2  # Two different email hashes