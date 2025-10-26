import app
import functions


def _admin_session(client):
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True
        sess['admin_username'] = 'admin'
        sess['csrf_token'] = 'test-csrf'  # noqa: S105


def test_admin_list_applications(_empty_db):
    client = app.app.test_client()
    _admin_session(client)

    first = functions.create_application_request(
        'foretagskonto',
        'Test',
        'api@example.com',
        '5560160680',
        'API Bolaget',
        'Hej',
        'Adress 1',
        'Kontakt 1',
        'Ref 1',
    )

    response = client.get('/admin/api/ansokningar')
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    assert any(entry['id'] == first for entry in payload['data'])


def test_admin_approve_application_api(empty_db, monkeypatch):
    client = app.app.test_client()
    _admin_session(client)

    sent = {}
    creation_sent = {}

    def fake_send(email, account_type, company_name):
        sent['email'] = email
        sent['type'] = account_type
        sent['company'] = company_name

    monkeypatch.setattr(app.email_service, 'send_application_approval_email', fake_send)
    monkeypatch.setattr(
        app.email_service,
        'send_creation_email',
        lambda email, link: creation_sent.update({'email': email, 'link': link}),
    )

    application_id = functions.create_application_request(
        'foretagskonto',
        'Företagskonto',
        'foretagskonto@example.com',
        '5560160680',
        'Handledarbolaget',
        'Test',
        'Fakturavägen 1',
        'Kontaktperson',
        'Ref-ABC',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    assert payload['data']['account_type'] == 'foretagskonto'
    assert sent['email'] == 'foretagskonto@example.com'
    assert creation_sent['email'] == 'foretagskonto@example.com'
    assert 'creation_link' in payload
    assert creation_sent['link'] == payload['creation_link']

    with empty_db.connect() as conn:
        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == 'approved'
        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select()
        ).first()
        assert pending_supervisor is not None


def test_admin_reject_application_api(empty_db, monkeypatch):
    client = app.app.test_client()
    _admin_session(client)

    sent = {}

    def fake_send(email, company_name, reason):
        sent['email'] = email
        sent['reason'] = reason
        sent['company'] = company_name

    monkeypatch.setattr(app.email_service, 'send_application_rejection_email', fake_send)

    application_id = functions.create_application_request(
        'foretagskonto',
        'Avslag Test',
        'reject@example.com',
        '5560160680',
        'Avslag AB',
        None,
        'Avslagsgatan 5',
        'Avslag Kontakt',
        'Avslag Ref',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/avslag',
        json={'reason': 'Ofullständiga uppgifter', 'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    assert payload['data']['reason'] == 'Ofullständiga uppgifter'
    assert sent['email'] == 'reject@example.com'

    with empty_db.connect() as conn:
        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == 'rejected'
        assert application.decision_reason == 'Ofullständiga uppgifter'


def test_admin_approve_application_email_failure_shows_warning(_empty_db, monkeypatch):
    """Test that approval email failure results in a warning but doesn't fail the request."""
    client = app.app.test_client()
    _admin_session(client)

    def fake_send_approval_email(_email, _account_type, _company_name):
        raise RuntimeError("Email service unavailable")

    creation_sent = {}
    monkeypatch.setattr(app.email_service, 'send_application_approval_email', fake_send_approval_email)
    monkeypatch.setattr(
        app.email_service,
        'send_creation_email',
        lambda email, link: creation_sent.update({'email': email, 'link': link}),
    )

    application_id = functions.create_application_request(
        'foretagskonto',
        'Test Failure',
        'failure@example.com',
        '5560160680',
        'Failure AB',
        None,
        'Failure Street',
        'Kontakt',
        'Ref',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    assert 'email_warning' in payload
    assert 'bekräftelsemejlet kunde inte skickas' in payload['email_warning']

    # Application should still be approved despite email failure
    with _empty_db.connect() as conn:
        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == 'approved'


def test_admin_approve_application_creation_email_failure_shows_warning(_empty_db, monkeypatch):
    """Test that creation email failure results in a warning."""
    client = app.app.test_client()
    _admin_session(client)

    sent = {}

    def fake_send_approval(_email, _account_type, _company_name):
        sent['approval'] = _email

    def fake_send_creation(_email, _link):
        raise RuntimeError("Creation email failed")

    monkeypatch.setattr(app.email_service, 'send_application_approval_email', fake_send_approval)
    monkeypatch.setattr(app.email_service, 'send_creation_email', fake_send_creation)

    application_id = functions.create_application_request(
        'foretagskonto',
        'Creation Failure',
        'creation-fail@example.com',
        '5560160680',
        'Creation Fail AB',
        None,
        'Creation Street',
        'Kontakt',
        'Ref',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    assert 'email_warning' in payload
    assert 'Aktiveringslänken kunde inte skickas' in payload['email_warning']
    assert sent['approval'] == 'creation-fail@example.com'


def test_admin_approve_application_both_email_failures_shows_combined_warning(_empty_db, monkeypatch):
    """Test that both email failures result in combined warning message."""
    client = app.app.test_client()
    _admin_session(client)

    def fake_send_approval(_email, _account_type, _company_name):
        raise RuntimeError("Approval email failed")

    def fake_send_creation(_email, _link):
        raise RuntimeError("Creation email failed")

    monkeypatch.setattr(app.email_service, 'send_application_approval_email', fake_send_approval)
    monkeypatch.setattr(app.email_service, 'send_creation_email', fake_send_creation)

    application_id = functions.create_application_request(
        'foretagskonto',
        'Both Failure',
        'both-fail@example.com',
        '5560160680',
        'Both Fail AB',
        None,
        'Both Street',
        'Kontakt',
        'Ref',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    assert 'email_warning' in payload
    # Both warnings should be combined
    assert 'bekräftelsemejlet kunde inte skickas' in payload['email_warning']
    assert 'Aktiveringslänken kunde inte skickas' in payload['email_warning']


def test_admin_approve_standard_account_no_creation_link(_empty_db, monkeypatch):
    """Test that standard accounts don't get a creation link."""
    client = app.app.test_client()
    _admin_session(client)

    sent = {}
    creation_sent = {}

    def fake_send(email, _account_type, _company_name):
        sent['email'] = email

    monkeypatch.setattr(app.email_service, 'send_application_approval_email', fake_send)
    monkeypatch.setattr(
        app.email_service,
        'send_creation_email',
        lambda email, link: creation_sent.update({'email': email, 'link': link}),
    )

    application_id = functions.create_application_request(
        'standard',
        'Standard User',
        'standard@example.com',
        '5560160680',
        'Standard Company',
        None,
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    assert 'creation_link' not in payload
    assert len(creation_sent) == 0  # No creation email sent for standard accounts
    assert sent['email'] == 'standard@example.com'


def test_admin_approve_foretagskonto_with_existing_supervisor(empty_db, monkeypatch):
    """Test approving foretagskonto when supervisor already exists."""
    client = app.app.test_client()
    _admin_session(client)

    sent = {}
    creation_sent = {}

    monkeypatch.setattr(
        app.email_service,
        'send_application_approval_email',
        lambda email, _account_type, _company_name: sent.update({'email': email}),
    )
    monkeypatch.setattr(
        app.email_service,
        'send_creation_email',
        lambda email, link: creation_sent.update({'email': email, 'link': link}),
    )

    # First, create an activated supervisor
    email = 'existing-supervisor@example.com'
    email_hash = functions.hash_value(functions.normalize_email(email))

    with empty_db.connect() as conn:
        conn.execute(
            functions.supervisors_table.insert().values(
                email=email_hash,
                name='Existing Supervisor',
                password=functions.hash_password('Password123'),
            )
        )

    # Now approve an application for the same email
    application_id = functions.create_application_request(
        'foretagskonto',
        'Existing Supervisor',
        email,
        '5560160680',
        'Existing Company',
        None,
        'Address',
        'Contact',
        'Ref',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    # No creation link should be sent for existing supervisor
    assert 'creation_link' not in payload
    assert len(creation_sent) == 0
    assert sent['email'] == email


def test_admin_approve_foretagskonto_updates_pending_supervisor_name(empty_db, monkeypatch):
    """Test that approving updates pending supervisor name if different."""
    client = app.app.test_client()
    _admin_session(client)

    sent = {}
    creation_sent = {}

    monkeypatch.setattr(
        app.email_service,
        'send_application_approval_email',
        lambda email, _account_type, _company_name: sent.update({'email': email}),
    )
    monkeypatch.setattr(
        app.email_service,
        'send_creation_email',
        lambda email, link: creation_sent.update({'email': email, 'link': link}),
    )

    email = 'update-name@example.com'
    email_hash = functions.hash_value(functions.normalize_email(email))

    # Create a pending supervisor with old name
    with empty_db.connect() as conn:
        conn.execute(
            functions.pending_supervisors_table.insert().values(
                email=email_hash,
                name='Old Name',
            )
        )

    # Approve application with new name
    application_id = functions.create_application_request(
        'foretagskonto',
        'New Updated Name',
        email,
        '5560160680',
        'Update Company',
        None,
        'Address',
        'Contact',
        'Ref',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    assert 'creation_link' in payload
    assert creation_sent['email'] == email

    # Verify name was updated
    with empty_db.connect() as conn:
        pending = conn.execute(
            functions.pending_supervisors_table.select().where(
                functions.pending_supervisors_table.c.email == email_hash
            )
        ).first()
        assert pending.name == 'New Updated Name'


def test_admin_approve_foretagskonto_does_not_update_empty_name(empty_db, monkeypatch):
    """Test that empty name in application doesn't override existing pending supervisor name."""
    client = app.app.test_client()
    _admin_session(client)

    monkeypatch.setattr(
        app.email_service,
        'send_application_approval_email',
        lambda _email, _account_type, _company_name: None,
    )
    monkeypatch.setattr(
        app.email_service,
        'send_creation_email',
        lambda _email, _link: None,
    )

    email = 'keep-name@example.com'
    email_hash = functions.hash_value(functions.normalize_email(email))

    # Create a pending supervisor with a name
    with empty_db.connect() as conn:
        conn.execute(
            functions.pending_supervisors_table.insert().values(
                email=email_hash,
                name='Original Name',
            )
        )

    # Approve application with empty name (just whitespace)
    application_id = functions.create_application_request(
        'foretagskonto',
        '   ',  # Empty name after strip
        email,
        '5560160680',
        'Keep Company',
        None,
        'Address',
        'Contact',
        'Ref',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200

    # Verify name was NOT updated
    with empty_db.connect() as conn:
        pending = conn.execute(
            functions.pending_supervisors_table.select().where(
                functions.pending_supervisors_table.c.email == email_hash
            )
        ).first()
        assert pending.name == 'Original Name'


def test_admin_approve_foretagskonto_creation_link_format(_empty_db, monkeypatch):
    """Test that creation link has the correct format."""
    client = app.app.test_client()
    _admin_session(client)

    creation_sent = {}

    monkeypatch.setattr(
        app.email_service,
        'send_application_approval_email',
        lambda _email, _account_type, _company_name: None,
    )
    monkeypatch.setattr(
        app.email_service,
        'send_creation_email',
        lambda email, link: creation_sent.update({'email': email, 'link': link}),
    )

    email = 'link-test@example.com'
    application_id = functions.create_application_request(
        'foretagskonto',
        'Link Test',
        email,
        '5560160680',
        'Link Company',
        None,
        'Address',
        'Contact',
        'Ref',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()

    creation_link = payload['creation_link']
    email_hash = functions.hash_value(functions.normalize_email(email))

    # Verify link contains the email hash
    assert email_hash in creation_link
    assert '/foretagskonto/skapa/' in creation_link
    assert creation_sent['link'] == creation_link


def test_admin_approve_application_idempotent_pending_supervisor(empty_db, monkeypatch):
    """Test that approving multiple foretagskonto applications for same email is handled correctly."""
    client = app.app.test_client()
    _admin_session(client)

    monkeypatch.setattr(
        app.email_service,
        'send_application_approval_email',
        lambda _email, _account_type, _company_name: None,
    )
    monkeypatch.setattr(
        app.email_service,
        'send_creation_email',
        lambda _email, _link: None,
    )

    email = 'same-email@example.com'

    # Create and approve first application
    app1_id = functions.create_application_request(
        'foretagskonto',
        'First Application',
        email,
        '5560160680',
        'Company One',
        None,
        'Address 1',
        'Contact 1',
        'Ref 1',
    )

    response1 = client.post(
        f'/admin/api/ansokningar/{app1_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response1.status_code == 200
    payload1 = response1.get_json()
    assert payload1['data']['pending_supervisor_created'] is True

    # Create and approve second application for same email
    app2_id = functions.create_application_request(
        'foretagskonto',
        'Second Application',
        email,
        '5560160681',  # Different orgnr
        'Company Two',
        None,
        'Address 2',
        'Contact 2',
        'Ref 2',
    )

    # This should fail because user email already exists
    response2 = client.post(
        f'/admin/api/ansokningar/{app2_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    # Should get an error about duplicate email
    assert response2.status_code == 500

    # Verify only one pending supervisor exists
    with empty_db.connect() as conn:
        pending_supervisors = conn.execute(
            functions.pending_supervisors_table.select()
        ).fetchall()
        assert len(pending_supervisors) == 1