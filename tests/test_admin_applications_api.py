# Copyright (c) Liam Suorsa
import app
import functions


def _admin_session(client):
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True
        sess['admin_username'] = 'admin'
        sess['csrf_token'] = 'test-csrf'


def test_admin_list_applications(empty_db):
    client = app.app.test_client()
    _admin_session(client)

    first = functions.create_application_request(
        'foretagskonto',
        'Test',
        'api@example.com',
        '5569668337',
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
        """
        Record the provided email details into the outer `sent` dictionary for test assertions.
        
        Parameters:
            email (str): Recipient email address to store under key 'email'.
            account_type (str): Account type to store under key 'type'.
            company_name (str): Company name to store under key 'company'.
        """
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
        '5569668337',
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
    assert payload['data']['supervisor_email'] == 'foretagskonto@example.com'
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


def test_admin_approve_standard_application_creates_activation_link(
    empty_db, monkeypatch
):
    client = app.app.test_client()
    _admin_session(client)

    sent: dict[str, str] = {}
    creation_sent: dict[str, str] = {}

    def fake_send(email, account_type, company_name):
        sent['email'] = email
        sent['type'] = account_type
        sent['company'] = company_name

    monkeypatch.setattr(
        app.email_service, 'send_application_approval_email', fake_send
    )
    monkeypatch.setattr(
        app.email_service,
        'send_creation_email',
        lambda email, link: creation_sent.update({'email': email, 'link': link}),
    )

    application_id = functions.create_application_request(
        'standard',
        'Standard Användare',
        'standard@example.com',
        '',
        '',
        'Hej',
        personnummer='9001011234',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/godkann',
        json={'csrf_token': 'test-csrf'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    assert payload['data']['account_type'] == 'standard'
    assert sent['email'] == 'standard@example.com'
    assert creation_sent['email'] == 'standard@example.com'
    assert 'creation_link' in payload
    assert creation_sent['link'] == payload['creation_link']

    with empty_db.connect() as conn:
        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == 'approved'
        pending_user = conn.execute(
            functions.pending_users_table.select()
        ).first()
        assert pending_user is not None
        assert pending_user.email == functions.hash_value(
            functions.normalize_email('standard@example.com')
        )
        pending_supervisor = conn.execute(
            functions.pending_supervisors_table.select()
        ).fetchall()
        assert pending_supervisor == []


def test_admin_reject_application_api(empty_db, monkeypatch):
    """
    Verifies that the admin reject-application API records a rejection, sends a rejection email, and persists the decision reason.
    
    Sends a POST to the admin rejection endpoint for a created application, asserts a 200 response with a success payload containing the supplied reason, checks that a rejection email was sent to the applicant, and verifies the application row in the database has status 'rejected' and the decision_reason set to the provided reason.
    """
    client = app.app.test_client()
    _admin_session(client)

    sent = {}

    def fake_send(email, company_name, reason):
        sent['email'] = email
        sent['company'] = company_name
        sent['reason'] = reason

    monkeypatch.setattr(app.email_service, 'send_application_rejection_email', fake_send)

    application_id = functions.create_application_request(
        'foretagskonto',
        'Avslag Test',
        'reject@example.com',
        '5569668337',
        'Avslag AB',
        None,
        'Avslagsgatan 5',
        'Avslag Kontakt',
        'Avslag Ref',
    )

    response = client.post(
        f'/admin/api/ansokningar/{application_id}/avslag',
        json={'csrf_token': 'test-csrf', 'reason': 'Ofullständig ansökan'},
        headers={'X-CSRF-Token': 'test-csrf'},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['status'] == 'success'
    assert sent['email'] == 'reject@example.com'
    assert sent['reason'] == 'Ofullständig ansökan'
    assert payload['data']['decision_reason'] == 'Ofullständig ansökan'

    with empty_db.connect() as conn:
        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == 'rejected'
        assert application.decision_reason == 'Ofullständig ansökan'
