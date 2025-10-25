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

    def fake_send(email, account_type, company_name):
        sent['email'] = email
        sent['type'] = account_type
        sent['company'] = company_name

    monkeypatch.setattr(app.email_service, 'send_application_approval_email', fake_send)

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

    with empty_db.connect() as conn:
        application = conn.execute(
            functions.application_requests_table.select().where(
                functions.application_requests_table.c.id == application_id
            )
        ).first()
        assert application.status == 'approved'


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
