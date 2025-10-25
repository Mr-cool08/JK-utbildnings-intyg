import app
import functions


def _client():
    client = app.app.test_client()
    return client


def test_apply_landing_has_links(empty_db):
    with _client() as client:
        response = client.get('/ansok')
        assert response.status_code == 200
        body = response.data.decode('utf-8')
        assert '/ansok/anvandare' in body
        assert '/ansok/handledare' in body


def test_user_application_submission(empty_db):
    with _client() as client:
        with client.session_transaction() as session:
            session['csrf_token'] = 'test-token'
        response = client.post(
            '/ansok/anvandare',
            data={
                'csrf_token': 'test-token',
                'name': 'Anna Användare',
                'email': 'anna@example.com',
                'orgnr': '556016-0680',
                'comment': 'Ser fram emot att använda portalen.',
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert 'Tack! Vi hör av oss så snart vi granskat ansökan.' in response.data.decode('utf-8')

    with empty_db.connect() as conn:
        stored = conn.execute(functions.application_requests_table.select()).fetchall()
        assert len(stored) == 1
        row = stored[0]
        assert row.account_type == 'user'
        assert row.invoice_address is None


def test_handledare_application_submission(empty_db):
    with _client() as client:
        with client.session_transaction() as session:
            session['csrf_token'] = 'test-token'
        response = client.post(
            '/ansok/handledare',
            data={
                'csrf_token': 'test-token',
                'name': 'Helena Handledare',
                'email': 'helena@example.com',
                'company_name': 'Handledarbolaget AB',
                'invoice_address': 'Fakturagatan 1',
                'invoice_contact': 'Helena Handledare',
                'invoice_reference': 'Märkning 123',
                'orgnr': '5560160680',
                'comment': 'Vi vill administrera våra kursdeltagare.',
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        text = response.data.decode('utf-8')
        assert 'Tack! Vi hör av oss så snart vi granskat ansökan.' in text

    with empty_db.connect() as conn:
        stored = conn.execute(functions.application_requests_table.select()).fetchall()
        assert len(stored) == 1
        row = stored[0]
        assert row.account_type == 'handledare'
        assert row.invoice_address == 'Fakturagatan 1'
        assert row.invoice_contact == 'Helena Handledare'
        assert row.invoice_reference == 'Märkning 123'
