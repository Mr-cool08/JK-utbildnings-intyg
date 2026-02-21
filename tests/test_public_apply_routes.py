# Copyright (c) Liam Suorsa and Mika Suorsa
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
        assert '/ansok/standardkonto' in body
        assert '/ansok/foretagskonto' in body


def test_user_application_submission(empty_db):
    with _client() as client:
        with client.session_transaction() as session:
            session['csrf_token'] = 'test-token'
        response = client.post(
            '/ansok/standardkonto',
            data={
                'csrf_token': 'test-token',
                'name': 'Anna Användare',
                'email': 'anna@example.com',
                'personnummer': '9001011234',
                'comment': 'Ser fram emot att använda portalen.',
                'terms_confirmed': '1',
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert 'Tack! Vi hör av oss så snart vi granskat ansökan.' in response.data.decode('utf-8')

    with empty_db.connect() as conn:
        stored = conn.execute(functions.application_requests_table.select()).fetchall()
        assert len(stored) == 1
        row = stored[0]
        assert row.account_type == 'standard'
        assert row.invoice_address is None
        assert row.orgnr_normalized == ''
        assert row.personnummer_hash == functions.hash_value('9001011234')


def test_foretagskonto_application_submission(empty_db):
    with _client() as client:
        with client.session_transaction() as session:
            session['csrf_token'] = 'test-token'
        response = client.post(
            '/ansok/foretagskonto',
            data={
                'csrf_token': 'test-token',
                'name': 'Helena Företagskonto',
                'email': 'helena@example.com',
                'company_name': 'Handledarbolaget AB',
                'invoice_address': 'Fakturagatan 1',
                'invoice_contact': 'Helena Företagskonto',
                'invoice_reference': 'Märkning 123',
                'orgnr': '5569668337',
                'comment': 'Vi vill administrera våra kursdeltagare.',
                'terms_confirmed': '1',
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
        assert row.account_type == 'foretagskonto'
        assert row.invoice_address == 'Fakturagatan 1'
        assert row.invoice_contact == 'Helena Företagskonto'
        assert row.invoice_reference == 'Märkning 123'


def test_application_requires_terms_confirmation(empty_db):
    with _client() as client:
        with client.session_transaction() as session:
            session['csrf_token'] = 'test-token'
        response = client.post(
            '/ansok/standardkonto',
            data={
                'csrf_token': 'test-token',
                'name': 'Anna Användare',
                'email': 'anna@example.com',
                'orgnr': '556966-8337',
                'comment': 'Ser fram emot att använda portalen.',
            },
            follow_redirects=True,
        )
        body = response.data.decode('utf-8')
        assert response.status_code == 200
        assert 'Du måste intyga att du har läst och förstått villkoren och den juridiska informationen innan du skickar ansökan.' in body

    with empty_db.connect() as conn:
        stored = conn.execute(functions.application_requests_table.select()).fetchall()
        assert stored == []
