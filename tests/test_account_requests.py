import pytest

import app
import functions

@pytest.fixture
def client(empty_db):
    with app.app.test_client() as client:
        yield client

def test_apply_creates_pending_account(client):
    response = client.post(
        '/ansok',
        data={
            'username': 'Test Person',
            'email': 'test@example.com',
            'account_type': 'handledare',
            'org_number': '556677-8899',
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    with functions.get_engine().connect() as conn:
        rows = conn.execute(functions.pending_accounts_table.select()).fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row.username == 'Test Person'
    assert row.account_type == 'handledare'
    assert row.org_number == '5566778899'
    assert row.status == 'pending'


def test_admin_can_approve_pending_account(client):
    pending_id = functions.create_pending_account(
        email='user@example.com',
        username='New User',
        org_number='112233-4455',
        account_type='handledare',
    )

    with client.session_transaction() as session:
        session['admin_logged_in'] = True
        session['admin_username'] = 'Admin'

    response = client.post(f'/admin/requests/{pending_id}/approve')
    assert response.status_code == 302

    with functions.get_engine().connect() as conn:
        pending = conn.execute(
            functions.pending_accounts_table.select().where(
                functions.pending_accounts_table.c.id == pending_id
            )
        ).first()
        assert pending.status == 'approved'

        created_user = conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.email == functions.hash_value('user@example.com')
            )
        ).first()

    assert created_user is not None
    assert created_user.role == 'handledare'
    assert created_user.org_number == '1122334455'


def test_admin_can_deny_pending_account(client):
    pending_id = functions.create_pending_account(
        email='deny@example.com',
        username='Denied User',
        org_number='',
        account_type='user',
    )

    with client.session_transaction() as session:
        session['admin_logged_in'] = True
        session['admin_username'] = 'Admin'

    response = client.post(f'/admin/requests/{pending_id}/deny')
    assert response.status_code == 302

    with functions.get_engine().connect() as conn:
        pending = conn.execute(
            functions.pending_accounts_table.select().where(
                functions.pending_accounts_table.c.id == pending_id
            )
        ).first()
    assert pending.status == 'denied'


def test_user_can_request_membership(client):
    personnummer = '9001011234'
    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    with functions.get_engine().begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username='Ordinary User',
                email=functions.hash_value('user@example.com'),
                password=functions.hash_password('secret'),
                personnummer=pnr_hash,
                role='user',
            )
        )

    with client.session_transaction() as session:
        session['user_logged_in'] = True
        session['personnummer'] = pnr_hash
        session['username'] = 'Ordinary User'

    response = client.post(
        '/me/connect-organization',
        data={'org_number': '123456-7890'},
        follow_redirects=False,
    )
    assert response.status_code == 302

    with functions.get_engine().connect() as conn:
        requests = conn.execute(functions.membership_requests_table.select()).fetchall()
    assert len(requests) == 1
    req = requests[0]
    assert req.status == 'pending'
    assert req.org_number == '1234567890'


def test_handledare_can_approve_membership(client):
    org_number = '555555-1234'
    org_normalized = functions.normalize_org_number(org_number)
    pnr_hash = functions.hash_value(functions.normalize_personnummer('8501011234'))
    supervisor_email = 'boss@example.com'
    email_hash = functions.hash_value(functions.normalize_email(supervisor_email))

    with functions.get_engine().begin() as conn:
        user_id = conn.execute(
            functions.users_table.insert().values(
                username='Member User',
                email=functions.hash_value('member@example.com'),
                password=functions.hash_password('secret'),
                personnummer=pnr_hash,
                role='user',
            )
        ).inserted_primary_key[0]

        supervisor_user_id = conn.execute(
            functions.users_table.insert().values(
                username='Handledare',
                email=email_hash,
                password=functions.hash_password('another-secret'),
                personnummer=functions.hash_value('virtual:boss'),
                role='handledare',
                org_number=org_normalized,
            )
        ).inserted_primary_key[0]

        conn.execute(
            functions.supervisors_table.insert().values(
                name='Handledare',
                email=email_hash,
                password=functions.hash_password('handledare'),
            )
        )

        request_id = conn.execute(
            functions.membership_requests_table.insert().values(
                user_id=user_id,
                org_number=org_normalized,
                status='pending',
            )
        ).inserted_primary_key[0]

    with client.session_transaction() as session:
        session['supervisor_logged_in'] = True
        session['supervisor_email_hash'] = email_hash
        session['supervisor_name'] = 'Handledare'

    response = client.post(f'/handledare/requests/{request_id}/approve')
    assert response.status_code == 302

    with functions.get_engine().connect() as conn:
        req_row = conn.execute(
            functions.membership_requests_table.select().where(
                functions.membership_requests_table.c.id == request_id
            )
        ).first()
        member_user = conn.execute(
            functions.users_table.select().where(
                functions.users_table.c.id == user_id
            )
        ).first()

    assert req_row.status == 'approved'
    assert member_user.org_number == org_normalized

