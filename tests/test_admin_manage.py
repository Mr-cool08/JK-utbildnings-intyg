import app
import functions


def _admin_client():
    client = app.app.test_client()
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True
    return client


def _create_user_with_pdf(engine, email='user@example.com', personnummer='19900101-1234'):
    email_norm = functions.normalize_email(email)
    email_hash = functions.hash_value(email_norm)
    pnr_norm = functions.normalize_personnummer(personnummer)
    pnr_hash = functions.hash_value(pnr_norm)
    with engine.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username='Användare',
                email=email_hash,
                email_plain=email_norm,
                password=functions.hash_password('hemligt'),
                personnummer=pnr_hash,
            )
        )
    pdf_id = functions.store_pdf_blob(pnr_hash, 'intyg.pdf', b'PDF-DATA', ['fallskydd'])
    return pnr_norm, pdf_id


def test_admin_manage_requires_login(empty_db):
    client = app.app.test_client()
    response = client.get('/admin/hantera')
    assert response.status_code == 302
    response = client.post('/admin/hantera/pdfer', json={'personnummer': '19900101-1234'})
    assert response.status_code == 403


def test_admin_manage_list_update_and_delete_pdf(empty_db):
    engine = empty_db
    personnummer, pdf_id = _create_user_with_pdf(engine)

    with _admin_client() as client:
        response = client.post('/admin/hantera/pdfer', json={'personnummer': personnummer})
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert len(data['pdfs']) == 1
        assert data['pdfs'][0]['id'] == pdf_id

        update_response = client.post(
            '/admin/hantera/uppdatera_kategorier',
            json={
                'personnummer': personnummer,
                'pdf_id': pdf_id,
                'categories': ['lift', 'truck'],
            },
        )
        assert update_response.status_code == 200
        update_data = update_response.get_json()
        assert update_data['status'] == 'success'
        assert set(update_data['categories']) == {'lift', 'truck'}

    with engine.connect() as conn:
        row = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.id == pdf_id
            )
        ).first()
    assert row is not None
    assert row.categories in {'lift,truck', 'truck,lift'}

    with _admin_client() as client:
        delete_response = client.post(
            '/admin/hantera/radera_pdf',
            json={'personnummer': personnummer, 'pdf_id': pdf_id},
        )
        assert delete_response.status_code == 200
        delete_data = delete_response.get_json()
        assert delete_data['status'] == 'success'

    with engine.connect() as conn:
        remaining = conn.execute(
            functions.user_pdfs_table.select().where(
                functions.user_pdfs_table.c.id == pdf_id
            )
        ).first()
    assert remaining is None


def test_admin_manage_send_reset_and_use_link(empty_db, monkeypatch):
    engine = empty_db
    personnummer, _ = _create_user_with_pdf(engine)
    sent_links = []

    def fake_send_email(address, link, username=None):
        sent_links.append(link)

    monkeypatch.setattr(app, 'send_password_reset_email', fake_send_email)

    with _admin_client() as client:
        response = client.post(
            '/admin/hantera/skicka_aterstallning',
            json={'email': 'user@example.com'},
        )
        assert response.status_code == 200
        payload = response.get_json()
        assert payload['status'] == 'success'

    assert sent_links, 'Reset email should have been sent'

    with engine.connect() as conn:
        token_row = conn.execute(functions.password_resets_table.select()).first()
    assert token_row is not None
    token = token_row.token

    with app.app.test_client() as client:
        get_response = client.get(f'/aterstall/{token}')
        assert get_response.status_code == 200
        assert 'Nytt lösenord' in get_response.get_data(as_text=True)

        post_response = client.post(
            f'/aterstall/{token}',
            data={'password': 'nyttlosen'},
            follow_redirects=False,
        )
        assert post_response.status_code == 302
        assert post_response.headers['Location'].endswith('/login')

    assert functions.check_personnummer_password(personnummer, 'nyttlosen')
