import io

import functions


def login_admin(client):
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True


def test_admin_upload_valid(client, tmp_path, monkeypatch):
    monkeypatch.setitem(client.application.config, 'UPLOAD_ROOT', tmp_path)
    login_admin(client)
    pdf_bytes = b'%PDF-1.4 test'
    data = {
        'email': 'new@example.com',
        'username': 'New User',
        'personnummer': '19900101-1234',
        'pdf': (io.BytesIO(pdf_bytes), 'doc.pdf'),
    }
    resp = client.post('/admin', data=data, content_type='multipart/form-data')
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'success'


def test_admin_upload_invalid_type(client, tmp_path, monkeypatch):
    monkeypatch.setitem(client.application.config, 'UPLOAD_ROOT', tmp_path)
    login_admin(client)
    data = {
        'email': 'new@example.com',
        'username': 'New User',
        'personnummer': '19900101-1234',
        'pdf': (io.BytesIO(b'not pdf'), 'doc.txt'),
    }
    resp = client.post('/admin', data=data, content_type='multipart/form-data')
    assert resp.status_code == 400
