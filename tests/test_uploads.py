import io
import sqlite3


def _login_admin(client):
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True


def test_upload_pdf_success(app, client):
    conn = sqlite3.connect('database.db')
    conn.close()

    pdf_bytes = b"%PDF-1.4 test"
    data = {
        'email': 'new@example.com',
        'username': 'New User',
        'personnummer': '19900101-1234',
        'pdf': (io.BytesIO(pdf_bytes), 'doc.pdf'),
    }
    _login_admin(client)
    resp = client.post('/admin', data=data, content_type='multipart/form-data')
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'success'


def test_upload_pdf_invalid_type(app, client):
    bad_bytes = b'not a pdf'
    data = {
        'email': 'bad@example.com',
        'username': 'Bad',
        'personnummer': '19900101-1234',
        'pdf': (io.BytesIO(bad_bytes), 'doc.txt'),
    }
    _login_admin(client)
    resp = client.post('/admin', data=data, content_type='multipart/form-data')
    assert resp.status_code == 400
    assert resp.get_json()['status'] == 'error'
