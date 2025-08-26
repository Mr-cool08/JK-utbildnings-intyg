import io
import os
from functions import hash_value, normalize_personnummer


def login_admin(client):
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True


def test_upload_valid_pdf(app, client):
    login_admin(client)
    pdf_bytes = b"%PDF-1.4 test"
    data = {
        'email': 'new@example.com',
        'username': 'New',
        'personnummer': '19900101-1234',
        'pdf': (io.BytesIO(pdf_bytes), 'doc.pdf'),
    }
    resp = client.post('/admin', data=data, content_type='multipart/form-data')
    assert resp.status_code == 200
    pnr_hash = hash_value(normalize_personnummer('19900101-1234'))
    user_dir = os.path.join(app.config['UPLOAD_ROOT'], pnr_hash)
    files = os.listdir(user_dir)
    assert any(f.endswith('.pdf') for f in files)


def test_upload_invalid_type(app, client):
    login_admin(client)
    data = {
        'email': 'bad@example.com',
        'username': 'Bad',
        'personnummer': '19900101-1234',
        'pdf': (io.BytesIO(b'plain text'), 'doc.txt'),
    }
    resp = client.post('/admin', data=data, content_type='multipart/form-data')
    assert resp.status_code == 400
