from main import create_app


def test_security_headers(client):
    resp = client.get('/')
    headers = resp.headers
    assert 'Content-Security-Policy' in headers
    assert 'Strict-Transport-Security' in headers
    assert headers.get('X-Content-Type-Options') == 'nosniff'
    assert headers.get('X-Frame-Options') == 'SAMEORIGIN'


def test_cors_allowed_origin(tmp_path, monkeypatch):
    monkeypatch.setenv('SECRET_KEY', 'test-secret')
    monkeypatch.setenv('ALLOWED_ORIGINS', 'https://example.com')
    app = create_app()
    app.config.update(TESTING=True, UPLOAD_ROOT=str(tmp_path))
    client = app.test_client()
    resp = client.get('/', headers={'Origin': 'https://example.com'})
    assert resp.headers.get('Access-Control-Allow-Origin') == 'https://example.com'
