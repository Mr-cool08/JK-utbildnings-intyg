import pytest


@pytest.mark.parametrize('app', [{'ALLOWED_ORIGINS': 'http://allowed.com'}], indirect=True)
def test_cors_allowlist(app, client):
    resp = client.get('/healthz', headers={'Origin': 'http://allowed.com'})
    assert resp.headers['Access-Control-Allow-Origin'] == 'http://allowed.com'


def test_security_headers_present(client):
    resp = client.get('/')
    headers = resp.headers
    assert 'Content-Security-Policy' in headers
    assert 'Strict-Transport-Security' in headers
    assert headers.get('X-Frame-Options') is not None
    assert headers.get('X-Content-Type-Options') == 'nosniff'
