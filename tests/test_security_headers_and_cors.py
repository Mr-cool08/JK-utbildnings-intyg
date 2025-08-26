
def test_security_headers(client):
    resp = client.get('/')
    headers = resp.headers
    assert 'Content-Security-Policy' in headers
    assert 'Strict-Transport-Security' in headers
    assert headers.get('X-Frame-Options') in ('SAMEORIGIN', 'DENY')
    assert headers.get('X-Content-Type-Options') == 'nosniff'

def test_cors_allowed_origin(app_factory):
    app = app_factory(ALLOWED_ORIGINS='http://example.com')
    with app.test_client() as c:
        resp = c.get('/healthz', headers={'Origin': 'http://example.com'})
        assert resp.headers.get('Access-Control-Allow-Origin') == 'http://example.com'
