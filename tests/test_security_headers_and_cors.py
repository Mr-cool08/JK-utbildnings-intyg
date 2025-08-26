
def test_security_headers(client):
    resp = client.get('/')
    assert resp.headers.get('Content-Security-Policy')
    assert resp.headers.get('Strict-Transport-Security')
    assert resp.headers.get('X-Frame-Options')
    assert resp.headers.get('X-Content-Type-Options')


def test_cors_allowed_origin(client):
    resp = client.get('/healthz', headers={'Origin': 'http://example.com'})
    assert resp.headers.get('Access-Control-Allow-Origin') == 'http://example.com'
