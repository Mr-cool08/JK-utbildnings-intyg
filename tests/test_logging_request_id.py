import re


def test_request_id_echo(client):
    resp = client.get('/healthz', headers={'X-Request-ID': 'abc123'})
    assert resp.headers['X-Request-ID'] == 'abc123'


def test_request_id_generated(client):
    resp = client.get('/healthz')
    rid = resp.headers.get('X-Request-ID')
    assert rid and re.match(r'^[0-9a-fA-F-]{36}$', rid)
