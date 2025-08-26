import re


def test_request_id_echo(client):
    resp = client.get('/healthz', headers={'X-Request-ID': 'abc-123'})
    assert resp.headers['X-Request-ID'] == 'abc-123'


def test_request_id_generated(client):
    resp = client.get('/healthz')
    header = resp.headers.get('X-Request-ID')
    assert header
    assert re.match(r'^[0-9a-f-]{36}$', header)
