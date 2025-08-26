import uuid

def test_request_id_echo(client):
    resp = client.get('/healthz', headers={'X-Request-ID': 'abc'})
    assert resp.headers['X-Request-ID'] == 'abc'

def test_request_id_generated(client):
    resp = client.get('/healthz')
    rid = resp.headers['X-Request-ID']
    assert rid
    uuid.UUID(rid)
