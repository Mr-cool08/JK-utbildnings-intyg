
def test_request_id_echo(client):
    resp = client.get('/healthz', headers={'X-Request-ID': 'abc-123'})
    assert resp.status_code == 200
    assert resp.headers['X-Request-ID'] == 'abc-123'


def test_request_id_generated(client):
    resp = client.get('/healthz')
    assert resp.status_code == 200
    assert resp.headers.get('X-Request-ID')
