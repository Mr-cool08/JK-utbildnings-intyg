import logging

def test_html_404(client):
    resp = client.get('/no-such-page')
    assert resp.status_code == 404
    assert resp.headers['Content-Type'].startswith('text/html')
    assert b'Sidan du letade efter' in resp.data

def test_api_404(app):
    with app.test_client() as c:
        resp = c.get('/api/missing')
    data = resp.get_json()
    assert resp.status_code == 404
    assert data['status'] == 404
    assert 'request_id' in data

def test_api_500_logs_request_id(app, caplog):
    with caplog.at_level(logging.ERROR):
        with app.test_client() as c:
            resp = c.get('/api/boom')
    data = resp.get_json()
    rid = resp.headers['X-Request-ID']
    assert resp.status_code == 500
    assert data['request_id'] == rid
    assert any(r.request_id == rid for r in caplog.records)
