import logging


def test_html_404(client):
    resp = client.get('/not-found')
    assert resp.status_code == 404
    assert b'Sidan du letade efter' in resp.data
    assert 'text/html' in resp.content_type


def test_api_404(client):
    resp = client.get('/api/not-found', headers={'Accept': 'application/json'})
    assert resp.status_code == 404
    data = resp.get_json()
    assert data['status'] == 404
    assert data['request_id']


def test_api_500_logs_request_id(app, caplog):
    @app.route('/api/error')
    def boom():
        raise RuntimeError('boom')

    client = app.test_client()
    with caplog.at_level(logging.ERROR):
        resp = client.get('/api/error')
    assert resp.status_code == 500
    data = resp.get_json()
    assert data['status'] == 500
    assert data['request_id']
    assert any(record.request_id == data['request_id'] for record in caplog.records)
