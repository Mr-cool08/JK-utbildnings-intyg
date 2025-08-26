def test_404_html(client):
    resp = client.get('/missing', headers={'Accept': 'text/html'})
    assert resp.status_code == 404
    assert b'Sidan du letade efter' in resp.data


def test_404_json(client):
    resp = client.get('/api/missing', headers={'Accept': 'application/json'})
    assert resp.status_code == 404
    data = resp.get_json()
    assert data['status'] == 404
    assert data['request_id']
def test_500_handler_logs_request_id(app, client):
    @app.route('/api/boom')
    def boom():
        raise RuntimeError('boom')

    handler = app.logger.handlers[0]
    records = []
    original_emit = handler.emit

    def emit(record):
        records.append(record)
        original_emit(record)

    handler.emit = emit

    resp = client.get('/api/boom')
    assert resp.status_code == 500
    rid = resp.get_json()['request_id']
    assert any(getattr(r, 'request_id', None) == rid for r in records)
