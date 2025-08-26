import logging


def test_404_html(client):
    resp = client.get('/missing')
    assert resp.status_code == 404
    assert b'Sidan du letade efter' in resp.data


def test_404_json(client):
    resp = client.get('/api/missing')
    assert resp.status_code == 404
    data = resp.get_json()
    assert data['status'] == 404
    assert data['type'] == 'NotFound'
    assert 'request_id' in data


def test_500_json(app, client, caplog):
    @app.route('/api/error')
    def _err():
        raise RuntimeError('boom')

    caplog.set_level(logging.ERROR)
    resp = client.get('/api/error')
    assert resp.status_code == 500
    data = resp.get_json()
    assert data['status'] == 500
    assert data['type'] == 'RuntimeError'
    assert 'request_id' in data
    assert any('Unhandled exception' in r.message for r in caplog.records)
