import sqlite3

def test_healthz(client):
    resp = client.get('/healthz')
    assert resp.status_code == 200
    assert resp.get_json() == {'status': 'ok'}

def test_readiness_ok(client):
    resp = client.get('/readiness')
    data = resp.get_json()
    assert resp.status_code == 200
    assert data['status'] == 'ok'
    assert data['details']['storage'] == 'ok'
    assert data['details']['database'] == 'ok'

def test_readiness_failure(app, monkeypatch):
    def bad_connect(_):
        raise RuntimeError('no db')
    monkeypatch.setattr(sqlite3, 'connect', bad_connect)
    with app.test_client() as c:
        resp = c.get('/readiness')
    assert resp.status_code == 503
    assert resp.get_json()['status'] == 'fail'
