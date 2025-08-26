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
    assert data['checks']['storage'] == 'ok'
    assert data['checks']['database'] == 'ok'


def test_readiness_db_failure(app, client, monkeypatch):
    import main

    def fail_connect(*args, **kwargs):
        raise sqlite3.OperationalError('boom')

    monkeypatch.setattr(main.sqlite3, 'connect', fail_connect)
    resp = client.get('/readiness')
    assert resp.status_code == 503
    data = resp.get_json()
    assert data['status'] == 'error'
    assert 'database' in data['checks']
