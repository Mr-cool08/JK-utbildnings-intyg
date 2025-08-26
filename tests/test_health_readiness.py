import os


def test_healthz(client):
    resp = client.get('/healthz')
    assert resp.status_code == 200
    assert resp.get_json() == {'status': 'ok'}


def test_readiness_ok(client):
    resp = client.get('/readiness')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] == 'ok'


def test_readiness_storage_fail(app, client, monkeypatch):
    monkeypatch.setattr(os, 'access', lambda *a, **k: False)
    resp = client.get('/readiness')
    assert resp.status_code == 503
    data = resp.get_json()
    assert data['status'] == 'unavailable'
