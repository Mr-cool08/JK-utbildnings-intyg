import sqlite3

import main
import functions


def test_healthz(client):
    resp = client.get('/healthz')
    assert resp.status_code == 200
    assert resp.get_json() == {'status': 'ok'}


def test_readiness_ok(client):
    resp = client.get('/readiness')
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'ok'


def test_readiness_fs_fail(client, monkeypatch):
    monkeypatch.setitem(client.application.config, 'UPLOAD_ROOT', '/nope')
    resp = client.get('/readiness')
    assert resp.status_code == 503
    assert resp.get_json()['status'] == 'error'


def test_readiness_db_fail(client, monkeypatch):
    def connect_fail(*args, **kwargs):
        raise sqlite3.OperationalError('fail')
    monkeypatch.setattr(main.sqlite3, 'connect', connect_fail)
    resp = client.get('/readiness')
    assert resp.status_code == 503
    assert resp.get_json()['status'] == 'error'
