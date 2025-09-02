import os
import sys
import sqlite3
import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import functions

@pytest.fixture
def db(monkeypatch, tmp_path):
    db_path = tmp_path / 'test.db'
    real_connect = sqlite3.connect
    def connect_stub(_):
        return real_connect(db_path)
    monkeypatch.setattr(functions, 'DB_PATH', str(db_path))
    monkeypatch.setattr(functions.sqlite3, 'connect', connect_stub)
    functions.create_database()
    return db_path

def test_normalize_personnummer(db):
    assert functions.normalize_personnummer('19900101-1234') == '199001011234'
    assert functions.normalize_personnummer('199001011234') == '199001011234'
    assert functions.normalize_personnummer('9001011234') == '199001011234'
    with pytest.raises(ValueError):
        functions.normalize_personnummer('123')

def test_admin_and_user_create_flow(db, monkeypatch):
    email = 'new@example.com'
    username = 'New'
    personnummer = '19900101-1234'
    pdfs = ['a.pdf', 'b.pdf']
    assert functions.admin_create_user(email, username, personnummer, pdfs)

    conn = sqlite3.connect(db)
    cursor = conn.cursor()
    cursor.execute('SELECT email, pdf_path FROM pending_users')
    row = cursor.fetchone()
    conn.close()
    assert row[0] == functions.hash_value(email)
    assert row[1] == 'a.pdf;b.pdf'
    assert not functions.check_user_exists(email)

    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    assert functions.user_create_user('secret', pnr_hash)
    assert functions.check_user_exists(email)

    functions.verify_certificate.cache_clear()
    calls = {'count': 0}
    real_connect = sqlite3.connect
    def connect_count(_):
        calls['count'] += 1
        return real_connect(db)
    monkeypatch.setattr(functions.sqlite3, 'connect', connect_count)

    assert functions.verify_certificate(personnummer)
    assert functions.verify_certificate(personnummer)
    assert calls['count'] == 1
