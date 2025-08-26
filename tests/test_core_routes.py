def test_home_page(client):
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'Welcome' in resp.data


def test_login_failure(app, client):
    from functions import hash_value
    import sqlite3

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            "Test",
            hash_value("test@example.com"),
            hash_value("secret"),
            hash_value("199001011234"),
        ),
    )
    conn.commit()
    conn.close()

    resp = client.post('/login', data={'personnummer': '199001011234', 'password': 'wrong'})
    assert resp.status_code == 401
    assert b'Invalid credentials' in resp.data
