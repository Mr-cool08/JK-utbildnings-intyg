import sqlite3
import hashlib

def testing():
    print("Testing database connection")
def create_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pending_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            personsnummer TEXT NOT NULL,
            pdf_path TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            personsnummer TEXT NOT NULL,
            pdf_path TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def check_password_user(email, password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM users WHERE email = ? AND password = ?
    ''', (email, hashlib.sha256(password.encode()).hexdigest()))
    user = cursor.fetchone()
    conn.close()
    return user is not None

def check_user_exists(email):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM users WHERE email = ?
    ''', (email,))
    user = cursor.fetchone()
    conn.close()
    return user is not None

def get_username(email):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT username FROM users WHERE email = ?
    ''', (email,))
    user = cursor.fetchone()
    conn.close()
    return user[0] if user else None


def admin_create_user(email, username, personsnummer, pdf_path):
    if check_user_exists(email):
        return False

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO pending_users (email, username, personsnummer, pdf_path)
        VALUES (?, ?, ?, ?)
    ''', (email, username, personsnummer, pdf_path))
    conn.commit()
    conn.close()
    return True


def user_create_user(email, password, username, personsnummer, pdf_path):
    if check_user_exists(email):
        return False
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Remove from pending_users if exists
    cursor.execute('DELETE FROM pending_users WHERE email = ?', (email,))
    # Insert into users
    cursor.execute('''
        INSERT INTO users (email, password, username, personsnummer, pdf_path)
        VALUES (?, ?, ?, ?, ?)
    ''', (email, hashlib.sha256(password.encode()).hexdigest(), username, personsnummer, pdf_path))
    conn.commit()
    conn.close()
    return True


def get_user_info(personnummer):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM users WHERE personsnummer = ?
    ''', (personnummer,))
    user = cursor.fetchone()
    conn.close()
    return user

