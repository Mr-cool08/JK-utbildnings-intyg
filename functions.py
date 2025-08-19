import sqlite3
import hashlib







def create_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pending_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            personnummer TEXT NOT NULL,
            pdf_path TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            personnummer TEXT NOT NULL,
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

def check_pending_user(personnummer):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM pending_users WHERE personnummer = ?
    ''', (personnummer,))
    user = cursor.fetchone()
    conn.close()
    return user is not None

def admin_create_user(email, username, personnummer, pdf_path):
    if check_user_exists(email):
        return False

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO pending_users (email, username, personnummer, pdf_path)
        VALUES (?, ?, ?, ?)
    ''', (email, username, personnummer, pdf_path))
    conn.commit()
    conn.close()
    return True


def user_create_user(password, personnummer):
    if check_user_exists(personnummer):
        print("Användare finns redan")
        return False

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        
        # Hämta användaren från pending_users
        cursor.execute('''
            SELECT email, username, personnummer, pdf_path 
            FROM pending_users 
            WHERE personnummer = ?
        ''', (personnummer,))
        row = cursor.fetchone()
        if not row:
            return False
        

        email, username, personnummer, pdf_path = row
        print(f"Skapar användare: {email}, {username}, {personnummer}, {pdf_path}")

        # Ta bort från pending_users
        cursor.execute('DELETE FROM pending_users WHERE personnummer = ?', (personnummer,))
        print("Användare borttagen från pending_users")
        # Lägg in i users
        cursor.execute('''
            INSERT INTO users (email, password, username, personnummer, pdf_path)
            VALUES (?, ?, ?, ?, ?)
        ''', (email, password, username, personnummer, pdf_path))
        print("Användare skapad i users")

        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print("Fel vid flytt av användare:", e)
        return False
    finally:
        conn.close()


def get_user_info(personnummer):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM users WHERE personnummer = ?
    ''', (personnummer,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_test_user():
    email = "test@example.com"
    username = "Test User"
    personnummer = "199001011234"
    pdf_path = "static/uploads/test.pdf"
    admin_create_user(email, username, personnummer, pdf_path)
