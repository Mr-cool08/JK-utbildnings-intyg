import sqlite3
import hashlib
import os
import re
from datetime import datetime

# Simple helper for hashing with a global salt. In a real application this
# should be replaced with a per-user salt and a stronger hashing algorithm.
SALT = os.getenv("HASH_SALT", "static_salt")


def hash_value(value: str) -> str:
    """Return a SHA-256 hash of ``value`` combined with a salt."""
    return hashlib.sha256((value + SALT).encode()).hexdigest()


def normalize_personnummer(pnr: str) -> str:
    """Normalize Swedish personal numbers to 12 digits.

    Accepts inputs with or without separators (e.g., YYMMDD-XXXX, YYYYMMDDXXXX).
    Returns a string with only digits (YYYYMMDDXXXX).
    """
    digits = re.sub(r"\D", "", pnr)
    if len(digits) == 10:  # YYMMDDXXXX
        year = int(digits[:2])
        current_year = datetime.now().year % 100
        century = datetime.now().year // 100 - (1 if year > current_year else 0)
        digits = f"{century:02d}{digits}"
    if len(digits) != 12:
        raise ValueError("Ogiltigt personnummerformat.")
    return digits






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
            personnummer TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def check_password_user(email, password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT * FROM users WHERE email = ? AND password = ?''',
        (hash_value(email), hash_value(password)),
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None


def check_personnummer_password(personnummer: str, password: str) -> bool:
    """Return True if the hashed personnummer and password match a user."""
    personnummer = normalize_personnummer(personnummer)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT * FROM users WHERE personnummer = ? AND password = ?''',
        (hash_value(personnummer), hash_value(password)),
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None

def check_user_exists(email):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT * FROM users WHERE email = ?''',
        (hash_value(email),),
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None

def get_username(email):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT username FROM users WHERE email = ?''',
        (hash_value(email),),
    )
    user = cursor.fetchone()
    conn.close()
    return user[0] if user else None

def check_pending_user(personnummer):
    personnummer = normalize_personnummer(personnummer)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT * FROM pending_users WHERE personnummer = ?''',
        (hash_value(personnummer),),
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None

def admin_create_user(email, username, personnummer, pdf_path):
    if check_user_exists(email):
        return False

    personnummer = normalize_personnummer(personnummer)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        '''
        INSERT INTO pending_users (email, username, personnummer, pdf_path)
        VALUES (?, ?, ?, ?)
        ''',
        (hash_value(email), username, hash_value(personnummer), pdf_path),
    )
    conn.commit()
    conn.close()
    return True


def user_create_user(password, personnummer):
    personnummer = normalize_personnummer(personnummer)
    if get_user_info(personnummer):
        print("Användare finns redan")
        return False

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:

        # Hämta användaren från pending_users
        cursor.execute(
            '''
            SELECT email, username, personnummer
            FROM pending_users
            WHERE personnummer = ?
            ''',
            (hash_value(personnummer),),
        )
        row = cursor.fetchone()
        if not row:
            return False

        email_hashed, username, pnr_hash = row
        print(f"Skapar användare: {email_hashed}, {username}, {pnr_hash}")

        # Ta bort från pending_users
        cursor.execute(
            'DELETE FROM pending_users WHERE personnummer = ?',
            (hash_value(personnummer),),
        )
        print("Användare borttagen från pending_users")
        # Lägg in i users
        cursor.execute(
            '''
            INSERT INTO users (email, password, username, personnummer)
            VALUES (?, ?, ?, ?)
            ''',
            (email_hashed, hash_value(password), username, pnr_hash),
        )
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
    personnummer = normalize_personnummer(personnummer)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT * FROM users WHERE personnummer = ?''',
        (hash_value(personnummer),),
    )
    user = cursor.fetchone()
    conn.close()
    return user

def create_test_user():
    email = "test@example.com"
    username = "Test User"
    personnummer = "199001011234"
    admin_create_user(email, username, personnummer, "dummy.pdf")
