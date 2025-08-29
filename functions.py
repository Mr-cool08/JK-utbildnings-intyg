import sqlite3
import hashlib
import hmac
import os
import re
from datetime import datetime

# Global salt for deterministic hashing of identifiers like email and
# personnummer. Passwords get their own per-user salts.
SALT = os.getenv("HASH_SALT", "static_salt").encode()
# Number of iterations for PBKDF2. Can be overridden via env for tuning.
ITERATIONS = int(os.getenv("HASH_ITERATIONS", "100000"))
# Path to the SQLite database file. Using a file ensures persistence across
# restarts as long as the path points to a persistent volume.
DB_PATH = os.getenv("DATABASE_PATH", "database.db")


def hash_value(value: str) -> str:
    """Return a salted PBKDF2-HMAC hash of ``value``.

    The result is deterministic for a given ``value`` and global ``SALT`` so
    it can be used as a key in the database for lookup purposes.
    """
    return hashlib.pbkdf2_hmac("sha256", value.encode(), SALT, ITERATIONS).hex()


def hash_password(password: str) -> str:
    """Return a securely hashed password with a per-user random salt."""
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"{salt.hex()}:{pwd_hash.hex()}"


def verify_password(stored: str, password: str) -> bool:
    """Verify a password against the stored ``salt:hash`` string."""
    try:
        salt_hex, hash_hex = stored.split(":")
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS).hex()
    return hmac.compare_digest(pwd_hash, hash_hex)


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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT password FROM users WHERE email = ?''',
        (hash_value(email),),
    )
    row = cursor.fetchone()
    conn.close()
    return bool(row) and verify_password(row[0], password)


def check_personnummer_password(personnummer: str, password: str) -> bool:
    """Return True if the hashed personnummer and password match a user."""
    personnummer = normalize_personnummer(personnummer)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT password FROM users WHERE personnummer = ?''',
        (hash_value(personnummer),),
    )
    row = cursor.fetchone()
    conn.close()
    return bool(row) and verify_password(row[0], password)

def check_user_exists(email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT * FROM users WHERE email = ?''',
        (hash_value(email),),
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None

def get_username(email):
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT * FROM pending_users WHERE personnummer = ?''',
        (hash_value(personnummer),),
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None


def check_pending_user_hash(personnummer_hash: str) -> bool:
    """Return True if a pending user with ``personnummer_hash`` exists."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT 1 FROM pending_users WHERE personnummer = ?''',
        (personnummer_hash,),
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None

def admin_create_user(email, username, personnummer, pdf_path):
    if check_user_exists(email):
        return False

    personnummer = normalize_personnummer(personnummer)
    conn = sqlite3.connect(DB_PATH)
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


def user_create_user(password: str, personnummer_hash: str) -> bool:
    """Move a pending user identified by ``personnummer_hash`` into users."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # Kontrollera om användaren redan finns
        cursor.execute(
            'SELECT 1 FROM users WHERE personnummer = ?',
            (personnummer_hash,),
        )
        if cursor.fetchone():
            print("Användare finns redan")
            return False

        # Hämta användaren från pending_users
        cursor.execute(
            '''
            SELECT email, username, personnummer
            FROM pending_users
            WHERE personnummer = ?
            ''',
            (personnummer_hash,),
        )
        row = cursor.fetchone()
        if not row:
            return False

        email_hashed, username, pnr_hash = row
        print(f"Skapar användare: {email_hashed}, {username}, {pnr_hash}")

        # Ta bort från pending_users
        cursor.execute(
            'DELETE FROM pending_users WHERE personnummer = ?',
            (personnummer_hash,),
        )
        print("Användare borttagen från pending_users")

        # Lägg in i users
        cursor.execute(
            '''
            INSERT INTO users (email, password, username, personnummer)
            VALUES (?, ?, ?, ?)
            ''',
            (email_hashed, hash_password(password), username, pnr_hash),
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
    conn = sqlite3.connect(DB_PATH)
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
