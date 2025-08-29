import logging
import sqlite3
import hashlib
import os
import re
from datetime import datetime

# Simple helper for hashing with a global salt. In a real application this
# should be replaced with a per-user salt and a stronger hashing algorithm.
logger = logging.getLogger(__name__)
SALT = os.getenv("HASH_SALT", "static_salt")


def hash_value(value: str) -> str:
    """Return a SHA-256 hash of ``value`` combined with a salt."""
    logger.debug("Hashing value")
    return hashlib.sha256((value + SALT).encode()).hexdigest()


def normalize_personnummer(pnr: str) -> str:
    """Normalize Swedish personal numbers to 12 digits.

    Accepts inputs with or without separators (e.g., YYMMDD-XXXX, YYYYMMDDXXXX).
    Returns a string with only digits (YYYYMMDDXXXX).
    """
    logger.debug("Normalizing personnummer %s", pnr)
    digits = re.sub(r"\D", "", pnr)
    if len(digits) == 10:  # YYMMDDXXXX
        year = int(digits[:2])
        current_year = datetime.now().year % 100
        century = datetime.now().year // 100 - (1 if year > current_year else 0)
        digits = f"{century:02d}{digits}"
    if len(digits) != 12:
        logger.error("Invalid personnummer format: %s", pnr)
        raise ValueError("Ogiltigt personnummerformat.")
    logger.debug("Normalized personnummer to %s", digits)
    return digits






def create_database():
    logger.debug("Creating database and ensuring tables exist")
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
    logger.info("Database initialized")

def check_password_user(email, password):
    logger.debug("Checking password for email %s", email)
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
    logger.debug("Checking login for %s", personnummer)
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
    logger.debug("Checking if user exists for email %s", email)
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
    logger.debug("Fetching username for email %s", email)
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
    logger.debug("Checking pending user for %s", personnummer)
    conn = sqlite3.connect('database.db')
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
    logger.debug("Checking pending user by hash %s", personnummer_hash)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT 1 FROM pending_users WHERE personnummer = ?''',
        (personnummer_hash,),
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None

def admin_create_user(email, username, personnummer, pdf_path):
    logger.debug("Admin creating user %s", personnummer)
    if check_user_exists(email):
        logger.warning("Attempt to recreate existing user %s", email)
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
    logger.info("Pending user created for %s", personnummer)
    return True


def user_create_user(password: str, personnummer_hash: str) -> bool:
    """Move a pending user identified by ``personnummer_hash`` into users."""
    logger.debug("Moving pending user %s to users", personnummer_hash)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        # Kontrollera om användaren redan finns
        cursor.execute(
            'SELECT 1 FROM users WHERE personnummer = ?',
            (personnummer_hash,),
        )
        if cursor.fetchone():
            logger.warning("User %s already exists", personnummer_hash)
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
            logger.warning("Pending user %s not found", personnummer_hash)
            return False

        email_hashed, username, pnr_hash = row
        logger.debug("Creating user %s", username)

        # Ta bort från pending_users
        cursor.execute(
            'DELETE FROM pending_users WHERE personnummer = ?',
            (personnummer_hash,),
        )
        logger.debug("Removed pending user %s", personnummer_hash)

        # Lägg in i users
        cursor.execute(
            '''
            INSERT INTO users (email, password, username, personnummer)
            VALUES (?, ?, ?, ?)
            ''',
            (email_hashed, hash_value(password), username, pnr_hash),
        )
        logger.info("User %s created", username)

        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logger.exception("Error moving pending user")
        return False
    finally:
        conn.close()


def get_user_info(personnummer):
    personnummer = normalize_personnummer(personnummer)
    logger.debug("Fetching user info for %s", personnummer)
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
    logger.debug("Creating test user")
    email = "test@example.com"
    username = "Test User"
    personnummer = "199001011234"
    admin_create_user(email, username, personnummer, "dummy.pdf")
