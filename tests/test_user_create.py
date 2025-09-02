import sqlite3
import functions


def test_user_create_hashes_password(empty_db):
    db_path = empty_db

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO pending_users (email, username, personnummer, pdf_path) VALUES (?, ?, ?, ?)",
        (
            functions.hash_value("user@example.com"),
            "User",
            functions.hash_value("199001011234"),
            "doc.pdf",
        ),
    )
    conn.commit()
    conn.close()

    assert functions.user_create_user("mypassword", functions.hash_value("199001011234"))

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password FROM users WHERE personnummer = ?",
        (functions.hash_value("199001011234"),),
    )
    row = cursor.fetchone()
    conn.close()
    assert row is not None
    assert functions.verify_password(row[0], "mypassword")
