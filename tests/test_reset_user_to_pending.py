import os
import sqlite3
import sys
import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import functions  # noqa: E402


@pytest.fixture
def configured_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    real_connect = sqlite3.connect

    def connect_stub(_):
        return real_connect(db_path)

    monkeypatch.setattr(functions, "DB_PATH", str(db_path))
    monkeypatch.setattr(functions.sqlite3, "connect", connect_stub)
    monkeypatch.setattr(functions, "APP_ROOT", str(tmp_path))
    functions.create_database()
    return db_path


def _insert_user(db_path, email, username, personnummer):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, personnummer) VALUES (?, ?, ?, ?)",
        (
            username,
            functions.hash_value(email),
            functions.hash_password("secret"),
            functions.hash_value(functions.normalize_personnummer(personnummer)),
        ),
    )
    conn.commit()
    conn.close()


def test_reset_user_to_pending_moves_user(configured_db, tmp_path):
    email = "user@example.com"
    username = "User"
    personnummer = "19900101-1234"
    _insert_user(configured_db, email, username, personnummer)

    pnr_hash = functions.hash_value(functions.normalize_personnummer(personnummer))
    uploads_root = tmp_path / "uploads" / pnr_hash
    uploads_root.mkdir(parents=True)
    pdf_path = uploads_root / "certificate.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 test")

    result = functions.reset_user_to_pending(email, personnummer, os.path.join(tmp_path, "uploads"))

    assert result["username"] == username
    assert result["personnummer_hash"] == pnr_hash
    assert result["pdf_paths"] == [f"uploads/{pnr_hash}/certificate.pdf"]

    conn = sqlite3.connect(configured_db)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE personnummer = ?", (pnr_hash,))
    assert cursor.fetchone() is None
    cursor.execute(
        "SELECT email, username, pdf_path FROM pending_users WHERE personnummer = ?",
        (pnr_hash,),
    )
    pending_row = cursor.fetchone()
    conn.close()

    assert pending_row == (
        functions.hash_value(email),
        username,
        f"uploads/{pnr_hash}/certificate.pdf",
    )


def test_reset_user_to_pending_email_mismatch(configured_db, tmp_path):
    email = "user@example.com"
    username = "User"
    personnummer = "19900101-1234"
    _insert_user(configured_db, email, username, personnummer)

    with pytest.raises(ValueError):
        functions.reset_user_to_pending(
            "wrong@example.com",
            personnummer,
            os.path.join(tmp_path, "uploads"),
        )


def test_reset_user_to_pending_missing_user(configured_db, tmp_path):
    with pytest.raises(ValueError):
        functions.reset_user_to_pending(
            "missing@example.com",
            "19900101-1234",
            os.path.join(tmp_path, "uploads"),
        )
