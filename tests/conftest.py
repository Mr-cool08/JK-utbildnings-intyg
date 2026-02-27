# Copyright (c) Liam Suorsa and Mika Suorsa
import os
import sys
import tempfile
from pathlib import Path

import pytest
import werkzeug

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("admin_username", "test_admin")
os.environ.setdefault("admin_password", "test_password_123")
os.environ.setdefault("secret_key", "test-secret-key")
os.environ.setdefault("DEV_MODE", "true")
# Ensure tests use a temp directory for logs to avoid permission issues
_test_log_file = os.path.join(tempfile.gettempdir(), "pytest.log")
os.environ.setdefault("LOG_FILE", _test_log_file)
import app  # noqa: E402
import functions  # noqa: E402
from services.pdf_scanner import ScanVerdict  # noqa: E402

if not hasattr(werkzeug, "__version__"):
    werkzeug.__version__ = "3.0.0"


def _prepare_database(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("admin_username", "test_admin")
    monkeypatch.setenv("admin_password", "test_password_123")
    functions.reset_engine()
    functions.create_database()
    app.app.secret_key = "test-secret"


@pytest.fixture(autouse=True)
def allow_pdf_scanning(monkeypatch: pytest.MonkeyPatch):
    """Stubba PDF-skanning för tester som inte behöver säkerhetskontrollen."""

    def _allow_scan(_content: bytes, _logger=None):
        return ScanVerdict("ALLOW", [])

    monkeypatch.setattr("functions.pdf.service.scan_pdf_bytes", _allow_scan)


@pytest.fixture
def empty_db(tmp_path, monkeypatch):
    # Provide a fresh empty database for a test.
    _prepare_database(monkeypatch, tmp_path)
    return functions.get_engine()


@pytest.fixture(name="_empty_db")
def unused_empty_db(empty_db):
    # Alias fixture so tests can use an underscored name without Ruff warnings.
    return empty_db


@pytest.fixture
def user_db(tmp_path, monkeypatch):
    # Provide a database pre-populated with a default user.
    _prepare_database(monkeypatch, tmp_path)
    engine = functions.get_engine()
    with engine.begin() as conn:
        conn.execute(
            functions.users_table.insert().values(
                username="Test",
                email=functions.hash_value("test@example.com"),
                password=functions.hash_password("secret"),
                personnummer=functions.hash_value("9001011234"),
            )
        )
    return engine
