# Copyright (c) Liam Suorsa and Mika Suorsa
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
import werkzeug

sys.path.append(os.path.dirname(os.path.dirname(__file__)))


def _force_test_environment() -> None:
    # Force a hermetic pytest configuration even when the caller has already
    # loaded a .env file into the process environment.
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    os.environ["admin_username"] = "test_admin"
    os.environ["admin_password"] = "test_password_123"
    os.environ["secret_key"] = "test-secret-key"
    os.environ["DEV_MODE"] = "true"
    os.environ["ENABLE_DEMO_MODE"] = "false"
    os.environ["DISABLE_EMAILS"] = "true"


_force_test_environment()

# Ensure tests keep log output inside the workspace to avoid temp-dir permission issues.
_test_log_dir = Path(__file__).resolve().parents[1] / ".pytest_tmp" / "logs"
_test_log_dir.mkdir(parents=True, exist_ok=True)
_test_log_file = os.fspath(_test_log_dir / "pytest.log")
os.environ["LOG_FILE"] = _test_log_file
import app  # noqa: E402
import functions  # noqa: E402
from services.pdf_scanner import ScanVerdict  # noqa: E402

if not hasattr(werkzeug, "__version__"):
    werkzeug.__version__ = "3.0.0"


def _uses_repo_shared_basetemp(config: pytest.Config) -> bool:
    basetemp = getattr(config.option, "basetemp", None)
    shared_basetemp = Path(config.rootpath) / ".pytest_tmp" / "run"
    if not basetemp:
        return True

    configured_basetemp = Path(str(basetemp))
    if not configured_basetemp.is_absolute():
        configured_basetemp = Path(config.rootpath) / configured_basetemp
    return configured_basetemp.resolve() == shared_basetemp.resolve()


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    # Use a session-specific temp dir to avoid stale Windows locks between runs.
    if not _uses_repo_shared_basetemp(config):
        return

    temp_root = Path(config.rootpath) / ".pytest_tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    config.option.basetemp = os.fspath(
        temp_root / f"run-{os.getpid()}-{uuid4().hex[:8]}"
    )


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


@pytest.fixture(autouse=True)
def allow_public_rate_limited_routes(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
):
    if request.node.get_closest_marker("allow_public_rate_limited") is None:
        return
    monkeypatch.setattr(app, "register_public_submission", lambda _ip: True)


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
