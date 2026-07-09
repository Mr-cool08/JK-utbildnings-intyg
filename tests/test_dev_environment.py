# Copyright (c) Liam Suorsa and Mika Suorsa
from __future__ import annotations

import io

import app
import functions
from course_categories import COURSE_CATEGORIES
from functions.emails import service as email_service
from functions.notifications import critical_events
from scripts import seed_dev_environment, validate_dev_environment


def _configure_valid_dev_environment(monkeypatch, tmp_path):
    db_path = tmp_path / "dev.sqlite"

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("DISABLE_EMAILS", "true")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("SECRET_KEY", "dev-secret-key")
    monkeypatch.setenv("HASH_SALT", "dev-hash-salt")
    monkeypatch.setenv("DEV_ADMIN_USERNAME", "dev_admin")
    monkeypatch.setenv("DEV_ADMIN_PASSWORD", "dev-admin-placeholder")
    monkeypatch.setenv("DEV_PRIVATE_USER_NAME", "Dev Testperson")
    monkeypatch.setenv("DEV_PRIVATE_USER_EMAIL", "dev.private.user@example.com")
    monkeypatch.setenv("DEV_PRIVATE_USER_PERSONNUMMER", "199001011234")
    monkeypatch.setenv("DEV_PRIVATE_USER_PASSWORD", "dev-private-placeholder")
    monkeypatch.setenv("DEV_COMPANY_NAME", "Dev Exempelbolag AB")
    monkeypatch.setenv("DEV_COMPANY_EMAIL", "dev.company@example.com")
    monkeypatch.setenv("DEV_COMPANY_ORGNR", "5561234567")
    monkeypatch.setenv("DEV_COMPANY_PASSWORD", "dev-company-placeholder")
    monkeypatch.setenv("ADMIN_EMAIL", "dev-admin@example.com")

    for env_name in validate_dev_environment.FORBIDDEN_DEV_SMTP_VARIABLES:
        monkeypatch.delenv(env_name, raising=False)

    return db_path


def _csrf_token(client) -> str:
    with client.session_transaction() as session_data:
        return str(session_data["csrf_token"])


def _set_dev_ui_flags(monkeypatch) -> None:
    monkeypatch.setitem(app.app.config, "IS_DEV_ENVIRONMENT", True)
    monkeypatch.setitem(app.app.config, "DISABLE_ANALYTICS", True)
    monkeypatch.setitem(app.app.config, "NOINDEX", True)
    monkeypatch.setitem(app.app.config, "DEV_UI_LABEL", "Utvecklingsmiljö")
    monkeypatch.setitem(app.app.config, "APP_DISPLAY_NAME", "Utbildningsintyg DEV")


def test_resolve_secret_key_prefers_uppercase(monkeypatch):
    monkeypatch.setattr(
        app.os,
        "getenv",
        lambda key, default=None: {
            "SECRET_KEY": "upper-secret",
            "secret_key": "legacy-secret",
        }.get(key, default),
    )

    assert app._resolve_secret_key() == "upper-secret"


def test_create_app_applies_dev_session_cookie_defaults(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "0")
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("SECRET_KEY", "dev-secret")
    monkeypatch.delenv("SESSION_COOKIE_DOMAIN", raising=False)
    monkeypatch.delenv("SESSION_COOKIE_NAME", raising=False)
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("SESSION_COOKIE_HTTPONLY", raising=False)
    monkeypatch.delenv("SESSION_COOKIE_SAMESITE", raising=False)
    monkeypatch.delenv("PREFERRED_URL_SCHEME", raising=False)

    monkeypatch.setattr(app.functions, "create_database", lambda: None)
    monkeypatch.setattr(app, "_enable_debug_mode", lambda _app_obj: None)

    flask_app = app.create_app()

    assert flask_app.config["APP_ENV"] == "development"
    assert flask_app.config["IS_DEV_ENVIRONMENT"] is True
    assert flask_app.config["SESSION_COOKIE_NAME"] == "jk_dev_session"
    assert flask_app.config["SESSION_COOKIE_SECURE"] is True
    assert flask_app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert flask_app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert flask_app.config.get("SESSION_COOKIE_DOMAIN") in (None, "")
    assert flask_app.config["PREFERRED_URL_SCHEME"] == "https"


def test_create_app_requires_dev_mode_for_dev_environment_flags(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "0")
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DEV_MODE", "false")
    monkeypatch.setenv("SECRET_KEY", "prod-like-secret")
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("SESSION_COOKIE_NAME", raising=False)

    monkeypatch.setattr(app.functions, "create_database", lambda: None)

    flask_app = app.create_app()

    assert flask_app.config["APP_ENV"] == "development"
    assert flask_app.config["DEV_MODE"] is False
    assert flask_app.config["IS_DEV_ENVIRONMENT"] is False
    assert flask_app.config["APP_DISPLAY_NAME"] == "Utbildningsintyg"
    assert flask_app.config["DISABLE_ANALYTICS"] is False
    assert flask_app.config["NOINDEX"] is False
    assert flask_app.config["SESSION_COOKIE_SECURE"] is True


def test_dev_pages_disable_analytics_and_add_banner(empty_db, monkeypatch):
    _set_dev_ui_flags(monkeypatch)

    with app.app.test_client() as client:
        response = client.get("/", base_url="https://dev.utbildningsintyg.se")

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Utvecklingsmiljö - separat testmiljö med syntetisk data." in body
    assert 'name="robots" content="noindex, nofollow"' in body
    assert "Utbildningsintyg DEV" in body
    assert "https://www.googletagmanager.com/gtag/js?id=G-EHG218KKPZ" not in body
    assert "https://cdn.consentmanager.net/delivery/autoblocking/79b762eac2d3b.js" not in body


def test_gdpr_page_uses_explicit_noindex_follow_in_dev(empty_db, monkeypatch):
    _set_dev_ui_flags(monkeypatch)

    with app.app.test_client() as client:
        response = client.get("/gdpr", base_url="https://dev.utbildningsintyg.se")

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'name="robots" content="noindex, follow"' in body


def test_dev_robots_and_sitemap_are_restricted(empty_db, monkeypatch):
    _set_dev_ui_flags(monkeypatch)

    with app.app.test_client() as client:
        robots_response = client.get("/robots.txt")
        sitemap_response = client.get("/sitemap.xml")

    assert robots_response.status_code == 200
    assert robots_response.get_data(as_text=True) == "User-agent: *\nDisallow: /\n"
    assert sitemap_response.status_code == 404


def test_dev_admin_login_uses_separate_credentials(empty_db, monkeypatch):
    _set_dev_ui_flags(monkeypatch)
    monkeypatch.setenv("DEV_ADMIN_USERNAME", "dev_admin")
    monkeypatch.setenv("DEV_ADMIN_PASSWORD", "dev-admin-placeholder")
    monkeypatch.setenv("admin_username", "prod_admin")
    monkeypatch.setenv("admin_password", "prod-admin-placeholder")

    with app.app.test_client() as client:
        wrong_response = client.post(
            "/login_admin",
            data={"username": "prod_admin", "password": "prod-admin-placeholder"},
        )
        correct_response = client.post(
            "/login_admin",
            data={"username": "dev_admin", "password": "dev-admin-placeholder"},
            follow_redirects=False,
        )

    assert wrong_response.get_json()["message"] == "Ogiltiga inloggningsuppgifter"
    assert correct_response.status_code == 302
    assert correct_response.headers.get("Location", "").endswith("/admin")


def test_validate_dev_environment_rejects_prod_postgres_host(monkeypatch, tmp_path):
    _configure_valid_dev_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/devdb")

    errors = validate_dev_environment.validate_dev_environment()

    assert any("postgres_dev" in error for error in errors)


def test_seed_dev_environment_supports_file_sqlite_smoke_flows(monkeypatch, tmp_path):
    db_path = _configure_valid_dev_environment(monkeypatch, tmp_path)
    _set_dev_ui_flags(monkeypatch)
    functions.reset_engine()

    try:
        seed_defaults = seed_dev_environment.seed_dev_environment()
        assert db_path.exists()
        assert seed_defaults["user_email"] == "dev.private.user@example.com"

        with app.app.test_client() as admin_client:
            admin_response = admin_client.post(
                "/login_admin",
                data={"username": "dev_admin", "password": "dev-admin-placeholder"},
                follow_redirects=False,
            )
        assert admin_response.status_code == 302
        assert admin_response.headers.get("Location", "").endswith("/admin")

        with app.app.test_client() as user_client:
            login_page = user_client.get("/login")
            assert login_page.status_code == 200
            login_response = user_client.post(
                "/login",
                data={
                    "personnummer": "199001011234",
                    "password": "dev-private-placeholder",
                    "csrf_token": _csrf_token(user_client),
                },
                follow_redirects=False,
            )
            assert login_response.status_code == 302
            assert login_response.headers.get("Location", "").endswith("/dashboard")

            upload_response = user_client.post(
                "/dashboard/ladda-upp",
                data={
                    "csrf_token": _csrf_token(user_client),
                    "category": COURSE_CATEGORIES[0][0],
                    "note": "Devuppladdning",
                    "certificate": (io.BytesIO(b"%PDF-1.4 dev"), "dev-intyg.pdf"),
                },
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            assert upload_response.status_code == 200
            assert "Intyget har laddats upp och sparats som PDF." in upload_response.get_data(
                as_text=True
            )

        with app.app.test_client() as supervisor_client:
            login_page = supervisor_client.get("/foretagskonto/login")
            assert login_page.status_code == 200
            login_response = supervisor_client.post(
                "/foretagskonto/login",
                data={
                    "orgnr": "5561234567",
                    "password": "dev-company-placeholder",
                    "csrf_token": _csrf_token(supervisor_client),
                },
                follow_redirects=False,
            )
            assert login_response.status_code == 302
            assert login_response.headers.get("Location", "").endswith("/foretagskonto")

        personnummer_hash = functions.hash_value(functions.normalize_personnummer("199001011234"))
        filenames = {pdf["filename"] for pdf in functions.get_user_pdfs(personnummer_hash)}
        assert any(filename.endswith("_dev-intyg.pdf") for filename in filenames)
    finally:
        functions.reset_engine()


def test_disable_emails_stops_password_reset_and_critical_notifications(monkeypatch):
    monkeypatch.setenv("DISABLE_EMAILS", "true")
    monkeypatch.setenv("ADMIN_EMAIL", "dev-admin@example.com")
    smtp_calls = []

    def _unexpected(*_args, **_kwargs):
        smtp_calls.append(("smtp", _args, _kwargs))
        raise AssertionError("Inga SMTP-anrop ska goras nar DISABLE_EMAILS=true.")

    monkeypatch.setattr(email_service, "load_smtp_settings", _unexpected)
    monkeypatch.setattr(email_service, "send_email_message", _unexpected)

    email_service.send_password_reset_email("test@example.com", "https://example.com/reset")
    critical_events.send_critical_error_notification(
        error_message="Devfel",
        endpoint="/dev-test",
        user_ip="127.0.0.1",
    )

    assert smtp_calls == []


# Copyright (c) Liam Suorsa and Mika Suorsa
