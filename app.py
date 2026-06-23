# Copyright (c) Liam Suorsa and Mika Suorsa
# Flask application for issuing and serving course certificates.

from __future__ import annotations

import logging
import os

from flask import Flask

from web import bootstrap

bootstrap.initialize_runtime()

import functions
from functions import security as sec
from functions.emails import service as email_service
from functions.logging import configure_module_logger
from functions.notifications import critical_events
from functions.pdf import service as pdf
from functions.requests import as_bool, get_request_ip, register_public_submission

from web.errors import register_error_handlers, request_entity_too_large
from web.helpers import (
    ALLOWED_ADMIN_APPROVAL_ERRORS,
    ALLOWED_ADMIN_REJECTION_ERRORS,
    ALLOWED_PDF_METADATA_UPDATE_ERRORS,
    ALLOWED_PDF_UPLOAD_ERRORS,
    ALLOWED_SUPERVISOR_ACTIVATION_ERRORS,
    CLIENT_LOG_TRUNCATION_LIMITS,
    CSRF_EXPIRED_MESSAGE,
    TOO_MANY_ATTEMPTS_MESSAGE,
    UPLOAD_MAX_BYTES,
    UPLOAD_MAX_MB,
    UPLOAD_TOO_LARGE_MESSAGE,
    SafeUserPayloadError,
    _add_months_to_date,
    _api_error_response,
    _coerce_text_payload_value,
    _editable_pdf_name,
    _format_display_name,
    _log_api_error,
    _mask_sensitive_fields,
    _mask_username_for_log,
    _parse_duration_expiry_value,
    _render_create_supervisor_page,
    _request_error_context,
    _resolve_certificate_expiry,
    _safe_user_error,
    _sanitize_search_term,
    _truncate_log_value,
    render_markdown_content,
)
from web.routes_admin import register_admin_routes
from web.routes_public import register_public_routes
from web.routes_supervisor import register_supervisor_routes
from web.routes_user import register_user_routes


ensure_csrf_token = sec.ensure_csrf_token
validate_csrf_token = sec.validate_csrf_token
save_pdf_for_user = pdf.save_pdf_for_user


logger = configure_module_logger(__name__)


def _trusted_proxy_hops(raw_value: str | None) -> int:
    # Behåll wrappern i app.py så testsviten kan monkeypatcha just denna yta.
    return bootstrap.trusted_proxy_hops(raw_value)


def _configure_proxy_fix(app: Flask) -> None:
    # Wrappern använder _trusted_proxy_hops ovan för att bevara tidigare testkrok.
    hops = _trusted_proxy_hops(os.getenv("TRUSTED_PROXY_COUNT"))
    bootstrap.apply_proxy_fix(app, hops)


def _configure_timezone() -> str:
    return bootstrap.configure_timezone()


def _enable_debug_mode(app: Flask) -> None:
    bootstrap.enable_debug_mode(app)


def _is_pytest_running() -> bool:
    return bootstrap.is_pytest_running()


def _resolve_secret_key() -> str:
    return bootstrap.resolve_secret_key(_is_pytest_running)


def create_app() -> Flask:
    # app.py är nu ett tunt kompositionslager som monterar delmodulerna.
    logger.debug("Applikationen initieras")
    logger.debug("Laddar miljövariabler och initierar databas")
    functions.create_database()

    app = Flask(__name__)
    timezone_name = _configure_timezone()
    app.config["APP_TIMEZONE"] = timezone_name
    _configure_proxy_fix(app)

    app.secret_key = _resolve_secret_key()
    app.config["MAX_CONTENT_LENGTH"] = UPLOAD_MAX_BYTES

    dev_mode = as_bool(os.getenv("DEV_MODE"))
    debug_mode = dev_mode
    app.config["DEV_MODE"] = dev_mode
    app.config["DEBUG"] = debug_mode
    if not dev_mode:
        root_logger = logging.getLogger()
        if root_logger.getEffectiveLevel() < logging.INFO:
            root_logger.setLevel(logging.INFO)
        app.logger.setLevel(logging.INFO)
        logger.setLevel(logging.INFO)
        functions.logger.setLevel(logging.INFO)

    logger.debug("Utvecklingsläge: %s", debug_mode)

    with app.app_context():
        if debug_mode:
            _enable_debug_mode(app)

    bootstrap.register_app_lifecycle(app)
    register_public_routes(app)
    register_supervisor_routes(app)
    register_user_routes(app)
    register_admin_routes(app)
    register_error_handlers(app)

    logger.debug("Applikationen är konfigurerad och redo")
    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    debug_mode = as_bool(os.getenv("DEV_MODE"))
    logger.critical(
        "Starting app from app.py, Debug is %s", "ENABLED" if debug_mode else "DISABLED"
    )

    try:
        app.run(
            debug=debug_mode,
            host="0.0.0.0",
            port=int(os.getenv("PORT", 8000)),
        )
    except KeyboardInterrupt:
        logger.info("Applikationen avbröts av användaren")
        try:
            critical_events.send_crash_notification(
                "Application interrupted by user (KeyboardInterrupt)"
            )
        except Exception as exc:
            logger.critical("Misslyckades med att skicka kraschnotifikation: %s", exc)
            critical_events.send_crash_notification(
                "Misslyckades med att skicka kraschnotifikation: " + str(exc)
            )
    except Exception as exc:
        logger.critical("Applikationen kraschade med undantag: %s", exc, exc_info=True)
        try:
            error_details = f"Exception: {type(exc).__name__}\nMessage: {str(exc)}"
            critical_events.send_crash_notification(error_details)
        except Exception as alert_error:
            logger.critical("Misslyckades med att skicka kraschnotifikation: %s", alert_error)
        raise


# Copyright (c) Liam Suorsa and Mika Suorsa
