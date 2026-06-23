# Copyright (c) Liam Suorsa and Mika Suorsa
"""Bootstrap och livscykelhooks för Flask-appen."""

from __future__ import annotations

from datetime import timedelta
import logging
import os
import sys
import time
import traceback
from typing import Callable

from flask import Flask, Response, current_app, g, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

from config_loader import load_environment
import functions
from functions.logging import (
    configure_module_logger,
    configure_root_logging,
    mask_headers,
    mask_sensitive_data,
)
from functions.notifications import critical_events
from functions.requests import as_bool, get_request_ip


logger = configure_module_logger("app")


def initialize_runtime() -> None:
    # Miljö och root logging måste vara klara innan vi skapar appen eller
    # importerar routes som förväntar sig konfigurerad loggning.
    load_environment()
    configure_root_logging()


def trusted_proxy_hops(raw_value: str | None) -> int:
    default_hops = 1
    if raw_value is None or raw_value.strip() == "":
        return default_hops

    try:
        hops = int(raw_value)
    except ValueError:
        logger.warning(
            "Ogiltigt värde för TRUSTED_PROXY_COUNT (%s) – använder standardvärdet 1.",
            raw_value,
        )
        return default_hops

    if hops < 0:
        logger.warning("TRUSTED_PROXY_COUNT kan inte vara negativt – proxystödet stängs av.")
        return 0

    return hops


def apply_proxy_fix(app: Flask, hops: int) -> None:
    # ProxyFix aktiveras bara när vi uttryckligen litar på inkommande proxylager.
    if hops > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=hops,
            x_proto=hops,
            x_host=hops,
            x_port=hops,
        )
        logger.info("ProxyFix är aktiverad med betrodda proxyhopp.")
        return

    logger.info("ProxyFix är inaktiverad.")


def configure_timezone() -> str:
    timezone_name = os.getenv("APP_TIMEZONE", "Europe/Stockholm").strip() or "Europe/Stockholm"
    os.environ["TZ"] = timezone_name
    tzset = getattr(time, "tzset", None)
    if callable(tzset):
        tzset()
    logger.info("Applikationens tidszon är satt till %s.", timezone_name)
    return timezone_name


def enable_debug_mode(app: Flask) -> None:
    # DEV_MODE styr den mer pratsamma lokala felsökningsloggningen.
    if not as_bool(os.getenv("DEV_MODE")):
        return

    stream = logging.StreamHandler()
    root = logging.getLogger()
    if not any(isinstance(handler, logging.StreamHandler) for handler in root.handlers):
        root.addHandler(stream)
    root.setLevel(logging.DEBUG)

    if not any(isinstance(handler, logging.StreamHandler) for handler in app.logger.handlers):
        app.logger.addHandler(stream)
    app.logger.setLevel(logging.DEBUG)

    logger.setLevel(logging.DEBUG)
    functions.logger.setLevel(logging.DEBUG)
    if not any(
        isinstance(handler, logging.StreamHandler) for handler in functions.logger.handlers
    ):
        functions.logger.addHandler(stream)

    functions.logger.debug("Utvecklingsläge är aktiverat")
    logger.debug("Utvecklingsläge är aktiverat")


def is_pytest_running() -> bool:
    return "PYTEST_CURRENT_TEST" in os.environ or any("pytest" in arg for arg in sys.argv)


def resolve_secret_key(is_pytest_running_func: Callable[[], bool]) -> str:
    secret_key = os.getenv("secret_key")
    if secret_key:
        return secret_key
    if is_pytest_running_func() and as_bool(os.getenv("DEV_MODE")):
        logger.warning("secret_key saknas i testmiljön. Genererar temporär nyckel.")
        return os.urandom(32).hex()
    error_msg = "KRITISKT: miljövariabeln secret_key måste vara satt och inte tom"
    logger.critical(error_msg)
    raise RuntimeError(error_msg)


def _before_first_request() -> None:
    session.permanent = True
    current_app.permanent_session_lifetime = timedelta(days=178)


def _log_request_start() -> None:
    if is_pytest_running():
        return

    if request.endpoint in ("health", "robots_txt"):
        return

    g.request_start = time.monotonic()
    g.view_start = g.request_start
    view_func = current_app.view_functions.get(request.endpoint) if request.endpoint else None
    if view_func:
        g.view_func_name = view_func.__name__
        logger.debug(
            "Vy startar: %s args=%s",
            view_func.__name__,
            mask_sensitive_data(request.view_args or {}),
        )

    client_ip = get_request_ip()
    logger.debug(
        "Begäran startad: %s %s (IP=%s, agent=%s)",
        request.method,
        request.path,
        mask_hash(client_ip) if client_ip else "okänd",
        request.headers.get("User-Agent", "okänd"),
    )
    logger.debug("Begäran headers: %s", mask_headers(dict(request.headers)))
    logger.debug(
        "Begäran query-parametrar: %s",
        mask_sensitive_data(request.args.to_dict(flat=False)),
    )
    if request.is_json:
        logger.debug("Begäran JSON-body: %s", mask_sensitive_data(request.get_json(silent=True)))


def _log_request_end(response: Response) -> Response:
    if is_pytest_running():
        return response

    if request.endpoint in ("health", "robots_txt", "sitemap_xml"):
        return response

    start = getattr(g, "request_start", None)
    duration = time.monotonic() - start if isinstance(start, (int, float)) else 0.0
    status_code = response.status_code
    if status_code >= 500:
        level = logging.ERROR
    elif status_code >= 400:
        level = logging.WARNING
    else:
        level = logging.INFO

    logger.log(
        level,
        "Begäran slutförd: %s %s -> %s (%.3fs)",
        request.method,
        request.path,
        status_code,
        duration,
    )
    logger.debug("Svar headers: %s", mask_headers(dict(response.headers)))
    if response.is_json:
        logger.debug("Svar JSON-body: %s", mask_sensitive_data(response.get_json(silent=True)))

    view_start = getattr(g, "view_start", None)
    view_duration = time.monotonic() - view_start if isinstance(view_start, (int, float)) else 0.0
    view_func_name = getattr(g, "view_func_name", None)
    if view_func_name:
        logger.debug("Vy avslutad: %s (%.3fs)", view_func_name, view_duration)
    return response


def _log_request_exception(exception: BaseException | None) -> None:
    if exception is not None:
        logger.error("Undantag under begäran: %s", str(exception))


def _teardown(exception: BaseException | None = None) -> None:
    # Här skickar vi bara kraschnotis när appkontexten verkligen stängs med fel.
    if exception is None:
        return

    logger.error("Applikation stängs ner på grund av exception: %s", str(exception))
    try:
        critical_events.send_crash_notification(
            error_message=str(exception),
            traceback=traceback.format_exc(),
        )
    except Exception as alert_error:
        logger.warning("Kunde inte skicka crash-notifikation: %s", str(alert_error))


def register_app_lifecycle(app: Flask) -> None:
    app.before_request(_before_first_request)
    app.before_request(_log_request_start)
    app.after_request(_log_request_end)
    app.teardown_request(_log_request_exception)
    app.teardown_appcontext(_teardown)


# Copyright (c) Liam Suorsa and Mika Suorsa
