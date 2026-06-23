# Copyright (c) Liam Suorsa and Mika Suorsa
"""Felsidor och felhantering för Flask-appen."""

from __future__ import annotations

import time

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException

from functions.logging import configure_module_logger
from functions.notifications import critical_events
from functions.requests import get_request_ip

from web.helpers import UPLOAD_TOO_LARGE_MESSAGE


logger = configure_module_logger("app")


def error():  # pragma: no cover
    # Den här routen finns kvar som avsiktlig testkrok för 500-sidan.
    raise Exception("Testing 500 error page")


def internal_server_error(_):  # pragma: no cover
    logger.error("500 Internt serverfel: %s", request.path)

    try:
        user_ip = get_request_ip()
        endpoint = request.path
        error_msg = f"Endpoint: {endpoint}\nMetod: {request.method}\nIP: {user_ip}"
        critical_events.send_critical_error_notification(
            error_message=error_msg,
            endpoint=endpoint,
            user_ip=user_ip,
        )
    except Exception as exc:
        logger.warning("Kunde inte skicka error-notifikation: %s", exc)

    error_code = 500
    error_message = "Ett internt serverfel har inträffat. Vänligen försök igen senare."
    return render_template(
        "error.html",
        error_code=error_code,
        error_message=error_message,
        time=time.time(),
    ), 500


def handle_unexpected_exception(error: Exception):  # pragma: no cover
    if isinstance(error, HTTPException):
        return error
    logger.error("Oväntat fel inträffade: %s", str(error))
    return internal_server_error(error)


def unauthorized_error(_):  # pragma: no cover
    logger.warning("401 Obehörig åtkomst: %s", request.path)
    error_code = 401
    error_message = "Du måste vara inloggad för att se denna sida."
    return render_template(
        "error.html",
        error_code=error_code,
        error_message=error_message,
        time=time.time(),
    ), 401


def conflict_error(_):  # pragma: no cover
    logger.error("409 Konflikt: %s", request.path)
    error_code = 409
    error_message = "Det uppstod en konflikt vid hantering av din begäran."
    return render_template(
        "error.html",
        error_code=error_code,
        error_message=error_message,
        time=time.time(),
    ), 409


def request_entity_too_large(_):  # pragma: no cover
    # Uppladdningsgränsen visas olika beroende på om klienten väntar JSON eller HTML-flöde.
    logger.warning("413 För stor uppladdning: %s", request.path)
    endpoint = request.endpoint or ""
    if endpoint.startswith("admin") or request.path == "/admin" or request.path.startswith("/admin/"):
        return jsonify({"status": "error", "message": UPLOAD_TOO_LARGE_MESSAGE}), 413
    if endpoint in {"user_upload_page", "user_upload_pdf_route"} or request.path in {
        "/dashboard/ladda-upp",
        "/dashboard/upload",
    } or request.path.startswith("/dashboard/ladda-upp/") or request.path.startswith(
        "/dashboard/upload/"
    ):
        flash(UPLOAD_TOO_LARGE_MESSAGE, "error")
        return redirect(url_for("user_upload_page"))

    error_code = 413
    error_message = UPLOAD_TOO_LARGE_MESSAGE
    return render_template(
        "error.html",
        error_code=error_code,
        error_message=error_message,
        time=time.time(),
    ), 413


def page_not_found(_):  # pragma: no cover
    logger.warning("Sidan hittades inte: %s", request.path)
    error_code = 404
    error_message = "Sidan du letade efter kunde inte hittas."
    return render_template(
        "error.html",
        error_code=error_code,
        error_message=error_message,
        time=time.time(),
    ), 404


def datetimeformat(value, format="%Y-%m-%d %H:%M:%S"):  # pragma: no cover
    import datetime

    return datetime.datetime.fromtimestamp(value).strftime(format)


def register_error_handlers(app: Flask) -> None:
    app.add_url_rule("/error", view_func=error)
    app.register_error_handler(500, internal_server_error)
    app.register_error_handler(Exception, handle_unexpected_exception)
    app.register_error_handler(401, unauthorized_error)
    app.register_error_handler(409, conflict_error)
    app.register_error_handler(413, request_entity_too_large)
    app.register_error_handler(404, page_not_found)
    app.add_template_filter(datetimeformat, "datetimeformat")


# Copyright (c) Liam Suorsa and Mika Suorsa
