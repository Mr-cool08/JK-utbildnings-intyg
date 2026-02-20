# Copyright (c) Liam Suorsa
# Flask application for issuing and serving course certificates.

from __future__ import annotations

from datetime import timedelta
import atexit
from functools import partial
import importlib
import importlib.util
import logging
import os
import secrets
import sys
from pathlib import Path
import threading
import time
from typing import Any, Sequence
import json

from flask import (
    Flask,
    Response,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    send_from_directory,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from config_loader import load_environment
from functions.logging import (
    configure_module_logger,
    configure_root_logging,
    mask_email,
    mask_hash,
    mask_headers,
    mask_sensitive_data,
)

from course_categories import (
    COURSE_CATEGORIES,
    COURSE_CATEGORY_GROUPS,
    labels_for_slugs,
    normalize_category_slugs,
)

from functions.emails import service as email_service
from functions.pdf import service as pdf
from functions.notifications import critical_events
from functions import security as sec
from functions.requests import as_bool, get_request_ip, register_public_submission


configure_root_logging()
load_environment()

import functions

ensure_csrf_token = sec.ensure_csrf_token
validate_csrf_token = sec.validate_csrf_token
save_pdf_for_user = pdf.save_pdf_for_user


logger = configure_module_logger(__name__)
logger.setLevel(logging.INFO)


def _render_create_supervisor_page(error: str | None = None, invalid: bool = False, **extra) -> Response:
    """Returnerar render_template för create_supervisor/create_user-sidor med standard-kwargs.

    Detta förenklar upprepade anrop som tidigare skickade samma kwargs flera gånger.
    """
    common = {
        "invalid": invalid,
        "page_title": "Skapa konto",
        "heading": "Skapa konto",
        "description": (
            "Välj ett starkt lösenord för ditt konto. "
            "Lösenordet måste vara minst åtta tecken långt."
        ),
        "submit_text": "Skapa konto",
    }
    common.update(extra or {})
    if error:
        common["error"] = error
    return render_template("create_supervisor.html", **common)


def _render_basic_markdown(text: str) -> str:
    rendered_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## "):
            rendered_lines.append(f"<h2>{stripped[3:].strip()}</h2>")
            continue
        if stripped.startswith("# "):
            rendered_lines.append(f"<h1>{stripped[2:].strip()}</h1>")
            continue
        if stripped:
            rendered_lines.append(f"<p>{stripped}</p>")
    return "\n".join(rendered_lines)


def render_markdown_content(text: str) -> Markup:
    markdown_spec = importlib.util.find_spec("markdown")
    if markdown_spec is None:
        logger.warning("Markdown-biblioteket saknas, använder enkel renderare.")
        return Markup(_render_basic_markdown(text))
    markdown_module = importlib.import_module("markdown")
    rendered = markdown_module.markdown(text, extensions=["extra"])
    return Markup(rendered)


ALLOWED_PDF_UPLOAD_ERRORS = {
    "Ingen fil vald.",
    "Endast PDF, PNG eller JPG tillåts.",
    "Filen verkar inte vara en giltig PDF.",
    "Exakt en kurskategori måste väljas.",
    "Bilden kunde inte konverteras till PDF.",
    "PDF:en blockerades av säkerhetsskannern.",
}
ALLOWED_SUPERVISOR_ACTIVATION_ERRORS = {
    "Lösenordet måste vara minst 8 tecken.",
}
ALLOWED_ADMIN_APPROVAL_ERRORS = {
    "Ansökan hittades inte.",
    "Ansökan är redan hanterad.",
    "Ansökan saknar personnummer och kan inte godkännas.",
    "E-postadressen är redan registrerad.",
    "Företagsnamn saknas för detta organisationsnummer.",
}
ALLOWED_ADMIN_REJECTION_ERRORS = {
    "Ansökan hittades inte.",
    "Ansökan är redan hanterad.",
}

CLIENT_LOG_TRUNCATION_LIMITS = {
    "message": 500,
    "context": 200,
    "url": 500,
    "details": 1000,
}

# Gemensamma användarmeddelanden
CSRF_EXPIRED_MESSAGE = "Formuläret är inte längre giltigt. Ladda om sidan och försök igen."
TOO_MANY_ATTEMPTS_MESSAGE = "Du har gjort för många försök. Vänta en stund och prova igen."


def _safe_user_error(message: str, allowed: set[str], fallback: str) -> str:
    # Returnera bara godkända felmeddelanden till användaren.
    cleaned = (message or "").strip()
    if cleaned in allowed:
        return cleaned
    return fallback


def _truncate_log_value(value: Any, limit: int) -> str:
    # Begränsa loggsträngar för att undvika enorma loggar.
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}…"


def _trusted_proxy_hops(raw_value: str | None) -> int:
    # Tolka TRUSTED_PROXY_COUNT och hantera ogiltiga värden på ett säkert sätt.
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
        logger.warning(
            "TRUSTED_PROXY_COUNT kan inte vara negativt – proxystödet stängs av.",
        )
        return 0

    return hops


def _configure_proxy_fix(app: Flask) -> None:
    # Aktivera ProxyFix så att Flask litar på headers från den externa proxyn.
    hops = _trusted_proxy_hops(os.getenv("TRUSTED_PROXY_COUNT"))
    if hops > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=hops,
            x_proto=hops,
            x_host=hops,
            x_port=hops,
        )
        logger.info("Aktiverar ProxyFix med %s betrodda proxyhopp", mask_hash(str(hops)))
    else:
        logger.info(
            "ProxyFix är inaktiverad (TRUSTED_PROXY_COUNT=%s)",
            os.getenv("TRUSTED_PROXY_COUNT", "0"),
        )


def _configure_timezone() -> str:
    # Sätt applikationens lokala tidszon för all datum/tid-formattering.
    timezone_name = os.getenv("APP_TIMEZONE", "Europe/Stockholm").strip() or "Europe/Stockholm"
    os.environ["TZ"] = timezone_name
    if hasattr(time, "tzset"):
        time.tzset()
    logger.info("Applikationens tidszon är satt till %s.", timezone_name)
    return timezone_name




def _enable_debug_mode(app: Flask) -> None:
    # Aktivera extra loggning och ev. testdata i debug-läge.
    stream = logging.StreamHandler()
    root = logging.getLogger()
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        root.addHandler(stream)
    root.setLevel(logging.DEBUG)

    if not any(isinstance(h, logging.StreamHandler) for h in app.logger.handlers):
        app.logger.addHandler(stream)
    app.logger.setLevel(logging.DEBUG)

    logger.setLevel(logging.DEBUG)
    functions.logger.setLevel(logging.DEBUG)
    if not any(isinstance(h, logging.StreamHandler) for h in functions.logger.handlers):
        functions.logger.addHandler(stream)

    functions.logger.debug("Debug mode is on")
    logger.debug("Debug mode is on")
    # Skapa testanvändare endast i debug-läge
    functions.create_test_user()
    print("Debug mode is on, test user created")


def _start_demo_reset_scheduler(app: Flask, demo_defaults: dict[str, str]) -> None:
    # Start a bakgrundstråd som återställer demodatabasen var femte minut.
    interval_seconds = 10 * 60

    # Lock to prevent concurrent database access during reset
    reset_lock = threading.Lock()

    # Store as app config so error handlers can check reset status
    app.demo_reset_lock = reset_lock

    def _reset_loop() -> None:
        logger.info("Bakgrundsjobb för demoreset startat")
        while True:
            # Only run reset if no other thread is actively using it
            if reset_lock.acquire(blocking=False):
                try:
                    with app.app_context():
                        logger.info("Bakgrundsjobb kör demoreset")
                        if functions.reset_demo_database(demo_defaults):
                            logger.info("Demoreset slutfördes framgångsrikt")
                        else:
                            logger.warning("Demoreset returnerade false")
                except Exception as exc:
                    logger.exception("Automatisk demoreset misslyckades: %s", exc)
                finally:
                    reset_lock.release()
            else:
                logger.debug("Demoreset hoppad över - låst för närvarande")

            time.sleep(interval_seconds)

    thread = threading.Thread(target=_reset_loop, daemon=True, name="demo-reset-loop")
    thread.start()
    logger.info("Bakgrundstråd startad: %s", thread.name)


def _is_pytest_running() -> bool:
    return "PYTEST_CURRENT_TEST" in os.environ or any("pytest" in arg for arg in sys.argv)


def _resolve_secret_key() -> str:
    secret_key = os.getenv("secret_key")
    if secret_key:
        return secret_key
    if _is_pytest_running() and as_bool(os.getenv("DEV_MODE")):
        logger.warning("secret_key saknas i testmiljön. Genererar temporär nyckel.")
        return secrets.token_hex(32)
    error_msg = "FATAL: secret_key environment variable must be set and non-empty"
    logger.critical(error_msg)
    
    raise RuntimeError(error_msg)


def create_app() -> Flask:
    # Create and configure the Flask application.
    logger.debug("Applikationen initieras")
    logger.debug("Loading environment variables and initializing database")
    functions.create_database()
    app = Flask(__name__)
    timezone_name = _configure_timezone()
    app.config["APP_TIMEZONE"] = timezone_name
    _configure_proxy_fix(app)

    # Validate secret_key is set
    app.secret_key = _resolve_secret_key()

    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB
    dev_mode = as_bool(os.getenv("DEV_MODE"))
    debug_mode = dev_mode
    app.config["DEBUG"] = debug_mode
    logger.debug("Debug mode: %s", debug_mode)

    demo_defaults = {
        "user_email": os.getenv("DEMO_USER_EMAIL", "demo.anvandare@example.com"),
        "user_name": os.getenv("DEMO_USER_NAME", "Demoanvändare"),
        "user_personnummer": os.getenv("DEMO_USER_PERSONNUMMER", "199001011234"),
        "user_password": os.getenv("DEMO_USER_PASSWORD", "DemoLösenord1!"),
        "supervisor_email": os.getenv("DEMO_SUPERVISOR_EMAIL", "demo.foretagskonto@example.com"),
        "supervisor_name": os.getenv("DEMO_SUPERVISOR_NAME", "Demoföretagskonto"),
        "supervisor_password": os.getenv("DEMO_SUPERVISOR_PASSWORD", "DemoForetagskonto1!"),
        "supervisor_orgnr": os.getenv("DEMO_SUPERVISOR_ORGNR", "5569668337"),
    }

    app.config["IS_DEMO"] = as_bool(os.getenv("ENABLE_DEMO_MODE"))
    app.config["DEMO_SITE_URL"] = os.getenv("DEMO_SITE_URL", "").strip()
    app.config["DEMO_CREDENTIALS"] = {
        "user_personnummer": demo_defaults["user_personnummer"],
        "user_password": demo_defaults["user_password"],
        "supervisor_email": demo_defaults["supervisor_email"],
        "supervisor_orgnr": demo_defaults["supervisor_orgnr"],
        "supervisor_password": demo_defaults["supervisor_password"],
    }
    app.config["DEMO_DEFAULTS"] = demo_defaults

    should_seed_demo_accounts = app.config["IS_DEMO"] or dev_mode
    if should_seed_demo_accounts:
        if app.config["IS_DEMO"]:
            logger.info("Demoläge aktiverat – initierar exempeldata")
        else:
            logger.info("Utvecklingsläge aktiverat – initierar demokonton utan demoläge")
        functions.ensure_demo_data(
            user_email=demo_defaults["user_email"],
            user_name=demo_defaults["user_name"],
            user_personnummer=demo_defaults["user_personnummer"],
            user_password=demo_defaults["user_password"],
            supervisor_email=demo_defaults["supervisor_email"],
            supervisor_name=demo_defaults["supervisor_name"],
            supervisor_password=demo_defaults["supervisor_password"],
            supervisor_orgnr=demo_defaults["supervisor_orgnr"],
        )
    if app.config["IS_DEMO"]:
        _start_demo_reset_scheduler(app, demo_defaults)

    with app.app_context():
        if debug_mode:
            _enable_debug_mode(app)

    logger.debug("Application created and database initialized")
    # Email handlers for ERROR and CRITICAL logs are now automatically attached
    # via configure_root_logging() in functions.logging module.

    # Startup email is sent from the first request handler to avoid duplicate
    # notifications from multiple app creation points (reloader or multiple workers).
    logger.debug("Applikationen är konfigurerad och redo")
    return app


def _register_shutdown_hook() -> None:
    # Registrera en hook som alltid försöker logga nedstängning.
    def _shutdown() -> None:
        logging.raiseExceptions = False
        logger.debug("Applikationen håller på att stängas ner")
        _send_shutdown_notification()

    atexit.register(_shutdown)


app = create_app()
_register_shutdown_hook()


@app.before_request
def _before_first_request():
    # Send startup notification once when the app starts
    if not hasattr(app, "_startup_notification_sent"):
        try:
            import socket

            hostname = socket.gethostname()
        except Exception:
            hostname = "Unknown"

        try:
            critical_events.send_startup_notification(hostname=hostname)
            setattr(app, "_startup_notification_sent", True)
            logger.info("Startupp-notifikation skickad")
        except Exception as e:
            logger.warning("Kunde inte skicka startupp-notifikation: %s", str(e))
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=178)


@app.before_request
def _log_request_start() -> None:
    # Skip logging for health check endpoint and other non-essential endpoints
    if request.endpoint in ("health", "robots_txt"):
        return
    
    g.request_start = time.monotonic()
    g.view_start = g.request_start
    view_func = app.view_functions.get(request.endpoint) if request.endpoint else None
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
    logger.debug(
        "Begäran headers: %s",
        mask_headers(dict(request.headers)),
    )
    logger.debug(
        "Begäran query-parametrar: %s",
        mask_sensitive_data(request.args.to_dict(flat=False)),
    )
    if request.is_json:
        logger.debug(
            "Begäran JSON-body: %s",
            mask_sensitive_data(request.get_json(silent=True)),
        )


@app.after_request
def _log_request_end(response: Response) -> Response:
    # Skip logging for health check endpoint and other non-essential endpoints
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
    logger.debug(
        "Svar headers: %s",
        mask_headers(dict(response.headers)),
    )
    if response.is_json:
        logger.debug(
            "Svar JSON-body: %s",
            mask_sensitive_data(response.get_json(silent=True)),
        )
    view_start = getattr(g, "view_start", None)
    view_duration = time.monotonic() - view_start if isinstance(view_start, (int, float)) else 0.0
    view_func_name = getattr(g, "view_func_name", None)
    if view_func_name:
        logger.debug(
            "Vy avslutad: %s (%.3fs)",
            view_func_name,
            view_duration,
        )
    return response


@app.teardown_request
def _log_request_exception(exception: Exception | None) -> None:
    if exception is not None:
        logger.exception("Undantag under begäran: %s", str(exception))


def _send_shutdown_notification():
    # Send shutdown notification when the app is shutting down
    try:
        critical_events.send_shutdown_notification(reason="Applikationen stängs ner")
        logger.info("Nedstängning-notifikation skickad")
    except Exception as e:
        logger.warning("Kunde inte skicka nedstängning-notifikation: %s", str(e))


@app.teardown_appcontext
def _teardown(exception=None):
    # Called when the app context is being torn down
    if exception is not None:
        logger.error("Applikation stängs ner på grund av exception: %s", str(exception))
        try:
            critical_events.send_crash_notification(
                error_message=str(exception), traceback=__import__("traceback").format_exc()
            )
        except Exception as e:
            logger.warning("Kunde inte skicka crash-notifikation: %s", str(e))


@app.route("/health")
def health() -> tuple[dict, int]:
    # Basic health check endpoint.
    return {"status": "ok"}, 200


def _require_admin() -> str:
    if not session.get("admin_logged_in"):
        abort(403)
    return session.get("admin_username", "okänd")


def _require_supervisor() -> tuple[str, str]:
    if not session.get("supervisor_logged_in"):
        abort(403)
    email_hash = session.get("supervisor_email_hash")
    if not email_hash:
        abort(403)
    supervisor_name = session.get("supervisor_name") or functions.get_supervisor_name_by_hash(
        email_hash
    )
    if supervisor_name:
        session["supervisor_name"] = supervisor_name
    return email_hash, supervisor_name or "Företagskonto"


@app.context_processor
def inject_flags():
    # Expose flags indicating debug and demo-läge to Jinja templates.
    host = request.host
    if host.startswith("demo."):
        host = host[len("demo.") :]
    main_site_url = f"{request.scheme}://{host}"
    return {
        "IS_DEV": current_app.debug,
        "IS_DEMO": current_app.config.get("IS_DEMO", False),
        "DEMO_SITE_URL": current_app.config.get("DEMO_SITE_URL", ""),
        "DEMO_CREDENTIALS": current_app.config.get("DEMO_CREDENTIALS", {}),
        "MAIN_SITE_URL": main_site_url,
    }


@app.route("/robots.txt")
def robots_txt():
    # Serve robots.txt to disallow all crawlers.
    if app.static_folder is None:
        abort(404)
    return send_from_directory(app.static_folder, "robots.txt", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    # Serve sitemap.xml with public URLs only.
    if app.static_folder is None:
        abort(404)
    return send_from_directory(app.static_folder, "sitemap.xml", mimetype="application/xml")


@app.route("/debug/clear-session", methods=["GET", "POST"])
def debug_clear_session():
    if not current_app.config.get("DEV_MODE"):
        abort(404)
    session.clear()
    return redirect("/")


@app.route("/create_user/<pnr_hash>", methods=["POST", "GET"])
def create_user(pnr_hash: str):  # type: ignore[no-untyped-def]
    # Allow a pending user to set a password and activate the account.
    logger.info("Handling create_user for hash %s", pnr_hash)
    if request.method == "POST":
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()
        if password != confirm:
            return _render_create_supervisor_page(error="Lösenorden måste matcha.", invalid=False)
        if len(password) < 8:
            return _render_create_supervisor_page(error="Lösenordet måste vara minst 8 tecken långt.", invalid=False)
        logger.debug("Creating user with hash %s", pnr_hash)
        if not functions.user_create_user(password, pnr_hash):
            logger.warning("Kunde inte skapa användare för hash %s", pnr_hash)
            return _render_create_supervisor_page(
                error=("Kontot kunde inte aktiveras. Kontrollera att länken är giltig."),
                invalid=False,
            )
        return redirect("/login")
    if functions.check_pending_user_hash(pnr_hash):
        return render_template(
            "create_supervisor.html",
            invalid=False,
            page_title="Skapa konto",
            heading="Skapa konto",
            description=(
                "Välj ett starkt lösenord för ditt konto. "
                "Lösenordet måste vara minst åtta tecken långt."
            ),
            submit_text="Skapa konto",
            invalid_message="Länken är ogiltig eller har redan använts.",
        )
    logger.warning("User hash %s not found during create_user", pnr_hash)
    abort(404, description="Standardkonto hittades inte")


@app.route("/foretagskonto/skapa/<email_hash>", methods=["GET", "POST"])
def supervisor_create(email_hash: str):
    logger.info("Handling supervisor creation for hash %s", email_hash)
    if request.method == "POST":
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()
        if password != confirm:
            return render_template(
                "create_supervisor.html",
                error="Lösenorden måste matcha.",
                invalid=False,
            )
        try:
            if not functions.supervisor_activate_account(email_hash, password):
                return render_template(
                    "create_supervisor.html",
                    error="Kontot kunde inte aktiveras. Kontrollera att länken är giltig.",
                    invalid=False,
                )
        except ValueError as exc:
            return render_template(
                "create_supervisor.html",
                error=_safe_user_error(
                    str(exc),
                    ALLOWED_SUPERVISOR_ACTIVATION_ERRORS,
                    (
                        "Kontot kunde inte aktiveras. Kontrollera att länken är giltig "
                        "och att lösenordet uppfyller kraven."
                    ),
                ),
                invalid=False,
            )
        logger.info("Supervisor account activated for %s", email_hash)
        return redirect(url_for("supervisor_login"))

    if functions.check_pending_supervisor_hash(email_hash):
        return render_template("create_supervisor.html", invalid=False)
    logger.warning("Supervisor hash %s not found during activation", email_hash)
    return render_template("create_supervisor.html", invalid=True)


@app.route("/foretagskonto/login", methods=["GET", "POST"])
def supervisor_login():
    csrf_token = sec.ensure_csrf_token()
    if request.method == "POST":
        if not validate_csrf_token():
            logger.warning("Ogiltig CSRF-token vid företagskontoinloggning")
            return (
                render_template(
                    "supervisor_login.html",
                    error="Formuläret är inte längre giltigt. Ladda om sidan och försök igen.",
                    csrf_token=csrf_token,
                ),
                400,
            )
        orgnr = request.form.get("orgnr", "").strip()
        password = request.form.get("password", "").strip()
        if not orgnr or not password:
            return render_template(
                "supervisor_login.html",
                error="Ogiltiga inloggningsuppgifter.",
                csrf_token=csrf_token,
            )
        try:
            normalized_orgnr = functions.validate_orgnr(orgnr)
        except ValueError:
            logger.warning("Ogiltigt organisationsnummer vid företagskontoinloggning")
            return render_template(
                "supervisor_login.html",
                error="Ogiltiga inloggningsuppgifter.",
                csrf_token=csrf_token,
            )

        details = functions.get_supervisor_login_details_for_orgnr(normalized_orgnr)
        if not details:
            logger.warning(
                "Företagskonto saknas för organisationsnummer %s",
                mask_hash(functions.hash_value(normalized_orgnr)),
            )
            return render_template(
                "supervisor_login.html",
                error="Ogiltiga inloggningsuppgifter.",
                csrf_token=csrf_token,
            )

        normalized_email = details["email"]
        email_hash = details["email_hash"]
        try:
            valid = functions.verify_supervisor_credentials(normalized_email, password)
        except ValueError:
            logger.warning(
                "Ogiltig kontokonfiguration vid företagskontoinloggning för %s",
                mask_hash(functions.hash_value(normalized_orgnr)),
            )
            return render_template(
                "supervisor_login.html",
                error="Ogiltiga inloggningsuppgifter.",
                csrf_token=csrf_token,
            )
        if not valid:
            logger.warning(
                "Felaktigt lösenord för företagskonto %s",
                mask_hash(functions.hash_value(normalized_orgnr)),
            )
            return render_template(
                "supervisor_login.html",
                error="Ogiltiga inloggningsuppgifter.",
                csrf_token=csrf_token,
            )

        session["supervisor_logged_in"] = True
        session["supervisor_email_hash"] = email_hash
        session["supervisor_orgnr"] = normalized_orgnr
        supervisor_name = details.get("name") or functions.get_supervisor_name_by_hash(email_hash)
        if supervisor_name:
            session["supervisor_name"] = supervisor_name
        logger.info(
            "Supervisor %s loggade in för organisationsnummer %s",
            mask_hash(email_hash),
            mask_hash(functions.hash_value(normalized_orgnr)),
        )
        return redirect(url_for("supervisor_dashboard"))

    return render_template("supervisor_login.html", csrf_token=csrf_token)


@app.route("/foretagskonto", methods=["GET"])
def supervisor_dashboard():
    if not session.get("supervisor_logged_in"):
        return redirect(url_for("supervisor_login"))
    email_hash, supervisor_name = _require_supervisor()
    csrf_token = sec.ensure_csrf_token()
    connections = functions.list_supervisor_connections(email_hash)
    users = []
    for entry in connections:
        person_hash = entry["personnummer_hash"]
        username = (entry.get("username") or "Standardkonto").strip()
        pdfs = functions.get_user_pdfs(person_hash)
        for pdf in pdfs:
            pdf["category_labels"] = labels_for_slugs(pdf.get("categories") or [])
        users.append(
            {
                "personnummer_hash": person_hash,
                "username": username,
                "pdfs": pdfs,
            }
        )

    return render_template(
        "supervisor_dashboard.html",
        supervisor_name=supervisor_name,
        users=users,
        csrf_token=csrf_token,
    )


@app.post("/foretagskonto/kopplingsforfragan")
def supervisor_link_request_route():
    email_hash, _ = _require_supervisor()
    if not validate_csrf_token(allow_if_absent=True):
        flash("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.", "error")
        return redirect(url_for("supervisor_dashboard"))
    personnummer = (request.form.get("personnummer") or "").strip()
    if not personnummer:
        flash("Ange personnummer för standardkontot.", "error")
        return redirect(url_for("supervisor_dashboard"))
    try:
        normalized = functions.normalize_personnummer(personnummer)
    except ValueError:
        flash("Personnumret är ogiltigt.", "error")
        return redirect(url_for("supervisor_dashboard"))

    success, reason = functions.create_supervisor_link_request(email_hash, normalized)
    if success:
        flash("Kopplingsförfrågan har skickats.", "success")
    elif reason == "missing_user":
        flash("Standardkontot kunde inte hittas.", "error")
    elif reason == "already_connected":
        flash("Standardkontot är redan kopplat till ditt konto.", "error")
    elif reason == "already_requested":
        flash("Det finns redan en kopplingsförfrågan till standardkontot.", "error")
    else:
        flash("Kopplingsförfrågan kunde inte skickas.", "error")
    return redirect(url_for("supervisor_dashboard"))


@app.route("/foretagskonto/standardkonto/<person_hash>/pdf/<int:pdf_id>")
def supervisor_download_pdf(person_hash: str, pdf_id: int):
    email_hash, _ = _require_supervisor()
    if not functions.supervisor_has_access(email_hash, person_hash):
        logger.warning(
            "Supervisor %s attempted to access pdf %s for %s without permission",
            email_hash,
            pdf_id,
            person_hash,
        )
        abort(404)
    pdf = functions.get_pdf_content(person_hash, pdf_id)
    if not pdf:
        abort(404)
    filename, content = pdf
    as_attachment = request.args.get("download", "1") != "0"
    logger.info(
        "Supervisor %s retrieving %s for %s",
        email_hash,
        filename,
        person_hash,
    )
    response = make_response(content)
    response.headers["Content-Type"] = "application/pdf"
    disposition = "attachment" if as_attachment else "inline"
    response.headers["Content-Disposition"] = f'{disposition}; filename="{filename}"'
    return response


@app.post("/foretagskonto/dela/<person_hash>/<int:pdf_id>")
def supervisor_share_pdf_route(person_hash: str, pdf_id: int):
    email_hash, supervisor_name = _require_supervisor()
    anchor = request.form.get("anchor", "")
    redirect_target = url_for("supervisor_dashboard")
    if anchor:
        redirect_target += f"#{anchor}"

    if not validate_csrf_token(allow_if_absent=True):
        flash("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.", "error")
        return redirect(redirect_target)

    if not functions.supervisor_has_access(email_hash, person_hash):
        logger.warning(
            "Supervisor %s attempted to share pdf %s for %s without permission",
            email_hash,
            pdf_id,
            person_hash,
        )
        flash("Åtgärden kunde inte utföras.", "error")
        return redirect(redirect_target)

    recipient_email = (request.form.get("recipient_email") or "").strip()
    if not recipient_email:
        flash("Ange en e-postadress.", "error")
        return redirect(redirect_target)

    try:
        normalized_recipient = email_service.normalize_valid_email(recipient_email)
    except ValueError:
        flash("Ogiltig e-postadress.", "error")
        return redirect(redirect_target)

    pdf = functions.get_pdf_content(person_hash, pdf_id)
    if not pdf:
        flash("Intyget kunde inte hittas.", "error")
        return redirect(redirect_target)

    owner_name = functions.get_username_by_personnummer_hash(person_hash) or "Standardkontot"
    attachments = [(pdf[0], pdf[1])]

    try:
        email_service.send_pdf_share_email(
            normalized_recipient,
            attachments,
            supervisor_name,
            owner_name=owner_name,
        )
    except RuntimeError:
        logger.exception(
            "Failed to share pdf %s for %s by supervisor %s",
            pdf_id,
            person_hash,
            email_hash,
        )
        flash("Ett internt fel inträffade när intyget skulle delas.", "error")
        return redirect(redirect_target)

    logger.info(
        "Supervisor %s shared pdf %s for %s to %s",
        email_hash,
        pdf_id,
        person_hash,
        normalized_recipient,
    )
    flash("Intyget har skickats via e-post.", "success")
    return redirect(redirect_target)


@app.post("/foretagskonto/kopplingar/<person_hash>/ta-bort")
def supervisor_remove_connection_route(person_hash: str):
    email_hash, _ = _require_supervisor()
    anchor = request.form.get("anchor", "")
    redirect_target = url_for("supervisor_dashboard")
    if anchor:
        redirect_target += f"#{anchor}"

    if not validate_csrf_token(allow_if_absent=True):
        flash("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.", "error")
        return redirect(redirect_target)

    if functions.supervisor_remove_connection(email_hash, person_hash):
        logger.info("Supervisor %s removed access to %s", email_hash, person_hash)
        flash("Kopplingen har tagits bort.", "success")
    else:
        flash("Kopplingen kunde inte tas bort.", "error")
    return redirect(redirect_target)


@app.route("/aterstall-losenord/<token>", methods=["GET", "POST"])
def password_reset(token: str):
    info = functions.get_password_reset(token)
    if not info or info.get("used_at") is not None:
        return render_template("password_reset.html", invalid=True)

    if request.method == "POST":
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()
        if not password or password != confirm:
            return render_template(
                "password_reset.html",
                invalid=False,
                error="Lösenorden måste fyllas i och matcha.",
            )
        if len(password) < 8:
            return render_template(
                "password_reset.html",
                invalid=False,
                error="Lösenordet måste vara minst 8 tecken.",
            )
        if not functions.reset_password_with_token(token, password):
            return render_template("password_reset.html", invalid=True)
        return redirect("/login")

    return render_template("password_reset.html", invalid=False)


@app.route("/foretagskonto/aterstall-losenord/<token>", methods=["GET", "POST"])
def supervisor_password_reset(token: str):
    info = functions.get_supervisor_password_reset(token)
    if not info or info.get("used_at") is not None:
        return render_template("supervisor_password_reset.html", invalid=True)

    if request.method == "POST":
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()
        if not password or password != confirm:
            return render_template(
                "supervisor_password_reset.html",
                invalid=False,
                error="Lösenorden måste fyllas i och matcha.",
            )
        if len(password) < 8:
            return render_template(
                "supervisor_password_reset.html",
                invalid=False,
                error="Lösenordet måste vara minst 8 tecken.",
            )
        if not functions.reset_supervisor_password_with_token(token, password):
            return render_template("supervisor_password_reset.html", invalid=True)
        return redirect(url_for("supervisor_login"))

    return render_template("supervisor_password_reset.html", invalid=False)


@app.route("/", methods=["GET"])
def home():
    # Render the landing page.
    logger.debug("Rendering home page")
    return render_template("index.html")


@app.route("/ansok", methods=["GET"])
def apply_account():
    """Visa val för ansökan om konto."""

    return render_template("apply.html")


def _flag_application_field_error(message: str, field_errors: dict[str, bool]) -> None:
    # Markera specifika fält som ska flaggas i formuläret utifrån felmeddelanden.
    lowered = message.lower()
    if "namn" in lowered:
        field_errors["name"] = True
    if "e-post" in lowered or "email" in lowered:
        field_errors["email"] = True
    if "personnummer" in lowered:
        field_errors["personnummer"] = True
    if "organisationsnummer" in lowered:
        field_errors["orgnr"] = True
    if "företagsnamn" in lowered:
        field_errors["company_name"] = True
    if "fakturaadress" in lowered:
        field_errors["invoice_address"] = True
    if "kontaktperson" in lowered:
        field_errors["invoice_contact"] = True
    if "märkning" in lowered:
        field_errors["invoice_reference"] = True


@app.route("/ansok/standardkonto", methods=["GET", "POST"])
def apply_standardkonto():
    """Visa och hantera ansökan för standardkonto."""

    account_type = "standard"
    form_errors: list[str] = []
    base_field_errors = {
        "name": False,
        "email": False,
        "personnummer": False,
        "company_name": False,
        "invoice_address": False,
        "invoice_contact": False,
        "invoice_reference": False,
        "comment": False,
        "terms_confirmed": False,
    }
    field_errors = dict(base_field_errors)
    status_code = 200

    base_form_data = {
        "name": "",
        "email": "",
        "personnummer": "",
        "comment": "",
        "terms_confirmed": "",
        "company_name": "",
    }

    form_data = dict(base_form_data)

    if request.method == "POST":
        for key in form_data:
            form_data[key] = (request.form.get(key, "") or "").strip()
        if not validate_csrf_token():
            form_errors.append("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.")
        else:
            client_ip = get_request_ip()
            if not register_public_submission(client_ip):
                status_code = 429
                form_errors.append("Du har gjort för många försök. Vänta en stund och prova igen.")
            else:
                if not as_bool(form_data.get("terms_confirmed")):
                    field_errors["terms_confirmed"] = True
                    form_errors.append(
                        "Du måste intyga att du har läst och förstått villkoren och den juridiska informationen innan du skickar ansökan."
                    )
                if not form_errors:
                    try:
                        request_id = functions.create_application_request(
                            account_type,
                            form_data["name"],
                            form_data["email"],
                            "",
                            form_data.get("company_name"),
                            form_data.get("comment"),
                            form_data.get("invoice_address"),
                            form_data.get("invoice_contact"),
                            form_data.get("invoice_reference"),
                            form_data.get("personnummer"),
                        )
                        logger.info(
                            "Ny ansökan %s mottagen från %s",
                            request_id,
                            mask_hash(functions.hash_value(form_data["email"].lower())),
                        )
                    except ValueError as exc:
                        message = str(exc)
                        form_errors.append(message)
                        _flag_application_field_error(message, field_errors)
                    except Exception as exc:  # pragma: no cover - defensiv loggning
                        logger.exception("Kunde inte spara ansökan")
                        form_errors.append(
                            "Det gick inte att skicka ansökan just nu. Försök igen senare."
                        )
                    else:
                        # Make the client-facing confirmation explicit about which account type was submitted
                        display_type = (
                            "företagskonto" if account_type == "foretagskonto" else "standardkonto"
                        )
                        flash(
                            f"Din ansökan om {display_type} har skickats. Tack! Vi hör av oss så snart vi granskat ansökan.",
                            "success",
                        )
                        return redirect(url_for("application_submitted", account_type=account_type))

    csrf_token = sec.ensure_csrf_token()

    return (
        render_template(
            "apply_standardkonto.html",
            csrf_token=csrf_token,
            form_data=form_data,
            form_errors=form_errors,
            field_errors=field_errors,
        ),
        status_code,
    )


@app.route("/ansok/foretagskonto", methods=["GET", "POST"])
def apply_foretagskonto():
    """Visa och hantera ansökan för företagskonto."""

    account_type = "foretagskonto"
    form_errors: list[str] = []
    base_field_errors = {
        "name": False,
        "email": False,
        "orgnr": False,
        "company_name": False,
        "invoice_address": False,
        "invoice_contact": False,
        "invoice_reference": False,
        "comment": False,
        "terms_confirmed": False,
    }
    field_errors = dict(base_field_errors)
    status_code = 200

    base_form_data = {
        "name": "",
        "email": "",
        "orgnr": "",
        "comment": "",
        "terms_confirmed": "",
        "company_name": "",
        "invoice_address": "",
        "invoice_contact": "",
        "invoice_reference": "",
    }

    form_data = dict(base_form_data)

    if request.method == "POST":
        for key in form_data:
            form_data[key] = (request.form.get(key, "") or "").strip()
        if not validate_csrf_token():
            form_errors.append("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.")
        else:
            client_ip = get_request_ip()
            if not register_public_submission(client_ip):
                status_code = 429
                form_errors.append("Du har gjort för många försök. Vänta en stund och prova igen.")
            else:
                if not as_bool(form_data.get("terms_confirmed")):
                    field_errors["terms_confirmed"] = True
                    form_errors.append(
                        "Du måste intyga att du har läst och förstått villkoren och den juridiska informationen innan du skickar ansökan."
                    )
                if not form_errors:
                    try:
                        request_id = functions.create_application_request(
                            account_type,
                            form_data["name"],
                            form_data["email"],
                            form_data["orgnr"],
                            form_data.get("company_name"),
                            form_data.get("comment"),
                            form_data.get("invoice_address"),
                            form_data.get("invoice_contact"),
                            form_data.get("invoice_reference"),
                        )
                        logger.info(
                            "Ny ansökan %s mottagen från %s",
                            request_id,
                            mask_hash(functions.hash_value(form_data["email"].lower())),
                        )
                    except ValueError as exc:
                        message = str(exc)
                        form_errors.append(message)
                        _flag_application_field_error(message, field_errors)
                    except Exception as exc:  # pragma: no cover - defensiv loggning
                        logger.exception("Kunde inte spara ansökan")
                        form_errors.append(
                            "Det gick inte att skicka ansökan just nu. Försök igen senare."
                        )
                    else:
                        # Make the client-facing confirmation explicit about which account type was submitted
                        display_type = (
                            "företagskonto" if account_type == "foretagskonto" else "standardkonto"
                        )
                        flash(
                            f"Din ansökan om {display_type} har skickats. Tack! Vi hör av oss så snart vi granskat ansökan.",
                            "success",
                        )
                        return redirect(url_for("application_submitted", account_type=account_type))

    csrf_token = sec.ensure_csrf_token()

    return (
        render_template(
            "apply_foretagskonto.html",
            csrf_token=csrf_token,
            form_data=form_data,
            form_errors=form_errors,
            field_errors=field_errors,
        ),
        status_code,
    )


@app.route("/villkor", methods=["GET"])
def terms_of_service():
    """Visa sidan med villkor."""

    return render_template("terms_of_service.html")


@app.route("/ansok/klart", methods=["GET"])
def application_submitted():
    """Visa bekräftelse och nästa steg efter inskickad ansökan."""

    raw_type = request.args.get("account_type", "").strip().lower()
    account_type = "företagskonto" if raw_type == "foretagskonto" else "standardkonto"
    return render_template("application_submitted.html", account_type=account_type)


@app.route("/pris", methods=["GET"])
def pricing():
    """Visa prislistan."""

    return render_template("pris.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Authenticate users using personnummer and password.
    csrf_token = sec.ensure_csrf_token()
    if request.method == "POST":
        if not validate_csrf_token():
            logger.warning("Ogiltig CSRF-token vid användarinloggning")
            return (
                render_template(
                    "user_login.html",
                    error="Formuläret är inte längre giltigt. Ladda om sidan och försök igen.",
                    csrf_token=csrf_token,
                ),
                400,
            )
        raw_personnummer = request.form["personnummer"]
        try:
            personnummer = functions.normalize_personnummer(raw_personnummer)
        except ValueError:
            logger.warning("Ogiltigt personnummer angivet vid inloggning")
            return (
                render_template(
                    "user_login.html",
                    error="Ogiltiga inloggningsuppgifter",
                    csrf_token=csrf_token,
                ),
                401,
            )

        if personnummer == "" or not personnummer.isnumeric():
            logger.warning("Ogiltigt normaliserat personnummer vid inloggning")
            return (
                render_template(
                    "user_login.html",
                    error="Ogiltiga inloggningsuppgifter",
                    csrf_token=csrf_token,
                ),
                401,
            )
        password = request.form["password"]
        personnummer_hash = functions.hash_value(personnummer)
        if password == "":
            logger.warning("Empty password provided for %s", mask_hash(personnummer_hash))
            return (
                render_template(
                    "user_login.html",
                    error="Ogiltiga inloggningsuppgifter",
                    csrf_token=csrf_token,
                ),
                401,
            )
        logger.debug("Login attempt for %s", mask_hash(personnummer_hash))
        if functions.check_personnummer_password(personnummer, password):
            session["user_logged_in"] = True
            session["personnummer"] = personnummer_hash
            session["personnummer_raw"] = personnummer
            session["username"] = functions.get_username_by_personnummer_hash(personnummer_hash)
            logger.info("User %s logged in", mask_hash(personnummer_hash))
            return redirect("/dashboard")
        else:
            logger.warning("Invalid login for %s", mask_hash(personnummer_hash))
            return (
                render_template(
                    "user_login.html",
                    error="Ogiltiga inloggningsuppgifter",
                    csrf_token=csrf_token,
                ),
                401,
            )
    logger.debug("Rendering login page")
    return render_template("user_login.html", csrf_token=csrf_token)


@app.route("/dashboard", methods=["GET"])
def dashboard():
    # Visa alla PDF:er för den inloggade användaren.
    if not session.get("user_logged_in"):
        logger.debug("Unauthenticated access to dashboard")
        return redirect("/login")
    pnr_hash = session.get("personnummer")
    user_name = session.get("username")
    if not user_name and pnr_hash:
        user_name = functions.get_username_by_personnummer_hash(pnr_hash)
        if user_name:
            session["username"] = user_name
    if not pnr_hash:
        return redirect("/login")
    pdfs = functions.get_user_pdfs(pnr_hash)
    for pdf in pdfs:
        pdf["category_labels"] = labels_for_slugs(pdf.get("categories", []))
    grouped_pdfs = []
    groups_by_slug = {}
    for slug, label in COURSE_CATEGORIES:
        group = {"slug": slug, "label": label, "pdfs": []}
        grouped_pdfs.append(group)
        groups_by_slug[slug] = group
    uncategorized_group = {
        "slug": "okategoriserade",
        "label": "Okategoriserade intyg",
        "pdfs": [],
    }
    for pdf in pdfs:
        categories = pdf.get("categories") or []
        matched = False
        for slug in categories:
            group = groups_by_slug.get(slug)
            if group is not None:
                group["pdfs"].append(pdf)
                matched = True
        if not matched:
            uncategorized_group["pdfs"].append(pdf)
    visible_groups = [group for group in grouped_pdfs if group["pdfs"]]
    if uncategorized_group["pdfs"]:
        visible_groups.append(uncategorized_group)
    category_summary = [
        {
            "slug": slug,
            "label": label,
            "count": len(groups_by_slug[slug]["pdfs"]),
        }
        for slug, label in COURSE_CATEGORIES
    ]
    if uncategorized_group["pdfs"]:
        category_summary.append(
            {
                "slug": uncategorized_group["slug"],
                "label": uncategorized_group["label"],
                "count": len(uncategorized_group["pdfs"]),
            }
        )
    pending_link_requests = functions.list_user_link_requests(pnr_hash)
    supervisor_connections = functions.list_user_supervisor_connections(pnr_hash)
    logger.debug("Dashboard for %s shows %d pdfs", pnr_hash, len(pdfs))
    user_name = (user_name or "").capitalize()
    csrf_token = sec.ensure_csrf_token()
    return render_template(
        "dashboard.html",
        pdfs=pdfs,
        course_categories=COURSE_CATEGORIES,
        course_category_groups=COURSE_CATEGORY_GROUPS,
        category_summary=category_summary,
        grouped_pdfs=visible_groups,
        user_name=user_name,
        pending_link_requests=pending_link_requests,
        supervisor_connections=supervisor_connections,
        csrf_token=csrf_token,
    )


@app.post("/dashboard/ladda-upp")
def user_upload_pdf_route():
    if not session.get("user_logged_in"):
        return redirect("/login")

    if not validate_csrf_token():
        flash("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.", "error")
        return redirect("/dashboard")

    personnummer = session.get("personnummer_raw")
    if not personnummer:
        flash("Kunde inte identifiera användaren. Logga in igen.", "error")
        return redirect("/dashboard")

    if not validate_csrf_token(allow_if_absent=True):
        flash("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.", "error")
        return redirect("/dashboard")

    uploaded_file = request.files.get("certificate")
    category = request.form.get("category", "")
    note = (request.form.get("note", "") or "").strip()

    if not uploaded_file or uploaded_file.filename == "":
        flash("Ingen fil vald.", "error")
        return redirect("/dashboard")

    if not category:
        flash("Välj en kurskategori.", "error")
        return redirect("/dashboard")

    if len(note) > 300:
        flash("Anteckningen får vara högst 300 tecken.", "error")
        return redirect("/dashboard")

    try:
        pdf.save_pdf_for_user(personnummer, uploaded_file, [category], note=note, logger=logger)
    except ValueError as exc:
        flash(
            _safe_user_error(
                str(exc),
                ALLOWED_PDF_UPLOAD_ERRORS,
                "Filen kunde inte laddas upp. Kontrollera filformatet och försök igen.",
            ),
            "error",
        )
        return redirect("/dashboard")
    except Exception:
        logger.exception("Kunde inte spara intyg för användare")
        flash("Ett fel inträffade när intyget skulle sparas.", "error")
        return redirect("/dashboard")

    flash("Intyget har laddats upp och sparats som PDF.", "success")
    return redirect("/dashboard")


@app.post("/dashboard/kopplingsforfragan/<supervisor_hash>/godkann")
def user_accept_link_request_route(supervisor_hash: str):
    if not session.get("user_logged_in"):
        return redirect("/login")
    if not validate_csrf_token(allow_if_absent=True):
        flash("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.", "error")
        return redirect("/dashboard")
    personnummer_hash = session.get("personnummer")
    if not personnummer_hash:
        flash("Inte inloggad.", "error")
        return redirect("/login")
    if functions.user_accept_link_request(personnummer_hash, supervisor_hash):
        flash("Kopplingen är nu aktiv.", "success")
    else:
        flash("Kopplingsförfrågan kunde inte godkännas.", "error")
    return redirect("/dashboard")


@app.post("/dashboard/kopplingsforfragan/<supervisor_hash>/avsla")
def user_reject_link_request_route(supervisor_hash: str):
    if not session.get("user_logged_in"):
        return redirect("/login")
    if not validate_csrf_token(allow_if_absent=True):
        flash("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.", "error")
        return redirect("/dashboard")
    personnummer_hash = session.get("personnummer")
    if not personnummer_hash:
        flash("Inte inloggad.", "error")
        return redirect("/login")
    if functions.user_reject_link_request(personnummer_hash, supervisor_hash):
        flash("Kopplingsförfrågan har avböjts.", "success")
    else:
        flash("Kopplingsförfrågan kunde inte avböjas.", "error")
    return redirect("/dashboard")


@app.post("/dashboard/kopplingar/<supervisor_hash>/ta-bort")
def user_remove_supervisor_connection_route(supervisor_hash: str):
    if not session.get("user_logged_in"):
        return redirect("/login")
    if not validate_csrf_token(allow_if_absent=True):
        flash("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.", "error")
        return redirect("/dashboard")
    personnummer_hash = session.get("personnummer")
    if not personnummer_hash:
        flash("Inte inloggad.", "error")
        return redirect("/login")
    if functions.user_remove_supervisor_connection(personnummer_hash, supervisor_hash):
        flash("Kopplingen har tagits bort.", "success")
    else:
        flash("Kopplingen kunde inte tas bort.", "error")
    return redirect("/dashboard")


@app.post("/dashboard/intyg/<int:pdf_id>/ta-bort")
def user_delete_pdf_route(pdf_id: int):
    if not session.get("user_logged_in"):
        return redirect("/login")

    if not validate_csrf_token(allow_if_absent=True):
        flash("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.", "error")
        return redirect("/dashboard")

    personnummer = session.get("personnummer_raw")
    if not personnummer:
        flash("Kunde inte identifiera användaren. Logga in igen.", "error")
        return redirect("/dashboard")

    try:
        if functions.delete_user_pdf(personnummer, pdf_id):
            flash("Intyget har tagits bort.", "success")
        else:
            flash("Intyget kunde inte tas bort.", "error")
    except Exception:
        logger.exception("Kunde inte ta bort intyg %s för användare", pdf_id)
        flash("Ett fel inträffade när intyget skulle tas bort.", "error")

    return redirect("/dashboard")


@app.route("/my_pdfs/<int:pdf_id>")
def download_pdf(pdf_id: int):
    # Serve a stored PDF for the logged-in user from the database.
    if not session.get("user_logged_in"):
        logger.debug("Unauthenticated download attempt for %s", pdf_id)
        return redirect("/login")
    pnr_hash = session.get("personnummer")
    if not pnr_hash:
        return redirect("/login")
    as_attachment = request.args.get("download", "1") != "0"
    pdf = functions.get_pdf_content(pnr_hash, pdf_id)
    if not pdf:
        logger.warning("PDF %s not found for user %s", pdf_id, pnr_hash)
        abort(404)
    filename, content = pdf
    logger.info("User %s retrieving %s (as_attachment=%s)", pnr_hash, filename, as_attachment)
    response = make_response(content)
    response.headers["Content-Type"] = "application/pdf"
    disposition = "attachment" if as_attachment else "inline"
    response.headers["Content-Disposition"] = f'{disposition}; filename="{filename}"'
    return response


@app.route("/share_pdf", methods=["POST"])
def share_pdf() -> tuple[Response, int]:  # pragma: no cover
    # Share a PDF with a recipient via e-post.
    if not session.get("user_logged_in"):
        logger.debug("Unauthenticated share attempt")
        return jsonify({"fel": "Du måste vara inloggad för att dela intyg."}), 401

    payload = request.get_json(silent=True) or request.form
    if not payload:
        logger.error(f"Empty payload in share_pdf:{payload!r}")
        return jsonify({"fel": "Ogiltig begäran."}), 400

    pdf_ids_raw = payload.get("pdf_ids") if hasattr(payload, "get") else None
    recipient_email = (
        payload.get("recipient_email", "") if hasattr(payload, "get") else ""
    ).strip()

    if pdf_ids_raw is None and hasattr(payload, "get"):
        pdf_id_raw = payload.get("pdf_id")
        if pdf_id_raw is not None:
            pdf_ids_raw = [pdf_id_raw]

    if pdf_ids_raw is None:
        logger.debug(f"No pdf_ids provided in share_pdf: {payload!r}")
        return jsonify({"fel": "Ogiltigt intyg angivet."}), 400

    if isinstance(pdf_ids_raw, (str, bytes)):
        candidate_ids = [pdf_ids_raw]
    elif isinstance(pdf_ids_raw, (list, tuple, set)):
        candidate_ids = list(pdf_ids_raw)
    else:
        candidate_ids = [pdf_ids_raw]

    pdf_ids: list[int] = []
    seen_ids: set[int] = set()
    for raw_id in candidate_ids:
        try:
            pdf_id = int(raw_id)
        except (TypeError, ValueError):
            logger.warning("Invalid pdf_id provided for sharing: %r", raw_id)
            return jsonify({"fel": "Ogiltigt intyg angivet."}), 400
        if pdf_id in seen_ids:
            continue
        seen_ids.add(pdf_id)
        pdf_ids.append(pdf_id)

    if not pdf_ids:
        logger.debug(f"Empty pdf_ids after processing in share_pdf: {payload!r}")
        return jsonify({"fel": "Ogiltigt intyg angivet."}), 400

    if not recipient_email:
        logger.debug("Empty recipient_email in share_pdf: %r", payload)
        return jsonify({"fel": "Ange en e-postadress."}), 400

    pnr_hash = session.get("personnummer")
    if not pnr_hash:
        logger.error("Share request missing personnummer in session: %r", session)
        return jsonify({"fel": "Saknar användaruppgifter."}), 400

    attachments: list[tuple[str, bytes]] = []

    for pdf_id in pdf_ids:
        pdf = functions.get_pdf_content(pnr_hash, pdf_id)
        if not pdf:
            logger.debug("PDF %s not found for user %s when sharing", pdf_id, pnr_hash)
            return jsonify({"fel": "Intyget kunde inte hittas."}), 404
        filename, content = pdf
        attachments.append((filename, content))

    sender_name = session.get("username")
    if not sender_name:
        sender_name = functions.get_username_by_personnummer_hash(pnr_hash)
        if sender_name:
            session["username"] = sender_name

    sender_display = (sender_name or "").strip() or "Ett standardkonto"

    try:
        normalized_recipient = email_service.normalize_valid_email(recipient_email)
    except ValueError:
        logger.debug("Invalid recipient_email in share_pdf: %r", recipient_email)
        return jsonify({"fel": "Ogiltig e-postadress."}), 400

    if normalized_recipient != recipient_email:
        logger.debug(
            "Normalized share recipient email from %r to %s",
            recipient_email,
            normalized_recipient,
        )

    try:
        email_service.send_pdf_share_email(
            normalized_recipient,
            attachments,
            sender_display,
        )
    except RuntimeError as exc:
        logger.exception(
            "Failed to share pdf %s from %s to %s. Error: %s",
            pdf_ids,
            pnr_hash,
            normalized_recipient,
            exc,
        )
        return jsonify({"fel": "Ett internt fel har inträffat."}), 500

    logger.info(
        "User %s delade intyg %s med %s",
        pnr_hash,
        pdf_ids,
        normalized_recipient,
    )
    success_message = (
        "Intyget har skickats via e-post."
        if len(attachments) == 1
        else "Intygen har skickats via e-post."
    )
    return jsonify({"meddelande": success_message}), 200


@app.route("/view_pdf/<int:pdf_id>")
def view_pdf(pdf_id: int):
    # Redirect to a direct download of the specified PDF.
    if not session.get("user_logged_in"):
        logger.debug("Unauthenticated view attempt for %s", pdf_id)
        return redirect("/login")
    pnr_hash = session.get("personnummer")
    if not pnr_hash:
        return redirect("/login")
    pdf = functions.get_pdf_metadata(pnr_hash, pdf_id)
    if not pdf:
        logger.warning("PDF %s not found for user %s", pdf_id, pnr_hash)
        abort(404)
    logger.info("User %s laddar ned %s via direktlänk", pnr_hash, pdf["filename"])
    return redirect(url_for("download_pdf", pdf_id=pdf_id))


@app.route("/admin", methods=["POST", "GET"])
def admin():  # pragma: no cover
    # Admin dashboard for uploading certificates and creating users.
    if request.method == "POST":
        if not session.get("admin_logged_in"):
            logger.warning("Unauthorized admin POST")
            return redirect("/error", code=401)

        try:
            # --- Grab form data ---
            email_input = request.form.get("email", "").strip()
            username = request.form.get("username", "").strip()
            personnummer = functions.normalize_personnummer(
                request.form.get("personnummer", "").strip()
            )
            normalized_email = functions.normalize_email(email_input)
            email = normalized_email
            email_hash = functions.hash_value(email)
            pnr_hash = functions.hash_value(personnummer)

            raw_categories = request.form.getlist("categories")
            pdf_files = request.files.getlist("pdf")
            if not raw_categories:
                logger.warning("Admin upload missing categories (no selection)")
                return jsonify({"status": "error", "message": "Välj kategori för varje PDF."}), 400
            if not pdf_files:
                logger.warning("Admin upload without PDF")
                return jsonify({"status": "error", "message": "PDF-fil saknas"}), 400

            if len(raw_categories) != len(pdf_files):
                logger.warning(
                    "Admin upload category mismatch (categories=%d, files=%d)",
                    len(raw_categories),
                    len(pdf_files),
                )
                return jsonify({"status": "error", "message": "Välj kategori för varje PDF."}), 400

            logger.debug(
                "Admin upload for %s with categories %s",
                mask_hash(pnr_hash),
                raw_categories,
            )

            normalized_categories = []
            for idx, raw in enumerate(raw_categories):
                selected = normalize_category_slugs([raw])
                if len(selected) != 1:
                    logger.warning(
                        "Admin upload invalid category for file %d (value=%r)",
                        idx,
                        raw,
                    )
                    return jsonify(
                        {"status": "error", "message": "Välj giltig kategori för varje PDF."}
                    ), 400
                normalized_categories.append(selected[0])

            # --- Check if user exists ---
            user_exists = functions.get_user_info(personnummer) or functions.check_user_exists(
                email
            )
            pending_exists = functions.check_pending_user_hash(pnr_hash)

            # --- Save PDFs ---
            pdf_records = [
                pdf.save_pdf_for_user(personnummer, file_storage, [category], logger=logger)
                for file_storage, category in zip(pdf_files, normalized_categories)
            ]

            # --- Return early for existing or pending users ---
            if user_exists:
                logger.info(
                    "PDFs uploaded for existing user %s (%d files)",
                    mask_hash(pnr_hash),
                    len(pdf_records),
                )
                return jsonify(
                    {
                        "status": "success",
                        "message": "PDF:er uppladdade för befintligt standardkonto",
                    }
                )

            if pending_exists:
                logger.info(
                    "PDFs uploaded for pending user %s (%d files)",
                    mask_hash(pnr_hash),
                    len(pdf_records),
                )
                return jsonify(
                    {
                        "status": "success",
                        "message": "Standardkontot väntar redan på aktivering. PDF:er uppladdade.",
                    }
                )

            # --- Create new pending user ---
            if functions.admin_create_user(email, username, personnummer):
                link = url_for("create_user", pnr_hash=pnr_hash, _external=True)
                try:
                    email_service.send_creation_email(email, link)
                except RuntimeError as e:
                    logger.error(
                        "Failed to send creation email to %s",
                        mask_hash(email_hash),
                        exc_info=True,
                    )
                    return jsonify(
                        {
                            "status": "error",
                            "message": "Det gick inte att skicka inloggningslänken via e-post.",
                        }
                    ), 500

                logger.info("Admin created user %s", mask_hash(pnr_hash))
                return jsonify(
                    {"status": "success", "message": "Standardkonto skapat", "link": link}
                )

            logger.error("Failed to create pending user for %s", mask_hash(pnr_hash))
            return jsonify({"status": "error", "message": "Kunde inte skapa standardkonto"}), 500

        except ValueError as ve:
            logger.error("Value error during admin upload: %s", ve)
            return jsonify({"status": "error", "message": "Felaktiga användardata."}), 400
        except Exception as e:
            logger.exception("Server error during admin upload", exc_info=e)
            return jsonify({"status": "error", "message": "Serverfel"}), 500

    # --- GET request ---
    if not session.get("admin_logged_in"):
        logger.warning("Unauthorized admin GET")
        return redirect("/login_admin")

    admin_log_entries = []
    try:
        with functions.get_engine().connect() as conn:
            rows = conn.execute(
                functions.admin_audit_log_table.select()
                .order_by(functions.admin_audit_log_table.c.created_at.desc())
                .limit(10)
            ).fetchall()
        for row in rows:
            created_at = row.created_at
            if created_at and hasattr(created_at, "isoformat"):
                created_at = created_at.isoformat(sep=" ", timespec="minutes")
            admin_log_entries.append(
                {
                    "admin": row.admin,
                    "action": row.action,
                    "details": row.details,
                    "created_at": created_at or "",
                }
            )
    except Exception:
        logger.exception("Misslyckades att hämta adminlogg")

    logger.debug("Rendering admin page")
    return render_template(
        "admin.html",
        admin_log_entries=admin_log_entries,
    )


@app.get("/admin/guide")
def admin_guide():  # pragma: no cover
    if not session.get("admin_logged_in"):
        logger.warning("Unauthorized admin guide GET")
        return redirect("/login_admin")
    guide_path = Path(current_app.root_path) / "admin.md"
    try:
        guide_content = guide_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.exception("Admin guide file missing")
        guide_content = "Guiden kunde inte hittas."
    rendered_guide = render_markdown_content(guide_content)
    logger.debug("Rendering admin guide page")
    return render_template("admin_guide.html", guide_content=rendered_guide)


@app.get("/admin/konton")
def admin_accounts():  # pragma: no cover
    if not session.get("admin_logged_in"):
        logger.warning("Unauthorized admin accounts GET")
        return redirect("/login_admin")
    csrf_token = ensure_csrf_token()
    logger.debug("Rendering admin accounts page")
    return render_template(
        "admin_accounts.html",
        categories=COURSE_CATEGORIES,
        category_groups=COURSE_CATEGORY_GROUPS,
        csrf_token=csrf_token,
    )


@app.get("/admin/intyg")
def admin_certificates():  # pragma: no cover
    if not session.get("admin_logged_in"):
        logger.warning("Unauthorized admin certificates GET")
        return redirect("/login_admin")
    logger.debug("Rendering admin certificates page")
    return render_template(
        "admin_certificates.html",
        categories=COURSE_CATEGORIES,
    )


@app.get("/admin/foretagskonto")
def admin_company_accounts():  # pragma: no cover
    if not session.get("admin_logged_in"):
        logger.warning("Unauthorized admin company accounts GET")
        return redirect("/login_admin")
    logger.debug("Rendering admin company accounts page")
    csrf_token = ensure_csrf_token()
    return render_template("admin_company_accounts.html", csrf_token=csrf_token)


@app.route("/admin/ansokningar", methods=["GET", "POST"])
def admin_applications():  # pragma: no cover
    if not session.get("admin_logged_in"):
        return redirect("/login_admin")
    if request.method == "POST":
        if not validate_csrf_token(allow_if_absent=True):
            return jsonify(
                {
                    "status": "error",
                    "message": "Formuläret är inte längre giltigt. Ladda om sidan och försök igen.",
                }
            ), 400
        application_id = request.form.get("application_id")
        application_status = request.form.get("application_status")
        if not application_id:
            return jsonify({"status": "error", "message": "Ansökans ID saknas."}), 400
        if application_status == "approved":
            functions.approve_application_request(int(application_id), "admin")
            logger.debug("Ansökan har godkänts, success")
            return jsonify({"status": "success", "message": "Ansökan har godkänts."})
        elif application_status == "rejected":
            functions.reject_application_request(int(application_id), "admin")
            logger.debug("Ansökan har avslagits, success")
            return jsonify({"status": "success", "message": "Ansökan har avslagits."})
        else:
            logger.error("Ogiltig status för ansökan.")
            return jsonify({"status": "error", "message": "Ogiltig status för ansökan."}), 400
    elif request.method == "GET":
        applications_requests = functions.list_application_requests()

        if logger.isEnabledFor(logging.DEBUG):

            def _mask_text(value: Any) -> str:
                # Mask free-text values for logging to avoid PII leakage.
                if value is None:
                    return mask_sensitive_data(value)
                text_value = str(value).strip()
                if not text_value:
                    return mask_sensitive_data(text_value)
                return mask_hash(functions.hash_value(text_value))

            for application in applications_requests:
                logger.debug(
                    "ID: %s, Typ: %s, Namn: %s, E-post: %s, OrgNr: %s, "
                    "Företagsnamn: %s, Fakturaadress: %s, Fakturakontakt: %s, "
                    "Fakturareferens: %s, Kommentar: %s, Status: %s, Granskad av: %s, "
                    "Beslutsorsak: %s, Skapad: %s, Uppdaterad: %s, Granskad: %s",
                    application.get("id"),
                    application.get("account_type"),
                    _mask_text(application.get("name")),
                    mask_email(application.get("email", "")),
                    _mask_text(application.get("orgnr_normalized")),
                    _mask_text(application.get("company_name")),
                    _mask_text(application.get("invoice_address")),
                    _mask_text(application.get("invoice_contact")),
                    _mask_text(application.get("invoice_reference")),
                    _mask_text(application.get("comment")),
                    application.get("status"),
                    _mask_text(application.get("reviewed_by")),
                    _mask_text(application.get("decision_reason")),
                    application.get("created_at"),
                    application.get("updated_at"),
                    application.get("reviewed_at"),
                )
        csrf_token = sec.ensure_csrf_token()
        return render_template(
            "admin_applications.html", applications=applications_requests, csrf_token=csrf_token
        )
    else:
        return render_template("error.html", code=405, message="Method Not Allowed"), 405


@app.route("/gdpr", methods=["GET"])
def gdpr_info():
    return render_template("gdpr.html")


@app.route("/admin/fakturering", methods=["GET"])
def admin_invoicing():  # pragma: no cover
    if not session.get("admin_logged_in"):
        return redirect("/login_admin")
    companies = functions.list_companies_for_invoicing()
    return render_template("admin_invoicing.html", companies=companies)


def _serialize_application_row(row: dict) -> dict:  # pragma: no cover
    def _safe_isoformat(value: Any) -> str | None:
        if value is None:
            return None
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return None

    return {
        "id": row.get("id"),
        "account_type": row.get("account_type"),
        "name": row.get("name"),
        "email": row.get("email"),
        "orgnr_normalized": row.get("orgnr_normalized"),
        "company_name": row.get("company_name"),
        "invoice_address": row.get("invoice_address"),
        "invoice_contact": row.get("invoice_contact"),
        "invoice_reference": row.get("invoice_reference"),
        "comment": row.get("comment"),
        "status": row.get("status"),
        "reviewed_by": row.get("reviewed_by"),
        "decision_reason": row.get("decision_reason"),
        "created_at": _safe_isoformat(row.get("created_at")),
        "updated_at": _safe_isoformat(row.get("updated_at")),
        "reviewed_at": _safe_isoformat(row.get("reviewed_at")),
    }


@app.get("/admin/api/ansokningar")
def admin_list_applications():  # pragma: no cover
    _require_admin()
    status = request.args.get("status")
    try:
        rows = functions.list_application_requests(status)
    except ValueError as exc:
        logging.exception("Failed to list application requests")
        return jsonify({"status": "error", "message": "Felaktig begäran."}), 400

    serialized = [_serialize_application_row(row) for row in rows]
    return jsonify({"status": "success", "data": serialized})


@app.get("/admin/api/ansokningar/<int:application_id>")
def admin_get_application(application_id: int):  # pragma: no cover
    _require_admin()
    row = functions.get_application_request(application_id)
    if not row:
        return jsonify({"status": "error", "message": "Ansökan hittades inte."}), 404
    return jsonify({"status": "success", "data": _serialize_application_row(row)})


@app.post("/admin/api/ansokningar/<int:application_id>/godkann")
def admin_approve_application(application_id: int):  # pragma: no cover
    """
    Godkänn ansökan, skapa/aktivera konto(n), skicka mejl till sökande (normal user)
    och – vid företagskonto – även till handledare/supervisor. Logga admin-åtgärden.
    """
    admin_name = _require_admin()
    if not validate_csrf_token():
        return jsonify({"status": "error", "message": "Ogiltig CSRF-token."}), 400

    try:
        # Förväntat result-format (exempel):
        # {
        #   'email': 'applicant@example.com',
        #   'account_type': 'standard'|'foretagskonto',
        #   'company_name': 'Exempel AB'|None,
        #   'user_activation_required': True|False,
        #   'user_personnummer_hash': 'abc123'|None,
        #   'supervisor_activation_required': True|False,
        #   'supervisor_email_hash': 'def456'|None
        # }
        result = functions.approve_application_request(application_id, admin_name)
    except ValueError as exc:
        # Logga det interna felet på serversidan utan att exponera detaljer för användaren.
        logger.warning(
            "ValueError vid godkännande av ansökan %s: %s", application_id, exc, exc_info=True
        )
        return jsonify(
            {
                "status": "error",
                "message": _safe_user_error(
                    "",
                    ALLOWED_ADMIN_APPROVAL_ERRORS,
                    (
                        "Ansökan kunde inte godkännas. Kontrollera att den fortfarande "
                        "är väntande och att uppgifterna är kompletta."
                    ),
                ),
            }
        ), 400
    except Exception:
        logger.exception("Misslyckades att godkänna ansökan %s", application_id)
        return jsonify({"status": "error", "message": "Kunde inte godkänna ansökan."}), 500

    email_warnings: list[str] = []

    creation_link: str | None = None  # <- samlad länk för svaret

    # 2) Aktiveringslänk till NORMAL user (om aktivering krävs)
    if result.get("user_activation_required") and result.get("user_personnummer_hash"):
        link = url_for(
            "create_user",
            pnr_hash=result["user_personnummer_hash"],
            _external=True,
        )
        try:
            email_service.send_creation_email(result["email"], link)
            creation_link = link  # <- spara till payload
        except Exception:
            logger.exception(
                "Misslyckades att skicka aktiveringslänk till sökande för ansökan %s",
                application_id,
            )
            email_warnings.append("Aktiveringslänken till sökande kunde inte skickas.")

    # 3) Aktiveringslänk till SUPERVISOR (företagskonto)
    if result.get("supervisor_activation_required") and result.get("supervisor_email_hash"):
        link = url_for(
            "supervisor_create", email_hash=result["supervisor_email_hash"], _external=True
        )
        supervisor_email = result.get("supervisor_email") or result["email"]
        try:
            email_service.send_creation_email(supervisor_email, link)
            if creation_link is None:
                creation_link = link  # <- använd denna om ingen tidigare satt
        except Exception:
            logger.exception(
                "Misslyckades att skicka aktiveringslänk till supervisor (ansökan %s)",
                application_id,
            )
            email_warnings.append(
                "Aktiveringslänken till handledare/supervisor kunde inte skickas."
            )

    masked_email = mask_hash(functions.hash_value(result["email"]))
    functions.log_admin_action(
        admin_name,
        "godkände ansökan",
        f"application_id={application_id}, email={masked_email}",
    )

    payload: dict[str, Any] = {"status": "success", "data": result}
    if email_warnings:
        payload["email_warning"] = " ".join(email_warnings)
    if creation_link:
        payload["creation_link"] = creation_link  # <- TOPP-NIVÅ, uppfyller testet

    return jsonify(payload)


@app.post("/admin/api/ansokningar/<int:application_id>/avslag")
def admin_reject_application(application_id: int):  # pragma: no cover
    admin_name = _require_admin()
    if not validate_csrf_token():
        return jsonify({"status": "error", "message": "Ogiltig CSRF-token."}), 400

    payload = request.get_json(silent=True) or {}
    decision_reason = (payload.get("reason") or "").strip()
    if not decision_reason:
        decision_reason = "Ingen motivering angiven."

    try:
        result = functions.reject_application_request(application_id, admin_name, decision_reason)
    except ValueError as exc:
        # Logga detaljerat fel, men exponera inte undantagstexten för användaren.
        logger.warning("Kunde inte avslå ansökan %s: %s", application_id, exc)
        return jsonify(
            {
                "status": "error",
                "message": (
                    "Ansökan kunde inte avslås. Kontrollera att den fortfarande "
                    "är väntande och försök igen."
                ),
            }
        ), 400
    except Exception:
        logger.exception("Misslyckades att avslå ansökan %s", application_id)
        return jsonify({"status": "error", "message": "Kunde inte avslå ansökan."}), 500

    email_error = None
    try:
        email_service.send_application_rejection_email(
            result["email"], result["company_name"], decision_reason
        )
    except RuntimeError as exc:
        logger.exception("Misslyckades att skicka avslag för ansökan %s", application_id)
        email_error = str(exc)

    masked_email = mask_hash(functions.hash_value(result["email"]))
    functions.log_admin_action(
        admin_name,
        "avslog ansökan",
        f"application_id={application_id}, email={masked_email}",
    )

    response_payload = {"status": "success", "data": result}
    if email_error:
        response_payload["email_warning"] = "Ansökan avslogs men e-post kunde inte skickas."
    return jsonify(response_payload)


@app.post("/admin/api/oversikt")
def admin_user_overview():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get("personnummer") or "").strip()
    if not personnummer:
        logging.debug("Admin overview without personnummer: ", extra={"admin": admin_name})
        return jsonify({"status": "error", "message": "Ange personnummer."}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        logging.debug(
            "Admin overview with invalid personnummer: %s",
            personnummer,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ogiltigt personnummer."}), 400

    pnr_hash = functions.hash_value(normalized_personnummer)
    pdfs = functions.get_user_pdfs(pnr_hash)
    overview = []
    for pdf in pdfs:
        uploaded_at = pdf.get("uploaded_at")
        overview.append(
            {
                "id": pdf["id"],
                "filename": pdf["filename"],
                "categories": pdf.get("categories") or [],
                "category_labels": labels_for_slugs(pdf.get("categories") or []),
                "uploaded_at": uploaded_at.isoformat()
                if (uploaded_at and hasattr(uploaded_at, "isoformat"))
                else None,
            }
        )

    user_row = functions.get_user_info(normalized_personnummer)
    pending = functions.check_pending_user(normalized_personnummer)
    response = {
        "status": "success",
        "data": {
            "personnummer_hash": pnr_hash,
            "username": user_row.username if user_row else None,
            "email_hash": user_row.email if user_row else None,
            "pending": pending,
            "pdfs": overview,
            "categories": [{"slug": slug, "label": label} for slug, label in COURSE_CATEGORIES],
        },
    }
    functions.log_admin_action(
        admin_name,
        "visade användaröversikt",
        f"personnummer_hash={pnr_hash}",
    )
    logging.debug(
        "Admin overview for %s with %d pdfs",
        mask_hash(pnr_hash),
        len(pdfs),
        extra={"admin": admin_name},
    )
    return jsonify(response)


@app.post("/admin/api/klientlogg")
def admin_client_log():
    admin_name = _require_admin()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Ogiltigt loggformat."}), 400
    message = _truncate_log_value(payload.get("message"), CLIENT_LOG_TRUNCATION_LIMITS["message"])
    context = _truncate_log_value(payload.get("context"), CLIENT_LOG_TRUNCATION_LIMITS["context"])
    url = _truncate_log_value(payload.get("url"), CLIENT_LOG_TRUNCATION_LIMITS["url"])
    details = payload.get("details")
    if isinstance(details, (dict, list)):
        masked_details = mask_sensitive_data(details)
        masked_details = _truncate_log_value(
            json.dumps(masked_details, ensure_ascii=False),
            CLIENT_LOG_TRUNCATION_LIMITS["details"],
        )
    else:
        masked_details = _truncate_log_value(details, CLIENT_LOG_TRUNCATION_LIMITS["details"])
    status = payload.get("status")
    logger.warning(
        "Klientlogg från admin %s: %s | context=%s | url=%s | status=%s | details=%s",
        admin_name,
        message or "Okänt fel",
        context or "okänd",
        url or "okänd",
        status,
        masked_details,
    )
    return jsonify({"status": "success"})


@app.post("/admin/api/radera-pdf")
def admin_delete_pdf():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get("personnummer") or "").strip()
    pdf_id = payload.get("pdf_id")
    if not personnummer or pdf_id is None:
        logging.debug(
            "Admin delete_pdf without personnummer or pdf_id", extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ange personnummer och PDF-id."}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        logging.debug(
            "Admin delete_pdf with invalid personnummer: %s",
            personnummer,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ogiltigt personnummer."}), 400

    try:
        pdf_id_int = int(pdf_id)
    except (ValueError, TypeError):
        logging.debug(
            "Admin delete_pdf with invalid pdf_id: %s", pdf_id, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ogiltigt PDF-id."}), 400

    if not functions.delete_user_pdf(normalized_personnummer, pdf_id_int):
        return (
            jsonify({"status": "error", "message": "PDF kunde inte hittas."}),
            404,
        )

    pnr_hash = functions.hash_value(normalized_personnummer)
    functions.log_admin_action(
        admin_name,
        "raderade PDF",
        f"personnummer_hash={pnr_hash}, pdf_id={pdf_id_int}",
    )
    logging.info(
        "Admin deleted pdf %s for %s", pdf_id_int, mask_hash(pnr_hash), extra={"admin": admin_name}
    )
    return jsonify({"status": "success", "message": "PDF borttagen."})


@app.post("/admin/api/radera-konto")
def admin_delete_account():  # pragma: no cover
    admin_name = _require_admin()
    if not validate_csrf_token():
        return jsonify({"status": "error", "message": "Ogiltig CSRF-token."}), 400
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get("personnummer") or "").strip()
    personnummer_hash = (payload.get("personnummer_hash") or "").strip()
    notify_email = (payload.get("email") or "").strip()
    if not personnummer:
        if not personnummer_hash:
            logging.debug(
                "Admin delete_account without personnummer",
                extra={"admin": admin_name},
            )
            return jsonify({"status": "error", "message": "Välj ett konto att radera."}), 400
    personnummer_masked = (
        mask_hash(functions.hash_value(personnummer)) if personnummer else "saknas"
    )
    try:
        if personnummer:
            normalized_personnummer = functions.normalize_personnummer(personnummer)
            personnummer_hash = functions.hash_value(normalized_personnummer)
        elif not functions._is_valid_hash(personnummer_hash):
            raise ValueError("Ogiltig hash")
    except ValueError:
        logging.debug(
            "Admin delete_account with invalid personnummer: %s",
            personnummer_masked,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ogiltiga uppgifter."}), 400

    normalized_email = None
    if notify_email:
        try:
            normalized_email = email_service.normalize_valid_email(notify_email)
        except ValueError:
            return jsonify({"status": "error", "message": "Ogiltig e-postadress."}), 400

    try:
        deleted, summary, username = functions.admin_delete_user_account_by_hash(personnummer_hash)
    except Exception:
        logger.exception(
            "Misslyckades att radera konto för %s",
            personnummer_masked,
        )
        return jsonify({"status": "error", "message": "Kunde inte radera kontot."}), 500

    if not deleted:
        return jsonify({"status": "error", "message": "Kontot hittades inte."}), 404

    email_warning = None
    if normalized_email:
        try:
            email_service.send_account_deletion_email(normalized_email, username)
        except Exception:
            logger.exception("Misslyckades att skicka raderingsmejl")
            email_warning = "Kontot raderades, men mejlet kunde inte skickas."

    pnr_hash = personnummer_hash
    summary_details = ", ".join(f"{key}={value}" for key, value in summary.items())
    email_hash = (
        functions.hash_value(functions.normalize_email(notify_email))
        if normalized_email
        else "saknas"
    )
    functions.log_admin_action(
        admin_name,
        "raderade konto",
        f"personnummer_hash={pnr_hash}, email_hash={email_hash}, {summary_details}",
    )
    logging.info(
        "Admin deleted account for %s",
        mask_hash(pnr_hash),
        extra={"admin": admin_name},
    )
    response_payload = {
        "status": "success",
        "message": (
            "Kontot har raderats och mejl har skickats."
            if normalized_email
            else "Kontot har raderats."
        ),
        "data": summary,
    }
    if email_warning:
        response_payload["email_warning"] = email_warning
        response_payload["message"] = "Kontot har raderats."
    return jsonify(response_payload)


@app.get("/admin/api/konton/lista")
def admin_list_accounts():  # pragma: no cover
    _require_admin()
    accounts = functions.list_admin_accounts()
    return jsonify({"status": "success", "data": accounts})


@app.post("/admin/api/konton/uppdatera")
def admin_update_account():  # pragma: no cover
    admin_name = _require_admin()
    if not validate_csrf_token():
        return jsonify({"status": "error", "message": "Ogiltig CSRF-token."}), 400
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get("personnummer") or "").strip()
    email = (payload.get("email") or "").strip()
    username = (payload.get("username") or "").strip()
    if not personnummer or not email or not username:
        return jsonify({"status": "error", "message": "Fyll i personnummer, namn och e-post."}), 400

    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
        normalized_email = functions.normalize_email(email)
    except ValueError:
        return jsonify({"status": "error", "message": "Ogiltiga uppgifter."}), 400

    success, summary, error = functions.admin_update_user_account(
        normalized_personnummer, normalized_email, username
    )
    if not success:
        if error == "missing_account":
            return jsonify({"status": "error", "message": "Kontot hittades inte."}), 404
        if error == "email_in_use":
            return jsonify({"status": "error", "message": "E-postadressen används redan."}), 409
        return jsonify({"status": "error", "message": "Kunde inte uppdatera kontot."}), 400

    pnr_hash = functions.hash_value(normalized_personnummer)
    email_hash = functions.hash_value(normalized_email)
    summary_details = ", ".join(f"{key}={value}" for key, value in summary.items())
    functions.log_admin_action(
        admin_name,
        "uppdaterade konto",
        f"personnummer_hash={pnr_hash}, email_hash={email_hash}, {summary_details}",
    )
    logging.info("Admin updated account for %s", mask_hash(pnr_hash), extra={"admin": admin_name})
    return jsonify(
        {
            "status": "success",
            "message": "Kontot har uppdaterats.",
            "data": summary,
        }
    )


@app.post("/admin/api/uppdatera-pdf")
def admin_update_pdf():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get("personnummer") or "").strip()
    pdf_id = payload.get("pdf_id")
    categories = payload.get("categories")
    if not isinstance(categories, list):
        logging.debug(
            "Admin update_pdf with invalid categories: %r", categories, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Kategorier måste vara en lista."}), 400
    if not personnummer or pdf_id is None:
        logging.debug(
            "Admin update_pdf without personnummer or pdf_id", extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ange personnummer och PDF-id."}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        logging.debug(
            "Admin update_pdf with invalid personnummer: %s",
            personnummer,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ogiltigt personnummer."}), 400
    try:
        pdf_id_int = int(pdf_id)
    except (ValueError, TypeError):
        logging.debug(
            "Admin update_pdf with invalid pdf_id: %s", pdf_id, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ogiltigt PDF-id."}), 400

    try:
        normalized_categories = normalize_category_slugs(categories)
    except ValueError:
        logging.debug(
            "Admin update_pdf with invalid categories: %r", categories, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ogiltig kategori vald."}), 400

    if not functions.update_pdf_categories(
        normalized_personnummer, pdf_id_int, normalized_categories
    ):
        return (
            jsonify({"status": "error", "message": "PDF kunde inte uppdateras."}),
            404,
        )

    pnr_hash = functions.hash_value(normalized_personnummer)
    functions.log_admin_action(
        admin_name,
        "uppdaterade PDF-kategorier",
        f"personnummer_hash={pnr_hash}, pdf_id={pdf_id_int}, kategorier={';'.join(normalized_categories)}",
    )
    logging.info(
        "Admin updated categories for pdf %s for %s",
        pdf_id_int,
        mask_hash(pnr_hash),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "message": "Kategorier uppdaterade."})


@app.post("/admin/api/konton/losenord-status")
def admin_password_status():  # pragma: no cover
    admin_name = _require_admin()
    if not validate_csrf_token():
        return jsonify({"status": "error", "message": "Ogiltig CSRF-token."}), 400
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get("personnummer") or "").strip()
    email = (payload.get("email") or "").strip()

    if not personnummer:
        logger.debug(
            "Admin password_status without personnummer",
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ange personnummer."}), 400

    try:
        result = functions.get_admin_password_status(personnummer, email)
    except ValueError:
        return jsonify({"status": "error", "message": "Ogiltiga uppgifter."}), 400

    if not result:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Uppgifterna matchar inget standardkonto eller väntande konto.",
                }
            ),
            404,
        )

    if result["password_created"]:
        message = "Lösenord är redan skapat för kontot."
    else:
        message = "Lösenord är inte skapat ännu. Skicka en skapa-konto-länk till användaren."

    return jsonify(
        {
            "status": "success",
            "message": message,
            "data": result,
        }
    )


@app.post("/admin/api/konton/skapa-losenordslank")
def admin_send_create_password_link():  # pragma: no cover
    admin_name = _require_admin()
    if not validate_csrf_token():
        return jsonify({"status": "error", "message": "Ogiltig CSRF-token."}), 400
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get("personnummer") or "").strip()
    email = (payload.get("email") or "").strip()

    if not personnummer:
        logger.debug(
            "Admin send_create_password_link without personnummer",
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ange personnummer."}), 400

    try:
        personnummer_hash = functions.get_pending_user_personnummer_hash(personnummer)
    except ValueError:
        return jsonify({"status": "error", "message": "Ogiltiga uppgifter."}), 400

    if not personnummer_hash:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Kontot är redan aktiverat eller uppgifterna matchar inget väntande konto.",
                }
            ),
            404,
        )

    link = url_for("create_user", pnr_hash=personnummer_hash, _external=True)
    if email:
        try:
            normalized_email = functions.normalize_email(email)
        except ValueError:
            logger.warning(
                "Admin angav ogiltig e-postadress för skapa-konto-länk till %s",
                mask_hash(personnummer_hash),
                extra={"admin": admin_name},
            )
            return jsonify({"status": "error", "message": "Ogiltig e-postadress."}), 400
        try:
            email_service.send_creation_email(normalized_email, link)
        except RuntimeError:
            logger.exception("Misslyckades att skicka skapa-konto-länk")
            return jsonify({"status": "error", "message": "Kunde inte skicka skapa-konto-länk."}), 500

        email_hash = functions.hash_value(normalized_email)
        functions.log_admin_action(
            admin_name,
            "skickade skapa-konto-länk",
            f"personnummer_hash={personnummer_hash}, email_hash={email_hash}",
        )
        logger.info(
            "Admin sent create-password link for %s to %s",
            mask_hash(personnummer_hash),
            mask_hash(email_hash),
            extra={"admin": admin_name},
        )
        message = "Skapa-konto-länk skickad."
    else:
        functions.log_admin_action(
            admin_name,
            "hämtade skapa-konto-länk",
            f"personnummer_hash={personnummer_hash}",
        )
        logger.info(
            "Admin fetched create-password link for %s without email send",
            mask_hash(personnummer_hash),
            extra={"admin": admin_name},
        )
        message = "Skapa-konto-länk hämtad. Ingen e-post angavs för utskick."

    return jsonify(
        {
            "status": "success",
            "message": message,
            "link": link,
        }
    )


@app.post("/admin/api/skicka-aterstallning")
def admin_send_password_reset():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    account_type = (payload.get("account_type") or "standard").strip().lower()
    personnummer = (payload.get("personnummer") or "").strip()
    email = (payload.get("email") or "").strip()
    if account_type not in {"standard", "foretagskonto"}:
        logging.debug(
            "Admin send_password_reset with invalid account_type: %s",
            account_type,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ogiltig kontotyp."}), 400

    if account_type == "standard" and (not personnummer or not email):
        logging.debug(
            "Admin send_password_reset without personnummer or email", extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ange både personnummer och e-post."}), 400
    if account_type == "foretagskonto" and not email:
        logging.debug(
            "Admin send_password_reset without email for foretagskonto", extra={"admin": admin_name}
        )
        return jsonify(
            {"status": "error", "message": "Ange e-postadressen för företagskontot."}
        ), 400

    if account_type == "foretagskonto":
        try:
            token = functions.create_supervisor_password_reset_token(email)
        except ValueError as exc:
            logger.warning(
                "Misslyckades att skapa återställningstoken för företagskonto: %s",
                exc,
            )
            return jsonify({"status": "error", "message": "Företagskontot hittades inte."}), 404
        except Exception as exc:
            logger.exception(f"Misslyckades att skapa återställningstoken för företagskonto: {exc}")
            return jsonify({"status": "error", "message": "Kunde inte skapa återställning."}), 500

        link = url_for("supervisor_password_reset", token=token, _external=True)
        try:
            email_service.send_password_reset_email(email, link)
        except RuntimeError as exc:
            logger.exception(f"Misslyckades att skicka återställningsmejl för företagskonto: {exc}")
            return jsonify(
                {"status": "error", "message": "Kunde inte skicka återställningsmejl."}
            ), 500

        email_hash = functions.hash_value(functions.normalize_email(email))
        functions.log_admin_action(
            admin_name,
            "skickade företagskonto-återställning",
            f"email_hash={email_hash}",
        )
        logging.info(
            "Admin sent supervisor password reset to %s",
            mask_hash(email_hash),
            extra={"admin": admin_name},
        )
        return jsonify(
            {
                "status": "success",
                "message": "Återställningsmejl skickat till företagskontot.",
                "link": link,
            }
        )

    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        logging.debug(
            "Admin send_password_reset with invalid personnummer: %s",
            personnummer,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ogiltigt personnummer."}), 400

    try:
        token = functions.create_password_reset_token(normalized_personnummer, email)
    except ValueError as exc:
        logger.warning("Misslyckades att skapa återställningstoken: %s", exc)
        # Do not expose raw exception messages to the client; map to safe, user-facing text instead.
        exc_message = str(exc)
        if exc_message == "Kontot är inte aktiverat ännu.":
            message = "Kontot är inte aktiverat ännu."
            status_code = 409
        else:
            message = "Uppgifterna matchar inget aktivt standardkonto."
            status_code = 404
        return jsonify({"status": "error", "message": message}), status_code
    except Exception as exc:
        logger.exception(f"Misslyckades att skapa återställningstoken: {exc}")
        return jsonify({"status": "error", "message": "Kunde inte skapa återställning."}), 500

    link = url_for("password_reset", token=token, _external=True)
    try:
        email_service.send_password_reset_email(email, link)
    except RuntimeError as exc:
        logger.exception(f"Misslyckades att skicka återställningsmejl: {exc}")
        return jsonify({"status": "error", "message": "Kunde inte skicka återställningsmejl."}), 500

    pnr_hash = functions.hash_value(normalized_personnummer)
    email_hash = functions.hash_value(functions.normalize_email(email))
    functions.log_admin_action(
        admin_name,
        "skickade lösenordsåterställning",
        f"personnummer_hash={pnr_hash}, email_hash={email_hash}",
    )
    logging.info(
        "Admin sent password reset for %s to %s",
        mask_hash(pnr_hash),
        mask_hash(email_hash),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "message": "Återställningsmejl skickat.", "link": link})


@app.post("/admin/api/foretagskonto/skapa")
def admin_create_supervisor_route():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip()
    name = (payload.get("name") or "").strip()
    if not email or not name:
        logging.debug("Admin create_supervisor without email or name", extra={"admin": admin_name})
        return jsonify({"status": "error", "message": "Ange namn och e-post."}), 400

    try:
        normalized_email = functions.normalize_email(email)
    except ValueError:
        logging.debug(
            "Admin create_supervisor with invalid email: %s", email, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ogiltig e-postadress."}), 400

    if not functions.admin_create_supervisor(normalized_email, name):
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Företagskontot finns redan eller väntar på aktivering.",
                }
            ),
            409,
        )

    email_hash = functions.get_supervisor_email_hash(normalized_email)
    link = url_for("supervisor_create", email_hash=email_hash, _external=True)

    try:
        email_service.send_creation_email(normalized_email, link)
    except RuntimeError:
        logger.exception("Failed to send supervisor creation email to %s", email_hash)
        return (
            jsonify({"status": "error", "message": "Det gick inte att skicka inloggningslänken."}),
            500,
        )

    functions.log_admin_action(
        admin_name,
        "skapade företagskonto",
        f"email_hash={email_hash}",
    )
    logging.info("Admin created supervisor %s", mask_hash(email_hash), extra={"admin": admin_name})
    return jsonify({"status": "success", "message": "Företagskonto skapat.", "link": link})


@app.post("/admin/api/foretagskonto/koppla")
def admin_link_supervisor_route():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    orgnr = (payload.get("orgnr") or "").strip()
    personnummer = (payload.get("personnummer") or "").strip()
    if not orgnr or not personnummer:
        logging.debug(
            "Admin link_supervisor without orgnr or personnummer", extra={"admin": admin_name}
        )
        return jsonify(
            {"status": "error", "message": "Ange organisationsnummer och personnummer."}
        ), 400

    try:
        success, reason, email_hash = functions.admin_link_supervisor_to_user(orgnr, personnummer)
    except ValueError:
        logging.debug(
            "Admin link_supervisor with invalid orgnr or personnummer: %s, %s",
            orgnr,
            personnummer,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ogiltiga uppgifter."}), 400

    if not success:
        status_code = 400
        message = "Åtgärden kunde inte utföras."
        if reason == "missing_supervisor":
            status_code = 404
            message = "Företagskontot finns inte."
        elif reason == "missing_user":
            status_code = 404
            message = "Standardkontot finns inte."
        elif reason == "exists":
            status_code = 409
            message = "Kopplingen finns redan."
        logging.debug("Admin link_supervisor failed: %s", reason, extra={"admin": admin_name})
        return jsonify({"status": "error", "message": message}), status_code

    if not email_hash:
        logging.debug(
            "Admin link_supervisor missing email hash for orgnr %s",
            orgnr,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Företagskontot hittades inte."}), 404
    normalized_orgnr = functions.validate_orgnr(orgnr)
    normalized_personnummer = functions.normalize_personnummer(personnummer)
    personnummer_hash = functions.hash_value(normalized_personnummer)
    functions.log_admin_action(
        admin_name,
        "kopplade företagskonto",
        f"orgnr={normalized_orgnr}, email_hash={email_hash}, personnummer_hash={personnummer_hash}",
    )
    logging.info(
        "Admin linked supervisor %s to user %s",
        mask_hash(email_hash),
        mask_hash(personnummer_hash),
        extra={"admin": admin_name},
    )
    return jsonify(
        {"status": "success", "message": "Företagskontot har kopplats till standardkontot."}
    )


@app.post("/admin/api/foretagskonto/oversikt")
def admin_supervisor_overview():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    orgnr = (payload.get("orgnr") or "").strip()
    if not orgnr:
        logging.debug("Admin supervisor_overview without orgnr", extra={"admin": admin_name})
        return jsonify({"status": "error", "message": "Ange organisationsnummer."}), 400

    try:
        details = functions.get_supervisor_login_details_for_orgnr(orgnr)
    except ValueError:
        logging.debug(
            "Admin supervisor_overview with invalid orgnr: %s", orgnr, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ogiltigt organisationsnummer."}), 400

    if not details:
        logging.debug(
            "Admin supervisor_overview not found for orgnr: %s", orgnr, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Företagskontot hittades inte."}), 404

    email_hash = details["email_hash"]
    overview = functions.get_supervisor_overview(email_hash)
    if not overview:
        logging.debug(
            "Admin supervisor_overview not found for email hash: %s",
            email_hash,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Företagskontot hittades inte."}), 404

    functions.log_admin_action(
        admin_name,
        "visade företagskontoöversikt",
        f"orgnr={details['orgnr']}, email_hash={email_hash}",
    )
    logging.debug(
        "Admin supervisor_overview for %s with %d users",
        mask_hash(email_hash),
        len(overview.get("users", [])),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "data": overview})


@app.post("/admin/api/foretagskonto/ta-bort")
def admin_remove_supervisor_connection():  # pragma: no cover
    admin_name = _require_admin()
    if not validate_csrf_token():
        return jsonify({"status": "error", "message": "Ogiltig CSRF-token."}), 403
    payload = request.get_json(silent=True) or {}
    orgnr = (payload.get("orgnr") or "").strip()
    personnummer = (payload.get("personnummer") or "").strip()
    personnummer_hash = (payload.get("personnummer_hash") or "").strip()
    if not orgnr or (not personnummer and not personnummer_hash):
        return jsonify(
            {
                "status": "error",
                "message": "Ange organisationsnummer och personnummer eller hash.",
            }
        ), 400

    try:
        details = functions.get_supervisor_login_details_for_orgnr(orgnr)
        if personnummer:
            normalized_personnummer = functions.normalize_personnummer(personnummer)
            personnummer_hash = functions.hash_value(normalized_personnummer)
        elif not functions._is_valid_hash(personnummer_hash):
            raise ValueError("Ogiltig hash")
    except ValueError:
        return jsonify({"status": "error", "message": "Ogiltiga uppgifter."}), 400

    if not details:
        return jsonify({"status": "error", "message": "Företagskontot hittades inte."}), 404

    if not functions.supervisor_has_access(details["email_hash"], personnummer_hash):
        return jsonify({"status": "error", "message": "Kopplingen hittades inte."}), 404

    if not functions.supervisor_remove_connection(details["email_hash"], personnummer_hash):
        return jsonify({"status": "error", "message": "Kunde inte ta bort kopplingen."}), 400

    functions.log_admin_action(
        admin_name,
        "tog bort företagskoppling",
        f"orgnr={details['orgnr']}, email_hash={details['email_hash']}, personnummer_hash={personnummer_hash}",
    )
    logging.info(
        "Admin removed supervisor connection for %s",
        mask_hash(personnummer_hash),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "message": "Kopplingen har tagits bort."})


@app.post("/admin/api/foretagskonto/uppdatera-koppling")
def admin_change_supervisor_connection():  # pragma: no cover
    admin_name = _require_admin()
    if not validate_csrf_token():
        return jsonify({"status": "error", "message": "Ogiltig CSRF-token."}), 403
    payload = request.get_json(silent=True) or {}
    from_orgnr = (payload.get("from_orgnr") or "").strip()
    to_orgnr = (payload.get("to_orgnr") or "").strip()
    personnummer = (payload.get("personnummer") or "").strip()
    if not from_orgnr or not to_orgnr or not personnummer:
        return jsonify(
            {
                "status": "error",
                "message": "Ange nuvarande organisationsnummer, nytt organisationsnummer och personnummer.",
            }
        ), 400

    try:
        from_details = functions.get_supervisor_login_details_for_orgnr(from_orgnr)
        to_details = functions.get_supervisor_login_details_for_orgnr(to_orgnr)
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        return jsonify({"status": "error", "message": "Ogiltiga uppgifter."}), 400

    if not from_details or not to_details:
        return jsonify({"status": "error", "message": "Företagskontot hittades inte."}), 404

    personnummer_hash = functions.hash_value(normalized_personnummer)
    if not functions.supervisor_has_access(from_details["email_hash"], personnummer_hash):
        return jsonify({"status": "error", "message": "Den gamla kopplingen hittades inte."}), 404

    if not functions.supervisor_remove_connection(from_details["email_hash"], personnummer_hash):
        return jsonify(
            {"status": "error", "message": "Kunde inte ta bort den gamla kopplingen."}
        ), 400

    success, reason, email_hash = functions.admin_link_supervisor_to_user(
        to_orgnr, normalized_personnummer
    )
    if not success:
        rollback_success, rollback_reason, rollback_email_hash = (
            functions.admin_link_supervisor_to_user(from_orgnr, normalized_personnummer)
        )
        message = "Kunde inte skapa den nya kopplingen."
        if reason == "missing_supervisor":
            message = "Det nya företagskontot hittades inte."
        elif reason == "missing_user":
            message = "Standardkontot hittades inte."
        elif reason == "exists":
            message = "Det finns redan en koppling till det nya företagskontot."
        if not rollback_success:
            logger.error(
                "Rollback misslyckades vid ändring av koppling: reason=%s, rollback_reason=%s, rollback_email_hash=%s",
                reason,
                rollback_reason,
                rollback_email_hash,
            )
            return jsonify(
                {
                    "status": "error",
                    "message": (f"{message} Rollback misslyckades: {rollback_reason}."),
                }
            ), 500
        return jsonify({"status": "error", "message": message}), 400

    functions.log_admin_action(
        admin_name,
        "ändrade företagskoppling",
        (
            f"from_orgnr={from_details['orgnr']}, to_orgnr={to_details['orgnr']}, "
            f"email_hash={email_hash}, personnummer_hash={personnummer_hash}"
        ),
    )
    logging.info(
        "Admin changed supervisor connection for %s",
        mask_hash(personnummer_hash),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "message": "Kopplingen har uppdaterats."})


@app.post("/admin/api/foretagskonto/radera")
def admin_delete_supervisor_account_route():  # pragma: no cover
    admin_name = _require_admin()
    if not validate_csrf_token():
        return jsonify({"status": "error", "message": "Ogiltig CSRF-token."}), 403
    payload = request.get_json(silent=True) or {}
    orgnr = (payload.get("orgnr") or "").strip()
    if not orgnr:
        return jsonify({"status": "error", "message": "Ange organisationsnummer."}), 400

    try:
        deleted, summary, normalized_orgnr = functions.admin_delete_supervisor_account(orgnr)
    except ValueError:
        return jsonify({"status": "error", "message": "Ogiltigt organisationsnummer."}), 400
    except Exception:
        logger.exception("Misslyckades att radera företagskonto för %s", orgnr)
        return jsonify({"status": "error", "message": "Kunde inte radera företagskontot."}), 500

    if not deleted:
        return jsonify({"status": "error", "message": "Företagskontot hittades inte."}), 404

    summary_details = ", ".join(f"{key}={value}" for key, value in summary.items())
    functions.log_admin_action(
        admin_name,
        "raderade företagskonto",
        f"orgnr={normalized_orgnr}, {summary_details}",
    )
    logging.info(
        "Admin deleted supervisor account for %s",
        normalized_orgnr,
        extra={"admin": admin_name},
    )
    return jsonify(
        {
            "status": "success",
            "message": "Företagskontot har raderats.",
            "data": summary,
        }
    )


@app.get("/admin/avancerat")
def admin_advanced():  # pragma: no cover
    if not session.get("admin_logged_in"):
        logger.warning("Unauthorized admin advanced GET")
        return redirect("/login_admin")
    tables = sorted(functions.TABLE_REGISTRY.keys())
    return render_template("admin_advanced.html", tables=tables)


@app.get("/admin/advanced/api/schema/<table_name>")
def admin_advanced_schema(table_name: str):  # pragma: no cover
    _require_admin()
    try:
        schema = functions.get_table_schema(table_name)
    except ValueError:
        logging.debug("Admin advanced schema with unknown table: %s", table_name)
        return jsonify({"status": "error", "message": "Okänd tabell."}), 404
    logging.debug("Admin advanced schema for table: %s", table_name)
    return jsonify({"status": "success", "schema": schema})


@app.get("/admin/advanced/api/rows/<table_name>")
def admin_advanced_rows(table_name: str):  # pragma: no cover
    _require_admin()
    search_term = request.args.get("sok")
    limit = request.args.get("limit", type=int) or 100
    try:
        rows = functions.fetch_table_rows(table_name, search_term, limit)
    except ValueError:
        logging.debug("Admin advanced rows with unknown table: %s", table_name)
        return jsonify({"status": "error", "message": "Okänd tabell."}), 404
    logging.debug(
        "Admin advanced rows for table: %s, search: %r, limit: %d", table_name, search_term, limit
    )
    return jsonify({"status": "success", "rows": rows})


@app.post("/admin/advanced/api/rows/<table_name>")
def admin_advanced_create(table_name: str):  # pragma: no cover
    admin_name = _require_admin()
    values = request.get_json(silent=True) or {}
    try:
        row = functions.create_table_row(table_name, values)
    except ValueError as exc:
        logger.warning(f"Error in create_table_row: {exc}")
        return jsonify({"status": "error", "message": "Kunde inte skapa posten."}), 400
    functions.log_admin_action(
        admin_name,
        "skapade post",
        f"tabell={table_name}",
    )
    logging.info("Admin created row in table %s: %s", table_name, row, extra={"admin": admin_name})
    return jsonify({"status": "success", "row": row}), 201


@app.put("/admin/advanced/api/rows/<table_name>/<int:row_id>")
def admin_advanced_update(table_name: str, row_id: int):  # pragma: no cover
    admin_name = _require_admin()
    values = request.get_json(silent=True) or {}
    try:
        updated = functions.update_table_row(table_name, row_id, values)
    except ValueError as exc:
        logger.exception(f"Failed to update row in table '{table_name}', id={row_id}: {exc}")
        return jsonify({"status": "error", "message": "Felaktiga data."}), 400
    if not updated:
        logging.debug("Admin advanced update with missing row: table=%s, id=%d", table_name, row_id)
        return jsonify({"status": "error", "message": "Posten hittades inte."}), 404
    functions.log_admin_action(
        admin_name,
        "uppdaterade post",
        f"tabell={table_name}, id={row_id}",
    )
    logging.info(
        "Admin updated row in table %s, id=%d: %s",
        table_name,
        row_id,
        values,
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success"})


@app.delete("/admin/advanced/api/rows/<table_name>/<int:row_id>")
def admin_advanced_delete(table_name: str, row_id: int):  # pragma: no cover
    admin_name = _require_admin()
    try:
        deleted = functions.delete_table_row(table_name, row_id)
    except ValueError:
        logging.debug("Admin advanced delete with unknown table: %s", table_name)
        return jsonify({"status": "error", "message": "Okänd tabell."}), 404
    if not deleted:
        logging.debug("Admin advanced delete with missing row: table=%s, id=%d", table_name, row_id)
        return jsonify({"status": "error", "message": "Posten hittades inte."}), 404
    functions.log_admin_action(
        admin_name,
        "raderade post",
        f"tabell={table_name}, id={row_id}",
    )
    logging.info(
        "Admin deleted row in table %s, id=%d", table_name, row_id, extra={"admin": admin_name}
    )
    return jsonify({"status": "success"})


@app.route("/verify_certificate/<personnummer>", methods=["GET"])
def verify_certificate_route(personnummer):  # pragma: no cover
    # Allow an admin to verify whether a user's certificate is confirmed.
    #
    # Uses a cached lookup to avoid repeated database queries for the same
    # ``personnummer``. Returns a JSON response indicating the verification
    # status. If the certificate isn't verified, an informative message is sent
    # back to the administrator.
    if not session.get("admin_logged_in"):
        logger.warning("Unauthorized certificate verification attempt")
        return redirect("/login_admin")

    if functions.verify_certificate(personnummer):
        logger.info("Certificate for %s is verified", mask_hash(functions.hash_value(personnummer)))
        return jsonify({"status": "success", "verified": True})
    logger.info("Certificate for %s is NOT verified", mask_hash(functions.hash_value(personnummer)))
    return jsonify(
        {
            "status": "error",
            "message": "Standardkontots certifikat är inte verifierat",
        }
    ), 404


@app.route("/login_admin", methods=["POST", "GET"])
def login_admin():  # pragma: no cover
    # Authenticate an administrator for access to the admin panel.
    if request.method == "POST":
        admin_password = os.getenv("admin_password")
        admin_username = os.getenv("admin_username")

        # Require admin credentials to be explicitly set (no insecure defaults)
        if not admin_password or not admin_username:
            error_msg = "FATAL: admin_username and admin_password environment variables must be set and non-empty"
            logger.critical(error_msg)
            critical_events.send_critical_error_notification(error_message=error_msg, endpoint="/login_admin", user_ip=get_request_ip())
            raise RuntimeError(error_msg)
        if (
            request.form["username"] == admin_username
            and request.form["password"] == admin_password
        ):
            session["admin_logged_in"] = True
            session["admin_username"] = admin_username
            logger.info("Admin %s logged in", admin_username)
            return redirect("/admin")
        else:
            logger.warning("Invalid admin login attempt for %s", request.form["username"])
            return jsonify({"status": "error", "message": "Ogiltiga inloggningsuppgifter"})

    elif request.method == "GET":
        logger.debug("Rendering admin login page")
        return render_template("admin_login.html")
    else:
        logger.warning("Invalid request method %s to login_admin", request.method)
        return jsonify(
            {"status": "error", "message": "Ogiltig HTTP-metod", "method": request.method}
        )


@app.route("/logout")
def logout():
    # Logga ut både admin och användare.
    logger.info("Logging out user and admin")
    session.pop("user_logged_in", None)
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    session.pop("personnummer", None)
    session.pop("personnummer_raw", None)
    session.pop("supervisor_logged_in", None)
    session.pop("supervisor_email_hash", None)
    session.pop("supervisor_name", None)
    session.pop("supervisor_orgnr", None)
    return redirect("/")


## -------------------------Error Handlers -------------------------##
@app.route("/error")
def error():  # pragma: no cover
    # Intentionally raise an error to test the 500 page.
    # This will cause a 500 Internal Server Error
    raise Exception("Testing 500 error page")


@app.errorhandler(500)
def internal_server_error(_):  # pragma: no cover
    logger.error("500 Internal Server Error: %s", request.path)

    try:
        user_ip = get_request_ip()
        endpoint = request.path
        error_msg = f"Endpoint: {endpoint}\nMetod: {request.method}\nIP: {user_ip}"
        critical_events.send_critical_error_notification(
            error_message=error_msg, endpoint=endpoint, user_ip=user_ip
        )
    except Exception as e:
        logger.warning("Kunde inte skicka error-notifikation: %s", e)

    # Visa en användarvänlig 500-sida när ett serverfel inträffar.
    error_code = 500
    error_message = "Ett internt serverfel har inträffat. Vänligen försök igen senare."
    return render_template(
        "error.html", error_code=error_code, error_message=error_message, time=time.time()
    ), 500


@app.errorhandler(Exception)
def handle_unexpected_exception(error: Exception):  # pragma: no cover
    # Logga oväntade fel och låt HTTP-fel hanteras av sina egna handlers.
    if isinstance(error, HTTPException):
        return error
    logger.exception("Oväntat fel inträffade: %s", str(error))
    return internal_server_error(error)


@app.errorhandler(401)
def unauthorized_error(_):  # pragma: no cover
    # Visa en användarvänlig 401-sida vid obehörig åtkomst.
    logger.warning("401 Unauthorized: %s", request.path)
    error_code = 401
    error_message = "Du måste vara inloggad för att se denna sida."
    return render_template(
        "error.html", error_code=error_code, error_message=error_message, time=time.time()
    ), 401


@app.errorhandler(409)
def conflict_error(_):  # pragma: no cover
    # Visa en användarvänlig 409-sida vid konflikt.
    logger.error("409 Conflict: %s", request.path)
    error_code = 409
    error_message = "Det uppstod en konflikt vid hantering av din begäran."
    return render_template(
        "error.html", error_code=error_code, error_message=error_message, time=time.time()
    ), 409


@app.errorhandler(404)
def page_not_found(_):  # pragma: no cover
    # Visa en användarvänlig 404-sida när en sida saknas.
    logger.warning("Page not found: %s", request.path)
    error_code = 404
    error_message = "Sidan du letade efter kunde inte hittas."
    return render_template(
        "error.html", error_code=error_code, error_message=error_message, time=time.time()
    ), 404


##----------------------------------------##


@app.template_filter("datetimeformat")
def datetimeformat(value, format="%Y-%m-%d %H:%M:%S"):  # pragma: no cover
    # Format a POSIX timestamp for display in templates.
    import datetime

    return datetime.datetime.fromtimestamp(value).strftime(format)


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
        logger.info("Application interrupted by user")
        try:
            critical_events.send_shutdown_notification("Applikationen stängdes av normalt.")
        except Exception as e:
            logger.warning("Failed to send shutdown alert: %s", e)
    except Exception as e:
        logger.critical("Application crashed with exception: %s", e, exc_info=True)
        try:
            error_details = f"Exception: {type(e).__name__}\nMessage: {str(e)}"
            critical_events.send_crash_notification(error_details)
        except Exception as alert_error:
            logger.warning("Failed to send crash alert: %s", alert_error)
        raise

# © 2025 Liam Suorsa. All rights reserved.
