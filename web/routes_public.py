# Copyright (c) Liam Suorsa and Mika Suorsa
"""Publika routes och formulärflöden."""
from __future__ import annotations
from pathlib import Path
from flask import Flask, abort, current_app, flash, redirect, render_template, request, send_from_directory, session, url_for
import functions
from functions import security as sec
from functions.emails import service as email_service
from functions.logging import configure_module_logger, mask_hash
from functions.requests import as_bool, get_request_ip
from web.helpers import (
    ALLOWED_SUPERVISOR_ACTIVATION_ERRORS,
    CSRF_EXPIRED_MESSAGE,
    TOO_MANY_ATTEMPTS_MESSAGE,
    _render_create_supervisor_page,
    _safe_user_error,
)
logger = configure_module_logger("app")
validate_csrf_token = sec.validate_csrf_token


def _register_public_submission(client_ip: str | None) -> bool:
    # Tester patchar den publika ytan i app.py. Genom att läsa funktionen därifrån
    # bevarar vi samma krok även efter att routen flyttats till web/.
    import app as app_module

    return app_module.register_public_submission(client_ip)

def health() -> tuple[dict, int]:
    # Basic health check endpoint.
    return {"status": "ok"}, 200



def inject_flags():
    # Expose flags indicating debug-läge to Jinja templates.
    return {
        "IS_DEV": current_app.debug,
    }


def robots_txt():
    # Serve robots.txt to disallow all crawlers.
    if current_app.static_folder is None:
        abort(404)
    return send_from_directory(current_app.static_folder, "robots.txt", mimetype="text/plain")


def sitemap_xml():
    # Serve sitemap.xml with public URLs only.
    if current_app.static_folder is None:
        abort(404)
    return send_from_directory(current_app.static_folder, "sitemap.xml", mimetype="application/xml")


def mta_sts_policy():
    # Serve MTA-STS policyfilen för den dedikerade mta-sts-domänen.
    mta_sts_directory = Path(current_app.root_path) / "deploy" / "mta-sts" / ".well-known"
    return send_from_directory(mta_sts_directory, "mta-sts.txt", mimetype="text/plain")


def debug_clear_session():
    if not current_app.config.get("DEV_MODE") or not current_app.debug:
        abort(404)
    session.clear()
    return redirect("/")


def create_user(pnr_hash: str):  # type: ignore[no-untyped-def]
    # Allow a pending user to set a password and activate the account.
    logger.info("Hanterar create_user för hash %s", pnr_hash)
    if request.method == "POST":
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()
        if password != confirm:
            return _render_create_supervisor_page(error="Lösenorden måste matcha.", invalid=False)
        if len(password) < 8:
            return _render_create_supervisor_page(error="Lösenordet måste vara minst 8 tecken långt.", invalid=False)
        logger.debug("Skapar användare med hash %s", pnr_hash)
        if not functions.user_create_user(password, pnr_hash):
            logger.warning("Kunde inte skapa användare för hash %s", pnr_hash)
            return _render_create_supervisor_page(
                error=("Kontot kunde inte aktiveras. Kontrollera att länken är giltig."),
                invalid=False,
            )
        flash(
            "L\u00f6senordet \u00e4r skapat. Du kan nu logga in p\u00e5 ditt privatkonto.",
            "success",
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
    logger.warning("Användarhash %s hittades inte under create_user", pnr_hash)
    abort(404, description="Standardkonto hittades inte")



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



def home():
    # Render the landing page.
    logger.debug("Renderar startsida")
    return render_template("index.html")


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


def _handle_standard_account_registration():
    form_errors: list[str] = []
    field_errors = {
        "name": False,
        "email": False,
        "personnummer": False,
        "terms_confirmed": False,
    }
    form_data = {
        "name": "",
        "email": "",
        "personnummer": "",
        "terms_confirmed": "",
    }
    status_code = 200

    if request.method == "POST":
        for key in form_data:
            form_data[key] = (request.form.get(key, "") or "").strip()
        if not validate_csrf_token():
            form_errors.append(CSRF_EXPIRED_MESSAGE)
        else:
            client_ip = get_request_ip()
            if not _register_public_submission(client_ip):
                status_code = 429
                form_errors.append(TOO_MANY_ATTEMPTS_MESSAGE)
            else:
                if not as_bool(form_data.get("terms_confirmed")):
                    field_errors["terms_confirmed"] = True
                    form_errors.append(
                        "Du m\u00e5ste intyga att du har l\u00e4st och f\u00f6rst\u00e5tt villkoren och den juridiska informationen innan du skapar kontot."
                    )
                if not form_errors:
                    class _ActivationEmailDeliveryError(RuntimeError):
                        pass

                    try:
                        def _send_creation_email_before_commit(
                            registration_result: dict[str, str],
                        ) -> None:
                            creation_link = url_for(
                                "create_user",
                                pnr_hash=registration_result["personnummer_hash"],
                                _external=True,
                            )
                            try:
                                email_service.send_creation_email(
                                    registration_result["email"],
                                    creation_link,
                                )
                            except Exception as exc:
                                raise _ActivationEmailDeliveryError from exc

                        functions.register_standard_account(
                            form_data["name"],
                            form_data["email"],
                            form_data["personnummer"],
                            before_commit=_send_creation_email_before_commit,
                        )
                        logger.info(
                            "Nytt privatkonto registrerat f\u00f6r %s",
                            mask_hash(functions.hash_value(form_data["email"].lower())),
                        )
                        return redirect(url_for("standard_account_registered"))
                    except ValueError as exc:
                        message = str(exc)
                        form_errors.append(message)
                        _flag_application_field_error(message, field_errors)
                    except _ActivationEmailDeliveryError:
                        logger.exception(
                            "Privatkonto kunde inte skapas eftersom aktiveringsmejlet inte gick att skicka"
                        )
                        form_errors.append(
                            "Det gick inte att skicka aktiveringsmejlet just nu. Försök igen senare."
                        )
                    except Exception:
                        logger.exception("Kunde inte skapa privatkonto")
                        form_errors.append(
                            "Det gick inte att skapa kontot just nu. F\u00f6rs\u00f6k igen senare."
                        )

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


def apply_standardkonto():
    """Visa och hantera ansökan för standardkonto."""

    return _handle_standard_account_registration()


def standard_account_registered():
    """Visa bekräftelse efter skapad standardkontoansökan."""

    return render_template("standard_account_registered.html")


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
            if not _register_public_submission(client_ip):
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
                        try:
                            email_service.new_application_email_to_support(
                                account_type=account_type
                            )
                        except Exception:  # pragma: no cover - e-postfel ska inte stoppa ansökan
                            logger.exception(
                                "Ansökan sparades men supportmejl kunde inte skickas"
                            )
                    except ValueError as exc:
                        message = str(exc)
                        form_errors.append(message)
                        _flag_application_field_error(message, field_errors)
                    except Exception:  # pragma: no cover - defensiv loggning
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


def terms_of_service():
    """Visa sidan med villkor."""

    return render_template("terms_of_service.html")


def application_submitted():
    """Visa bekräftelse och nästa steg efter inskickad ansökan."""

    raw_type = request.args.get("account_type", "").strip().lower()
    account_type = "företagskonto" if raw_type == "foretagskonto" else "standardkonto"
    return render_template("application_submitted.html", account_type=account_type)


def public_organization_search():
    search_value = (request.args.get("orgnr") or "").strip()
    result = None
    form_error = None

    if search_value:
        try:
            result = functions.get_public_organization_overview(search_value)
        except ValueError:
            form_error = "Kontrollera organisationsnumret och f\u00f6rs\u00f6k igen."

    return render_template(
        "public_organization_search.html",
        form_data={"orgnr": search_value},
        form_error=form_error,
        result=result,
    )


def pricing():
    """Visa prislistan."""

    return render_template("pris.html")


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
            logger.warning("Tomt lösenord angavs för %s", mask_hash(personnummer_hash))
            return (
                render_template(
                    "user_login.html",
                    error="Ogiltiga inloggningsuppgifter",
                    csrf_token=csrf_token,
                ),
                401,
            )
        logger.debug("Inloggningsförsök för %s", mask_hash(personnummer_hash))
        if functions.check_personnummer_password(personnummer, password):
            session["user_logged_in"] = True
            session["personnummer"] = personnummer_hash
            session["personnummer_raw"] = personnummer
            session["username"] = functions.get_username_by_personnummer_hash(personnummer_hash)
            logger.info("Användare %s loggade in", mask_hash(personnummer_hash))
            return redirect("/dashboard")

        error_message = "Ogiltiga inloggningsuppgifter"
        if functions.check_pending_user(personnummer):
            logger.warning(
                "Inloggning nekades för ej verifierat konto %s",
                mask_hash(personnummer_hash),
            )
            error_message = (
                "Du behöver verifiera din e-postadress via länken i mejlet innan du kan logga in."
            )
        else:
            logger.warning("Ogiltig inloggning för %s", mask_hash(personnummer_hash))
        return (
            render_template(
                "user_login.html",
                error=error_message,
                csrf_token=csrf_token,
            ),
            401,
        )
    logger.debug("Renderar inloggningssida")
    return render_template("user_login.html", csrf_token=csrf_token)



def gdpr_info():
    return render_template("gdpr.html")

def register_public_routes(app: Flask) -> None:
    app.context_processor(inject_flags)
    app.add_url_rule("/health", view_func=health)
    app.add_url_rule("/robots.txt", view_func=robots_txt)
    app.add_url_rule("/sitemap.xml", view_func=sitemap_xml)
    app.add_url_rule("/.well-known/mta-sts.txt", view_func=mta_sts_policy)
    app.add_url_rule("/debug/clear-session", methods=["GET", "POST"], view_func=debug_clear_session)
    app.add_url_rule("/create_user/<pnr_hash>", methods=["POST", "GET"], view_func=create_user)
    app.add_url_rule("/aterstall-losenord/<token>", methods=["GET", "POST"], view_func=password_reset)
    app.add_url_rule("/", methods=["GET"], view_func=home)
    app.add_url_rule("/ansok", methods=["GET"], view_func=apply_account)
    app.add_url_rule("/ansok/standardkonto", methods=["GET", "POST"], view_func=apply_standardkonto)
    app.add_url_rule("/ansok/standardkonto/klart", methods=["GET"], view_func=standard_account_registered)
    app.add_url_rule("/ansok/foretagskonto", methods=["GET", "POST"], view_func=apply_foretagskonto)
    app.add_url_rule("/villkor", methods=["GET"], view_func=terms_of_service)
    app.add_url_rule("/ansok/klart", methods=["GET"], view_func=application_submitted)
    app.add_url_rule("/organisationer", methods=["GET"], view_func=public_organization_search)
    app.add_url_rule("/pris", methods=["GET"], view_func=pricing)
    app.add_url_rule("/login", methods=["GET", "POST"], view_func=login)
    app.add_url_rule("/gdpr", methods=["GET"], view_func=gdpr_info)

# Copyright (c) Liam Suorsa and Mika Suorsa
