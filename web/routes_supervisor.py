# Copyright (c) Liam Suorsa and Mika Suorsa
"""Routes för företagskonton och organisationskopplingar."""
from __future__ import annotations
from typing import Callable
from flask import Flask, Response, abort, flash, make_response, redirect, render_template, request, session, url_for
from flask.typing import ResponseReturnValue
import functions
from course_categories import labels_for_slugs
from functions import security as sec
from functions.emails import service as email_service
from functions.logging import configure_module_logger, mask_email, mask_email_reference, mask_hash
from web.helpers import (
    ALLOWED_SUPERVISOR_ACTIVATION_ERRORS,
    CSRF_EXPIRED_MESSAGE,
    _require_supervisor,
    _safe_user_error,
)
logger = configure_module_logger("app")
validate_csrf_token = sec.validate_csrf_token

def supervisor_create(activation_token: str):
    pending_email = functions.get_pending_supervisor_email_by_token(activation_token)
    if request.method == "POST":
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()
        if password != confirm:
            return render_template(
                "create_supervisor.html",
                error="Lösenorden måste matcha.",
                invalid=False,
            )
        if not pending_email:
            return render_template("create_supervisor.html", invalid=True)
        try:
            if not functions.supervisor_activate_account(pending_email, password):
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
        logger.info("Handledarkonto aktiverat för %s", mask_email_reference(pending_email))
        return redirect(url_for("supervisor_login"))

    if pending_email:
        return render_template("create_supervisor.html", invalid=False)
    logger.warning("Handledarens aktiveringslänk hittades inte eller har förbrukats")
    return render_template("create_supervisor.html", invalid=True)


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
            mask_email_reference(email_hash),
            mask_hash(functions.hash_value(normalized_orgnr)),
        )
        return redirect(url_for("supervisor_dashboard"))

    return render_template("supervisor_login.html", csrf_token=csrf_token)


def supervisor_dashboard():
    if not session.get("supervisor_logged_in"):
        return redirect(url_for("supervisor_login"))
    email_hash, supervisor_name = _require_supervisor()
    supervisor_orgnr = (session.get("supervisor_orgnr") or "").strip()
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

    company_name = None
    organization_link_requests = []
    if supervisor_orgnr:
        try:
            overview = functions.get_public_organization_overview(supervisor_orgnr)
        except ValueError:
            overview = {}
        company_name = overview.get("company_name")
        organization_link_requests = functions.list_pending_organization_link_requests(
            supervisor_orgnr
        )
        status_labels = {
            "active": "Aktivt privatkonto",
            "pending": "Inv\u00e4ntar l\u00f6senord",
            "missing": "Kontot kunde inte hittas",
        }
        for entry in organization_link_requests:
            entry["account_status_label"] = status_labels.get(
                entry.get("account_status", ""),
                "Ok\u00e4nd status",
            )

    return render_template(
        "supervisor_dashboard.html",
        company_name=company_name,
        organization_link_requests=organization_link_requests,
        supervisor_orgnr=supervisor_orgnr,
        supervisor_name=supervisor_name,
        users=users,
        csrf_token=csrf_token,
    )


def _handle_org_link_request_action(
    request_id: int,
    action_func: Callable[[int, str, str], tuple[bool, dict[str, str] | None, str]],
    email_sender: Callable[[str, str], None],
    success_message: str,
    email_failure_message: str,
    failure_messages: dict[str, str],
    fallback_message: str,
    email_log_message: str,
) -> ResponseReturnValue:
    email_hash, _ = _require_supervisor()
    supervisor_orgnr = (session.get("supervisor_orgnr") or "").strip()
    redirect_target = f"{url_for('supervisor_dashboard')}#organization-link-requests"
    if not validate_csrf_token():
        flash(CSRF_EXPIRED_MESSAGE, "error")
        return redirect(redirect_target)
    if not supervisor_orgnr:
        flash("F\u00f6retagskontot saknar organisationsnummer.", "error")
        return redirect(redirect_target)

    success, request_data, reason = action_func(
        request_id,
        email_hash,
        supervisor_orgnr,
    )
    if not success:
        flash(failure_messages.get(reason, fallback_message), "error")
        return redirect(redirect_target)
    if request_data is None:
        flash(fallback_message, "error")
        return redirect(redirect_target)

    try:
        overview = functions.get_public_organization_overview(supervisor_orgnr)
    except ValueError:
        company_name = f"organisationsnummer {supervisor_orgnr}"
    else:
        company_name = overview.get("company_name") or f"organisationsnummer {supervisor_orgnr}"

    try:
        email_sender(request_data["user_email"], company_name)
    except Exception:
        logger.exception(email_log_message, request_id)
        flash(email_failure_message, "error")
    else:
        flash(success_message, "success")

    return redirect(redirect_target)


def supervisor_approve_organization_link_request_route(request_id: int):
    return _handle_org_link_request_action(
        request_id,
        functions.approve_organization_link_request,
        email_service.send_organization_link_approved_email,
        "Kopplingen har godk\u00e4nts och privatpersonen har informerats via e-post.",
        "Kopplingen godk\u00e4ndes men bekr\u00e4ftelsemejlet kunde inte skickas till privatpersonen.",
        {
            "missing_request": "F\u00f6rfr\u00e5gan kunde inte hittas.",
            "missing_user": "Privatkontot finns inte l\u00e4ngre kvar.",
            "handled_request": "F\u00f6rfr\u00e5gan \u00e4r redan hanterad.",
        },
        "Kopplingen kunde inte godk\u00e4nnas.",
        "Koppling godk\u00e4nd men mejl kunde inte skickas till privatkonto f\u00f6r org-f\u00f6rfr\u00e5gan %s",
    )


def supervisor_reject_organization_link_request_route(request_id: int):
    return _handle_org_link_request_action(
        request_id,
        functions.reject_organization_link_request,
        email_service.send_organization_link_rejected_email,
        "F\u00f6rfr\u00e5gan har avslagits och privatpersonen har informerats via e-post.",
        "F\u00f6rfr\u00e5gan avslogs men bekr\u00e4ftelsemejlet kunde inte skickas till privatpersonen.",
        {
            "missing_request": "F\u00f6rfr\u00e5gan kunde inte hittas.",
            "handled_request": "F\u00f6rfr\u00e5gan \u00e4r redan hanterad.",
        },
        "Kopplingen kunde inte avsl\u00e5s.",
        "Koppling avslogs men mejl kunde inte skickas till privatkonto f\u00f6r org-f\u00f6rfr\u00e5gan %s",
    )


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


def supervisor_download_pdf(person_hash: str, pdf_id: int):
    email_hash, _ = _require_supervisor()
    if not functions.supervisor_has_access(email_hash, person_hash):
        logger.warning(
            "Handledare %s försökte komma åt pdf %s för %s utan behörighet",
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
        "Handledare %s hämtar %s för %s",
        email_hash,
        filename,
        person_hash,
    )
    response = make_response(content)
    response.headers["Content-Type"] = "application/pdf"
    disposition = "attachment" if as_attachment else "inline"
    response.headers["Content-Disposition"] = f'{disposition}; filename="{filename}"'
    return response


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
            "Handledare %s försökte dela pdf %s för %s utan behörighet",
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
        logger.error(
            "Misslyckades med att dela pdf %s för %s av handledare %s",
            pdf_id,
            person_hash,
            email_hash,
        )
        flash("Ett internt fel inträffade när intyget skulle delas.", "error")
        return redirect(redirect_target)

    logger.info(
        "Handledare %s delade pdf %s för %s till %s",
        email_hash,
        pdf_id,
        person_hash,
        mask_email(normalized_recipient),
    )
    flash("Intyget har skickats via e-post.", "success")
    return redirect(redirect_target)


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
        logger.info(
            "Handledare %s tog bort åtkomst till %s",
            mask_email_reference(email_hash),
            person_hash,
        )
        flash("Kopplingen har tagits bort.", "success")
    else:
        flash("Kopplingen kunde inte tas bort.", "error")
    return redirect(redirect_target)



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

def register_supervisor_routes(app: Flask) -> None:
    app.add_url_rule("/foretagskonto/skapa/<activation_token>", methods=["GET", "POST"], view_func=supervisor_create)
    app.add_url_rule("/foretagskonto/login", methods=["GET", "POST"], view_func=supervisor_login)
    app.add_url_rule("/foretagskonto", methods=["GET"], view_func=supervisor_dashboard)
    app.add_url_rule("/foretagskonto/organisationskopplingar/<int:request_id>/godkann", view_func=supervisor_approve_organization_link_request_route, methods=['POST'])
    app.add_url_rule("/foretagskonto/organisationskopplingar/<int:request_id>/avsla", view_func=supervisor_reject_organization_link_request_route, methods=['POST'])
    app.add_url_rule("/foretagskonto/kopplingsforfragan", view_func=supervisor_link_request_route, methods=['POST'])
    app.add_url_rule("/foretagskonto/standardkonto/<person_hash>/pdf/<int:pdf_id>", view_func=supervisor_download_pdf)
    app.add_url_rule("/foretagskonto/dela/<person_hash>/<int:pdf_id>", view_func=supervisor_share_pdf_route, methods=['POST'])
    app.add_url_rule("/foretagskonto/kopplingar/<person_hash>/ta-bort", view_func=supervisor_remove_connection_route, methods=['POST'])
    app.add_url_rule("/foretagskonto/aterstall-losenord/<token>", methods=["GET", "POST"], view_func=supervisor_password_reset)

# Copyright (c) Liam Suorsa and Mika Suorsa
