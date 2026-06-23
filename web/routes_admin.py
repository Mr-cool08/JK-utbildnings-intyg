# Copyright (c) Liam Suorsa and Mika Suorsa
"""Adminroutes, verktyg och JSON-API:er."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import json
import logging
import os
import secrets
from flask import Flask, current_app, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
import functions
from course_categories import COURSE_CATEGORIES, COURSE_CATEGORY_GROUPS, labels_for_slugs, normalize_category_slugs
from functions import security as sec
from functions.emails import service as email_service
from functions.logging import configure_module_logger, mask_email, mask_email_reference, mask_hash, mask_sensitive_data
from functions.notifications import critical_events
from functions.pdf import service as pdf
from functions.requests import get_request_ip
from web.helpers import (
    ALLOWED_ADMIN_APPROVAL_ERRORS,
    CLIENT_LOG_TRUNCATION_LIMITS,
    _api_error_response,
    _mask_sensitive_fields,
    _mask_username_for_log,
    _require_admin,
    _safe_user_error,
    _sanitize_search_term,
    _truncate_log_value,
    render_markdown_content,
)
logger = configure_module_logger("app")
ensure_csrf_token = sec.ensure_csrf_token
validate_csrf_token = sec.validate_csrf_token

def admin():  # pragma: no cover
    # Admin dashboard for uploading certificates and creating users.
    if request.method == "POST":
        if not session.get("admin_logged_in"):
            logger.warning("Obehörigt admin-POST-anrop")
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
                logger.warning("Adminuppladdning saknar kategorier (inget val)")
                return jsonify({"status": "error", "message": "Välj kategori för varje PDF."}), 400
            if not pdf_files:
                logger.warning("Adminuppladdning utan PDF")
                return jsonify({"status": "error", "message": "PDF-fil saknas"}), 400

            if len(raw_categories) != len(pdf_files):
                logger.warning(
                    "Adminuppladdning med mismatch i kategorier och filer (kategorier=%d, filer=%d)",
                    len(raw_categories),
                    len(pdf_files),
                )
                return jsonify({"status": "error", "message": "Välj kategori för varje PDF."}), 400

            logger.debug(
                "Adminuppladdning för %s med kategorier %s",
                mask_hash(pnr_hash),
                raw_categories,
            )

            normalized_categories = []
            for idx, raw in enumerate(raw_categories):
                selected = normalize_category_slugs([raw])
                if len(selected) != 1:
                    logger.warning(
                        "Adminuppladdning med ogiltig kategori för fil %d (värde=%r)",
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
                    "PDF:er uppladdade för befintlig användare %s (%d filer)",
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
                    "PDF:er uppladdade för väntande användare %s (%d filer)",
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
                        "Misslyckades med att skicka skapandemejl till %s",
                        mask_hash(email_hash),
                        exc_info=True,
                    )
                    return jsonify(
                        {
                            "status": "error",
                            "message": "Det gick inte att skicka inloggningslänken via e-post.",
                        }
                    ), 500

                logger.info("Admin skapade användare %s", mask_hash(pnr_hash))
                return jsonify(
                    {"status": "success", "message": "Standardkonto skapat", "link": link}
                )

            logger.error("Misslyckades med att skapa väntande användare för %s", mask_hash(pnr_hash))
            return jsonify({"status": "error", "message": "Kunde inte skapa standardkonto"}), 500

        except ValueError as ve:
            logger.error("Värdefel under adminuppladdning: %s", ve)
            return jsonify({"status": "error", "message": "Felaktiga användardata."}), 400
        except RequestEntityTooLarge:
            raise
        except Exception as e:
            logger.error("Serverfel under adminuppladdning", exc_info=e)
            return jsonify({"status": "error", "message": "Serverfel"}), 500

    # --- GET request ---
    if not session.get("admin_logged_in"):
        logger.warning("Obehörigt admin-GET-anrop")
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
        logger.error("Misslyckades att hämta adminlogg")

    logger.debug("Renderar adminsida")
    return render_template(
        "admin.html",
        admin_log_entries=admin_log_entries,
    )


def admin_guide():  # pragma: no cover
    if not session.get("admin_logged_in"):
        logger.warning("Obehörigt admin guide-GET-anrop")
        return redirect("/login_admin")
    guide_path = Path(current_app.root_path) / "admin.md"
    try:
        guide_content = guide_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.error("Admin guide-fil saknas")
        guide_content = "Guiden kunde inte hittas."
    rendered_guide = render_markdown_content(guide_content)
    logger.debug("Renderar admin guide-sida")
    return render_template("admin_guide.html", guide_content=rendered_guide)


def admin_accounts():  # pragma: no cover
    if not session.get("admin_logged_in"):
        logger.warning("Obehörigt admin accounts-GET-anrop")
        return redirect("/login_admin")
    csrf_token = ensure_csrf_token()
    logger.debug("Renderar admin accounts-sida")
    return render_template(
        "admin_accounts.html",
        categories=COURSE_CATEGORIES,
        category_groups=COURSE_CATEGORY_GROUPS,
        csrf_token=csrf_token,
    )


def admin_certificates():  # pragma: no cover
    if not session.get("admin_logged_in"):
        logger.warning("Obehörigt admin certificates-GET-anrop")
        return redirect("/login_admin")
    logger.debug("Renderar admin certificates-sida")
    return render_template(
        "admin_certificates.html",
        categories=COURSE_CATEGORIES,
    )


def admin_company_accounts():  # pragma: no cover
    if not session.get("admin_logged_in"):
        logger.warning("Obehörigt admin company accounts-GET-anrop")
        return redirect("/login_admin")
    logger.debug("Renderar admin company accounts-sida")
    csrf_token = ensure_csrf_token()
    return render_template("admin_company_accounts.html", csrf_token=csrf_token)


def _send_application_approval_emails(
    application_id: int, result: dict[str, Any]
) -> dict[str, str]:
    payload: dict[str, str] = {"message": "Ansökan godkänd."}
    email_warnings: list[str] = []

    if result.get("user_activation_required") and result.get("user_personnummer_hash"):
        link = url_for(
            "create_user",
            pnr_hash=result["user_personnummer_hash"],
            _external=True,
        )
        try:
            email_service.send_creation_email(result["email"], link)
            payload["message"] = (
                "Ansökan godkänd. Aktiveringsmejl skickat till standardkontot."
            )
            payload["access_link"] = link
            payload["access_link_label"] = "Aktiveringslänk"
            payload["access_link_type"] = "activation"
            payload["creation_link"] = link
        except Exception:
            logger.exception(
                "Misslyckades att skicka aktiveringslänk till sökande för ansökan %s",
                application_id,
            )
            email_warnings.append("Aktiveringslänken till sökande kunde inte skickas.")

    if result.get("account_type") == "foretagskonto":
        supervisor_email = result.get("supervisor_email") or result.get("email")
        if result.get("supervisor_activation_required") and supervisor_email:
            try:
                activation_token = functions.ensure_pending_supervisor_activation_token(
                    supervisor_email
                )
                link = url_for(
                    "supervisor_create",
                    activation_token=activation_token,
                    _external=True,
                )
                email_service.send_creation_email(supervisor_email, link)
                payload["message"] = (
                    "Ansökan godkänd. Aktiveringsmejl skickat till företagskontot."
                )
                payload["access_link"] = link
                payload["access_link_label"] = "Aktiveringslänk"
                payload["access_link_type"] = "activation"
                payload["creation_link"] = link
            except Exception:
                logger.exception(
                    "Misslyckades att skicka aktiveringslänk till supervisor (ansökan %s)",
                    application_id,
                )
                email_warnings.append(
                    "Aktiveringslänken till företagskontot kunde inte skickas."
                )
        elif supervisor_email:
            try:
                reset_token = functions.create_supervisor_password_reset_token(
                    supervisor_email
                )
                link = url_for(
                    "supervisor_password_reset",
                    token=reset_token,
                    _external=True,
                )
                email_service.send_password_reset_email(supervisor_email, link)
                payload["message"] = (
                    "Ansökan godkänd. Företagskontot finns redan och ett åtkomstmejl "
                    "har skickats."
                )
                payload["access_link"] = link
                payload["access_link_label"] = "Återställningslänk"
                payload["access_link_type"] = "password_reset"
            except Exception:
                logger.exception(
                    "Misslyckades att skicka åtkomstmejl till aktivt företagskonto "
                    "för ansökan %s",
                    application_id,
                )
                email_warnings.append(
                    "Åtkomstmejlet till företagskontot kunde inte skickas."
                )

    if email_warnings:
        payload["email_warning"] = " ".join(email_warnings)

    return payload


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
            result = functions.approve_application_request(int(application_id), "admin")
            email_result = _send_application_approval_emails(
                int(application_id), result
            )
            logger.debug("Ansökan har godkänts, lyckat")
            payload: dict[str, str] = {
                "status": "success",
                "message": email_result["message"],
            }
            for key in (
                "email_warning",
                "creation_link",
                "access_link",
                "access_link_label",
                "access_link_type",
            ):
                value = email_result.get(key)
                if value:
                    payload[key] = value
            return jsonify(payload)
        elif application_status == "rejected":
            functions.reject_application_request(int(application_id), "admin")
            logger.debug("Ansökan har avslagits, lyckat")
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


def admin_list_applications():  # pragma: no cover
    _require_admin()
    status = request.args.get("status")
    try:
        rows = functions.list_application_requests(status)
    except ValueError as exc:
        logger.warning(
            "Invalid status in list_application_requests: %s",
            exc,
        )
        logger.exception("Misslyckades med att lista ansökningar")
        return jsonify({"status": "error", "message": "Felaktig begäran."}), 400

    serialized = [_serialize_application_row(row) for row in rows]
    return jsonify({"status": "success", "data": serialized})


def admin_get_application(application_id: int):  # pragma: no cover
    _require_admin()
    row = functions.get_application_request(application_id)
    if not row:
        return jsonify({"status": "error", "message": "Ansökan hittades inte."}), 404
    return jsonify({"status": "success", "data": _serialize_application_row(row)})


def admin_approve_application(application_id: int):  # pragma: no cover
    """
    Godkänn ansökan, skapa/aktivera konto(n), skicka mejl till sökande (normal user)
    och – vid företagskonto – även till handledare/supervisor. Logga admin-åtgärden.
    """
    admin_name = _require_admin()
    if not validate_csrf_token():
        return _api_error_response(
            "Ogiltig CSRF-token.",
            400,
            severity="warning",
            extra={"route": "admin_approve_application", "admin": admin_name},
        )

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
        return _api_error_response(
            _safe_user_error(
                "",
                ALLOWED_ADMIN_APPROVAL_ERRORS,
                (
                    "Ansökan kunde inte godkännas. Kontrollera att den fortfarande "
                    "är väntande och att uppgifterna är kompletta."
                ),
            ),
            400,
            severity="warning",
            error=exc,
            extra={
                "route": "admin_approve_application",
                "application_id": application_id,
                "admin": admin_name,
            },
        )
    except Exception as exc:
        return _api_error_response(
            "Kunde inte godkänna ansökan.",
            500,
            severity="error",
            error=exc,
            extra={
                "route": "admin_approve_application",
                "application_id": application_id,
                "admin": admin_name,
            },
        )

    email_result = _send_application_approval_emails(application_id, result)

    masked_email = mask_hash(functions.hash_value(result["email"]))
    functions.log_admin_action(
        admin_name,
        "godkände ansökan",
        f"application_id={application_id}, email={masked_email}",
    )

    payload: dict[str, Any] = {
        "status": "success",
        "data": result,
        "message": email_result["message"],
    }
    for key in (
        "email_warning",
        "creation_link",
        "access_link",
        "access_link_label",
        "access_link_type",
    ):
        value = email_result.get(key)
        if value:
            payload[key] = value

    return jsonify(payload)


def admin_reject_application(application_id: int):  # pragma: no cover
    admin_name = _require_admin()
    if not validate_csrf_token():
        return _api_error_response(
            "Ogiltig CSRF-token.",
            400,
            severity="warning",
            extra={"route": "admin_reject_application", "admin": admin_name},
        )

    payload = request.get_json(silent=True) or {}
    decision_reason = (payload.get("reason") or "").strip()
    if not decision_reason:
        decision_reason = "Ingen motivering angiven."

    try:
        result = functions.reject_application_request(application_id, admin_name, decision_reason)
    except ValueError as exc:
        return _api_error_response(
            (
                "Ansökan kunde inte avslås. Kontrollera att den fortfarande "
                "är väntande och försök igen."
            ),
            400,
            severity="warning",
            error=exc,
            extra={
                "route": "admin_reject_application",
                "application_id": application_id,
                "admin": admin_name,
            },
        )
    except Exception as exc:
        return _api_error_response(
            "Kunde inte avslå ansökan.",
            500,
            severity="error",
            error=exc,
            extra={
                "route": "admin_reject_application",
                "application_id": application_id,
                "admin": admin_name,
            },
        )

    email_error = None
    try:
        email_service.send_application_rejection_email(
            result["email"], result["company_name"], decision_reason
        )
    except RuntimeError as exc:
        logger.error("Misslyckades att skicka avslag för ansökan %s", application_id)
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


def admin_user_overview():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get("personnummer") or "").strip()
    if not personnummer:
        logger.debug("Admin overview without personnummer", extra={"admin": admin_name})
        return jsonify({"status": "error", "message": "Ange personnummer."}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        personnummer_masked = mask_hash(functions.hash_value(personnummer))
        logger.debug(
            "Admin overview with invalid personnummer hash: %s",
            personnummer_masked,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ogiltigt personnummer."}), 400

    pnr_hash = functions.hash_value(normalized_personnummer)
    pdfs = functions.get_user_pdfs(pnr_hash)
    overview = []
    for pdf in pdfs:
        uploaded_at = pdf.get("uploaded_at")
        expires_on = pdf.get("expires_on")
        overview.append(
            {
                "id": pdf["id"],
                "filename": pdf["filename"],
                "categories": pdf.get("categories") or [],
                "category_labels": labels_for_slugs(pdf.get("categories") or []),
                "expires_on": expires_on.isoformat()
                if (expires_on and hasattr(expires_on, "isoformat"))
                else None,
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
    logger.debug(
        "Admin overview for %s with %d pdfs",
        mask_hash(pnr_hash),
        len(pdfs),
        extra={"admin": admin_name},
    )
    return jsonify(response)


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


def admin_delete_pdf():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get("personnummer") or "").strip()
    pdf_id = payload.get("pdf_id")
    if not personnummer or pdf_id is None:
        logger.debug(
            "Admin delete_pdf without personnummer or pdf_id", extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ange personnummer och PDF-id."}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        personnummer_masked = mask_hash(functions.hash_value(personnummer))
        logger.debug(
            "Admin delete_pdf with invalid personnummer hash: %s",
            personnummer_masked,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ogiltigt personnummer."}), 400

    try:
        pdf_id_int = int(pdf_id)
    except (ValueError, TypeError):
        logger.debug(
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
    logger.info(
        "Admin deleted pdf %s for %s", pdf_id_int, mask_hash(pnr_hash), extra={"admin": admin_name}
    )
    return jsonify({"status": "success", "message": "PDF borttagen."})


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
            logger.debug(
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
        logger.debug(
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
        logger.error(
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
            logger.error("Misslyckades att skicka raderingsmejl")
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
    logger.info(
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


def admin_list_accounts():  # pragma: no cover
    _require_admin()
    accounts = functions.list_admin_accounts()
    return jsonify({"status": "success", "data": accounts})


def admin_list_legacy_email_hashes():  # pragma: no cover
    _require_admin()
    references = functions.list_legacy_email_references()
    return jsonify({"status": "success", "data": references})


def admin_complete_legacy_email_hash():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}
    elif not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Ogiltig begäran."}), 400
    if not validate_csrf_token():
        return jsonify({"status": "error", "message": "Ogiltig CSRF-token."}), 400
    reference_type = (payload.get("reference_type") or "").strip()
    email_hash = (payload.get("email_hash") or "").strip()
    email = (payload.get("email") or "").strip()
    personnummer_hash = (payload.get("personnummer_hash") or "").strip() or None
    if not reference_type or not email_hash or not email:
        return jsonify({"status": "error", "message": "Välj referens och ange e-post."}), 400

    try:
        success, summary, error = functions.complete_legacy_email_reference(
            reference_type,
            email_hash,
            email,
            personnummer_hash,
        )
    except ValueError:
        return jsonify({"status": "error", "message": "Ogiltig e-postadress."}), 400

    if not success:
        messages = {
            "invalid_hash": "Ogiltig e-postreferens.",
            "invalid_personnummer": "Ogiltig personnummerreferens.",
            "invalid_type": "Ogiltig referenstyp.",
            "hash_mismatch": "E-postadressen matchar inte den valda hashen.",
            "missing": "Referensen hittades inte.",
            "email_in_use": "E-postadressen används redan av ett annat konto.",
        }
        status_code = 404 if error == "missing" else 409 if error == "email_in_use" else 400
        return (
            jsonify(
                {
                    "status": "error",
                    "message": messages.get(error or "", "Kunde inte komplettera e-post."),
                }
            ),
            status_code,
        )

    summary = summary or {}
    summary_details = ", ".join(f"{key}={value}" for key, value in summary.items())
    functions.log_admin_action(
        admin_name,
        "kompletterade e-posthash",
        (
            f"typ={reference_type}, email_ref={mask_hash(email_hash)}, "
            f"epost={mask_email(functions.normalize_email(email))}, {summary_details}"
        ),
    )
    return jsonify(
        {
            "status": "success",
            "message": "E-postadressen har kompletterats.",
            "data": summary,
        }
    )


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
    if summary is None:
        return jsonify({"status": "error", "message": "Kunde inte uppdatera kontot."}), 400

    pnr_hash = functions.hash_value(normalized_personnummer)
    email_hash = functions.hash_value(normalized_email)
    summary_details = ", ".join(f"{key}={value}" for key, value in summary.items())
    functions.log_admin_action(
        admin_name,
        "uppdaterade konto",
        f"personnummer_hash={pnr_hash}, email_hash={email_hash}, {summary_details}",
    )
    logger.info("Admin updated account for %s", mask_hash(pnr_hash), extra={"admin": admin_name})
    return jsonify(
        {
            "status": "success",
            "message": "Kontot har uppdaterats.",
            "data": summary,
        }
    )


def admin_update_pdf():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    personnummer = (payload.get("personnummer") or "").strip()
    pdf_id = payload.get("pdf_id")
    categories = payload.get("categories")
    if not isinstance(categories, list):
        logger.debug(
            "Admin update_pdf with invalid categories: %r", categories, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Kategorier måste vara en lista."}), 400
    if not personnummer or pdf_id is None:
        logger.debug(
            "Admin update_pdf without personnummer or pdf_id", extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ange personnummer och PDF-id."}), 400
    try:
        normalized_personnummer = functions.normalize_personnummer(personnummer)
    except ValueError:
        personnummer_masked = mask_hash(functions.hash_value(personnummer))
        logger.debug(
            "Admin update_pdf with invalid personnummer hash: %s",
            personnummer_masked,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Ogiltigt personnummer."}), 400
    try:
        pdf_id_int = int(pdf_id)
    except (ValueError, TypeError):
        logger.debug(
            "Admin update_pdf with invalid pdf_id: %s", pdf_id, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ogiltigt PDF-id."}), 400

    try:
        normalized_categories = normalize_category_slugs(categories)
    except ValueError:
        logger.debug(
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
    logger.info(
        "Admin updated categories for pdf %s for %s",
        pdf_id_int,
        mask_hash(pnr_hash),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "message": "Kategorier uppdaterade."})


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
            logger.error("Misslyckades att skicka skapa-konto-länk")
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


def admin_send_password_reset():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    account_type = (payload.get("account_type") or "standard").strip().lower()
    personnummer = (payload.get("personnummer") or "").strip()
    email = (payload.get("email") or "").strip()
    if account_type not in {"standard", "foretagskonto"}:
        logger.debug(
            "Admin send_password_reset with invalid account_type: %s",
            account_type,
            extra={"admin": admin_name},
        )

    if account_type == "standard" and (not personnummer or not email):
        logger.debug(
            "Admin send_password_reset without personnummer or email", extra={"admin": admin_name}
        )
        return _api_error_response(
            "Ange både personnummer och e-post.",
            400,
            severity="warning",
            extra={"route": "admin_send_password_reset", "admin": admin_name},
        )
    if account_type == "foretagskonto" and not email:
        logger.debug(
            "Admin send_password_reset without email for foretagskonto", extra={"admin": admin_name}
        )
        return _api_error_response(
            "Ange e-postadressen för företagskontot.",
            400,
            severity="warning",
            extra={"route": "admin_send_password_reset", "admin": admin_name},
        )

    if account_type == "foretagskonto":
        try:
            token = functions.create_supervisor_password_reset_token(email)
        except ValueError as exc:
            return _api_error_response(
                "Företagskontot hittades inte.",
                404,
                severity="warning",
                error=exc,
                extra={"route": "admin_send_password_reset", "admin": admin_name},
            )
        except Exception as exc:
            return _api_error_response(
                "Kunde inte skapa återställning.",
                500,
                severity="error",
                error=exc,
                extra={"route": "admin_send_password_reset", "admin": admin_name},
            )

        link = url_for("supervisor_password_reset", token=token, _external=True)
        try:
            email_service.send_password_reset_email(email, link)
        except RuntimeError as exc:
            return _api_error_response(
                "Kunde inte skicka återställningsmejl.",
                500,
                severity="error",
                error=exc,
                extra={"route": "admin_send_password_reset", "admin": admin_name},
            )

        email_hash = functions.hash_value(functions.normalize_email(email))
        functions.log_admin_action(
            admin_name,
            "skickade företagskonto-återställning",
            f"email_hash={email_hash}",
        )
        logger.info(
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
    except ValueError as exc:
        personnummer_masked = mask_hash(functions.hash_value(personnummer))
        logger.debug(
            "Admin send_password_reset with invalid personnummer hash: %s",
            personnummer_masked,
            extra={"admin": admin_name},
        )
        return _api_error_response(
            "Ogiltigt personnummer.",
            400,
            severity="warning",
            error=exc,
            extra={"route": "admin_send_password_reset", "admin": admin_name},
        )

    try:
        token = functions.create_password_reset_token(normalized_personnummer, email)
    except ValueError as exc:
        # Do not expose raw exception messages to the client; map to safe, user-facing text instead.
        exc_message = str(exc)
        if exc_message == "Kontot är inte aktiverat ännu.":
            message = "Kontot är inte aktiverat ännu."
            status_code = 409
        else:
            message = "Uppgifterna matchar inget aktivt standardkonto."
            status_code = 404
        return _api_error_response(
            message,
            status_code,
            severity="warning",
            error=exc,
            extra={"route": "admin_send_password_reset", "admin": admin_name},
        )
    except Exception as exc:
        return _api_error_response(
            "Kunde inte skapa återställning.",
            500,
            severity="error",
            error=exc,
            extra={"route": "admin_send_password_reset", "admin": admin_name},
        )

    link = url_for("password_reset", token=token, _external=True)
    try:
        email_service.send_password_reset_email(email, link)
    except RuntimeError as exc:
        return _api_error_response(
            "Kunde inte skicka återställningsmejl.",
            500,
            severity="error",
            error=exc,
            extra={"route": "admin_send_password_reset", "admin": admin_name},
        )

    pnr_hash = functions.hash_value(normalized_personnummer)
    email_hash = functions.hash_value(functions.normalize_email(email))
    functions.log_admin_action(
        admin_name,
        "skickade lösenordsåterställning",
        f"personnummer_hash={pnr_hash}, email_hash={email_hash}",
    )
    logger.info(
        "Admin sent password reset for %s to %s",
        mask_hash(pnr_hash),
        mask_hash(email_hash),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "message": "Återställningsmejl skickat.", "link": link})


def admin_create_supervisor_route():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip()
    name = (payload.get("name") or "").strip()
    if not email or not name:
        logger.debug("Admin create_supervisor without email or name", extra={"admin": admin_name})
        return jsonify({"status": "error", "message": "Ange namn och e-post."}), 400

    try:
        normalized_email = functions.normalize_email(email)
    except ValueError:
        logger.debug(
            "Admin create_supervisor with invalid email: %s",
            mask_email(email),
            extra={"admin": admin_name},
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

    try:
        activation_token = functions.ensure_pending_supervisor_activation_token(normalized_email)
    except ValueError:
        logger.error(
            "Misslyckades med att skapa aktiveringslänk för handledare %s",
            mask_email_reference(normalized_email),
        )
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Det gick inte att skapa inloggningslänken.",
                }
            ),
            500,
        )

    link = url_for("supervisor_create", activation_token=activation_token, _external=True)

    try:
        email_service.send_creation_email(normalized_email, link)
    except RuntimeError:
        logger.error(
            "Misslyckades med att skicka skapandemejl för handledare till %s",
            mask_email_reference(normalized_email),
        )
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Det gick inte att skicka inloggningslänken.",
                }
            ),
            500,
        )
    functions.log_admin_action(
        admin_name,
        "skapade företagskonto",
        f"email_ref={mask_email_reference(normalized_email)}",
    )
    logger.info(
        "Admin created supervisor %s",
        mask_email_reference(normalized_email),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "message": "Företagskonto skapat.", "link": link})


def admin_link_supervisor_route():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    orgnr = (payload.get("orgnr") or "").strip()
    personnummer = (payload.get("personnummer") or "").strip()
    if not orgnr or not personnummer:
        logger.debug(
            "Admin link_supervisor without orgnr or personnummer", extra={"admin": admin_name}
        )
        return jsonify(
            {"status": "error", "message": "Ange organisationsnummer och personnummer."}
        ), 400

    try:
        success, reason, email_hash = functions.admin_link_supervisor_to_user(orgnr, personnummer)
    except ValueError:
        personnummer_masked = mask_hash(functions.hash_value(personnummer))
        logger.debug(
            "Admin link_supervisor with invalid orgnr or personnummer hash: %s, %s",
            orgnr,
            personnummer_masked,
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
        logger.debug("Admin link_supervisor failed: %s", reason, extra={"admin": admin_name})
        return jsonify({"status": "error", "message": message}), status_code

    if not email_hash:
        logger.debug(
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
        (
            f"orgnr={normalized_orgnr}, email_ref={mask_email_reference(email_hash)}, "
            f"personnummer_hash={personnummer_hash}"
        ),
    )
    logger.info(
        "Admin linked supervisor %s to user %s",
        mask_email_reference(email_hash),
        mask_hash(personnummer_hash),
        extra={"admin": admin_name},
    )
    return jsonify(
        {"status": "success", "message": "Företagskontot har kopplats till standardkontot."}
    )


def admin_supervisor_overview():  # pragma: no cover
    admin_name = _require_admin()
    payload = request.get_json(silent=True) or {}
    orgnr = (payload.get("orgnr") or "").strip()
    if not orgnr:
        logger.debug("Admin supervisor_overview without orgnr", extra={"admin": admin_name})
        return jsonify({"status": "error", "message": "Ange organisationsnummer."}), 400

    try:
        details = functions.get_supervisor_login_details_for_orgnr(orgnr)
    except ValueError:
        logger.debug(
            "Admin supervisor_overview with invalid orgnr: %s", orgnr, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Ogiltigt organisationsnummer."}), 400

    if not details:
        logger.debug(
            "Admin supervisor_overview not found for orgnr: %s", orgnr, extra={"admin": admin_name}
        )
        return jsonify({"status": "error", "message": "Företagskontot hittades inte."}), 404

    email_hash = details["email_hash"]
    overview = functions.get_supervisor_overview(email_hash)
    if not overview:
        logger.debug(
            "Admin supervisor_overview not found for email reference: %s",
            mask_email_reference(email_hash),
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Företagskontot hittades inte."}), 404

    functions.log_admin_action(
        admin_name,
        "visade företagskontoöversikt",
        f"orgnr={details['orgnr']}, email_ref={mask_email_reference(email_hash)}",
    )
    logger.debug(
        "Admin supervisor_overview for %s with %d users",
        mask_email_reference(email_hash),
        len(overview.get("users", [])),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "data": overview})


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
        (
            f"orgnr={details['orgnr']}, "
            f"email_ref={mask_email_reference(details['email_hash'])}, "
            f"personnummer_hash={personnummer_hash}"
        ),
    )
    logger.info(
        "Admin removed supervisor connection for %s",
        mask_hash(personnummer_hash),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "message": "Kopplingen har tagits bort."})


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
                (
                    "Rollback misslyckades vid ändring av koppling: "
                    "reason=%s, rollback_reason=%s, rollback_email_ref=%s"
                ),
                reason,
                rollback_reason,
                mask_email_reference(rollback_email_hash or ""),
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
            f"email_ref={mask_email_reference(email_hash or '')}, "
            f"personnummer_hash={personnummer_hash}"
        ),
    )
    logger.info(
        "Admin changed supervisor connection for %s",
        mask_hash(personnummer_hash),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "message": "Kopplingen har uppdaterats."})


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
        logger.error("Misslyckades att radera företagskonto för %s", orgnr)
        return jsonify({"status": "error", "message": "Kunde inte radera företagskontot."}), 500

    if not deleted:
        return jsonify({"status": "error", "message": "Företagskontot hittades inte."}), 404

    summary_details = ", ".join(f"{key}={value}" for key, value in summary.items())
    functions.log_admin_action(
        admin_name,
        "raderade företagskonto",
        f"orgnr={normalized_orgnr}, {summary_details}",
    )
    logger.info(
        "Admin deleted supervisor account for %s",
        mask_hash(functions.hash_value(normalized_orgnr)),
        extra={"admin": admin_name},
    )
    return jsonify(
        {
            "status": "success",
            "message": "Företagskontot har raderats.",
            "data": summary,
        }
    )


def admin_advanced():  # pragma: no cover
    if not session.get("admin_logged_in"):
        logger.warning("Obehörigt admin advanced-GET-anrop")
        return redirect("/login_admin")
    tables = sorted(functions.TABLE_REGISTRY.keys())
    return render_template("admin_advanced.html", tables=tables)


def admin_advanced_schema(table_name: str):  # pragma: no cover
    admin_name = _require_admin()
    try:
        schema = functions.get_table_schema(table_name)
    except ValueError:
        logger.debug(
            "Admin advanced schema with unknown table: %s",
            table_name,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Okänd tabell."}), 404
    logger.debug("Admin advanced schema for table: %s", table_name, extra={"admin": admin_name})
    return jsonify({"status": "success", "schema": schema})


def admin_advanced_rows(table_name: str):  # pragma: no cover
    admin_name = _require_admin()
    search_term = request.args.get("sok")
    limit = request.args.get("limit", type=int) or 100
    try:
        rows = functions.fetch_table_rows(table_name, search_term, limit)
    except ValueError:
        logger.debug(
            "Admin advanced rows with unknown table: %s",
            table_name,
            extra={"admin": admin_name},
        )
        return jsonify({"status": "error", "message": "Okänd tabell."}), 404
    masked_search = _sanitize_search_term(search_term)
    logger.debug(
        "Admin advanced rows for table: %s, search: %r, limit: %d",
        table_name,
        masked_search,
        limit,
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "rows": rows})


def admin_advanced_create(table_name: str):  # pragma: no cover
    admin_name = _require_admin()
    values = request.get_json(silent=True) or {}
    try:
        row = functions.create_table_row(table_name, values)
    except ValueError as exc:
        logger.warning("Fel i create_table_row: %s", exc)
        return jsonify({"status": "error", "message": "Kunde inte skapa posten."}), 400
    masked_row = _mask_sensitive_fields(row)
    functions.log_admin_action(
        admin_name,
        "skapade post",
        f"tabell={table_name}",
    )
    logger.info(
        "Admin created row in table %s",
        table_name,
        extra={"admin": admin_name},
    )
    logger.debug(
        "Admin created masked row in table %s: %s",
        table_name,
        masked_row,
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success", "row": masked_row}), 201


def admin_advanced_update(table_name: str, row_id: int):  # pragma: no cover
    admin_name = _require_admin()
    values = request.get_json(silent=True) or {}
    try:
        updated = functions.update_table_row(table_name, row_id, values)
    except ValueError as exc:
        logger.error(
            "Misslyckades med att uppdatera rad i tabell '%s', id=%s: %s",
            table_name,
            row_id,
            exc,
            exc_info=True,
        )
        return jsonify({"status": "error", "message": "Felaktiga data."}), 400
    if not updated:
        logger.debug("Admin advanced update with missing row: table=%s, id=%d", table_name, row_id)
        return jsonify({"status": "error", "message": "Posten hittades inte."}), 404
    functions.log_admin_action(
        admin_name,
        "uppdaterade post",
        f"tabell={table_name}, id={row_id}",
    )
    logger.info(
        "Admin updated row in table %s, id=%d: %s",
        table_name,
        row_id,
        _mask_sensitive_fields(values),
        extra={"admin": admin_name},
    )
    return jsonify({"status": "success"})


def admin_advanced_delete(table_name: str, row_id: int):  # pragma: no cover
    admin_name = _require_admin()
    try:
        deleted = functions.delete_table_row(table_name, row_id)
    except ValueError:
        logger.debug("Admin advanced delete with unknown table: %s", table_name)
        return jsonify({"status": "error", "message": "Okänd tabell."}), 404
    if not deleted:
        logger.debug("Admin advanced delete with missing row: table=%s, id=%d", table_name, row_id)
        return jsonify({"status": "error", "message": "Posten hittades inte."}), 404
    functions.log_admin_action(
        admin_name,
        "raderade post",
        f"tabell={table_name}, id={row_id}",
    )
    logger.info(
        "Admin deleted row in table %s, id=%d", table_name, row_id, extra={"admin": admin_name}
    )
    return jsonify({"status": "success"})


def verify_certificate_route(personnummer):  # pragma: no cover
    # Allow an admin to verify whether a user's certificate is confirmed.
    #
    # Uses a cached lookup to avoid repeated database queries for the same
    # ``personnummer``. Returns a JSON response indicating the verification
    # status. If the certificate isn't verified, an informative message is sent
    # back to the administrator.
    if not session.get("admin_logged_in"):
        logger.warning("Obehörigt försök att verifiera intyg")
        return redirect("/login_admin")

    if functions.verify_certificate(personnummer):
        logger.info("Intyg för %s är verifierat", mask_hash(functions.hash_value(personnummer)))
        return jsonify({"status": "success", "verified": True})
    logger.info("Intyg för %s är INTE verifierat", mask_hash(functions.hash_value(personnummer)))
    return jsonify(
        {
            "status": "error",
            "message": "Standardkontots certifikat är inte verifierat",
        }
    ), 404


def login_admin():  # pragma: no cover
    # Authenticate an administrator for access to the admin panel.
    if request.method == "POST":
        admin_password = os.getenv("admin_password")
        admin_username = os.getenv("admin_username")

        # Require admin credentials to be explicitly set (no insecure defaults)
        if not admin_password or not admin_username:
            error_msg = "KRITISKT: miljövariablerna admin_username och admin_password måste vara satta och inte tomma"
            logger.critical(error_msg)
            critical_events.send_critical_error_notification(error_message=error_msg, endpoint="/login_admin", user_ip=get_request_ip())
            raise RuntimeError(error_msg)
        submitted_username = request.form.get("username")
        submitted_password = request.form.get("password")
        user_ok = secrets.compare_digest(str(submitted_username or ""), str(admin_username))
        pass_ok = secrets.compare_digest(str(submitted_password or ""), str(admin_password))
        if user_ok and pass_ok:
            session["admin_logged_in"] = True
            session["admin_username"] = admin_username
            logger.info("Admin %s loggade in", _mask_username_for_log(admin_username))
            return redirect("/admin")

        logger.warning(
            "Ogiltigt admin-inloggningsförsök för %s",
            _mask_username_for_log(submitted_username),
        )
        return jsonify({"status": "error", "message": "Ogiltiga inloggningsuppgifter"})

    elif request.method == "GET":
        logger.debug("Renderar admin-inloggningssida")
        return render_template("admin_login.html")
    else:
        logger.warning("Ogiltig förfrågningsmetod %s till login_admin", request.method)
        return jsonify(
            {"status": "error", "message": "Ogiltig HTTP-metod", "method": request.method}
        )


def logout():
    # Logga ut både admin och användare.
    logger.info("Loggar ut användare och admin")
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

def register_admin_routes(app: Flask) -> None:
    app.add_url_rule("/admin", methods=["POST", "GET"], view_func=admin)
    app.add_url_rule("/admin/guide", view_func=admin_guide, methods=['GET'])
    app.add_url_rule("/admin/konton", view_func=admin_accounts, methods=['GET'])
    app.add_url_rule("/admin/intyg", view_func=admin_certificates, methods=['GET'])
    app.add_url_rule("/admin/foretagskonto", view_func=admin_company_accounts, methods=['GET'])
    app.add_url_rule("/admin/ansokningar", methods=["GET", "POST"], view_func=admin_applications)
    app.add_url_rule("/admin/fakturering", methods=["GET"], view_func=admin_invoicing)
    app.add_url_rule("/admin/api/ansokningar", view_func=admin_list_applications, methods=['GET'])
    app.add_url_rule("/admin/api/ansokningar/<int:application_id>", view_func=admin_get_application, methods=['GET'])
    app.add_url_rule("/admin/api/ansokningar/<int:application_id>/godkann", view_func=admin_approve_application, methods=['POST'])
    app.add_url_rule("/admin/api/ansokningar/<int:application_id>/avslag", view_func=admin_reject_application, methods=['POST'])
    app.add_url_rule("/admin/api/oversikt", view_func=admin_user_overview, methods=['POST'])
    app.add_url_rule("/admin/api/klientlogg", view_func=admin_client_log, methods=['POST'])
    app.add_url_rule("/admin/api/radera-pdf", view_func=admin_delete_pdf, methods=['POST'])
    app.add_url_rule("/admin/api/radera-konto", view_func=admin_delete_account, methods=['POST'])
    app.add_url_rule("/admin/api/konton/lista", view_func=admin_list_accounts, methods=['GET'])
    app.add_url_rule("/admin/api/epost-hashar/lista", view_func=admin_list_legacy_email_hashes, methods=['GET'])
    app.add_url_rule("/admin/api/epost-hashar/komplettera", view_func=admin_complete_legacy_email_hash, methods=['POST'])
    app.add_url_rule("/admin/api/konton/uppdatera", view_func=admin_update_account, methods=['POST'])
    app.add_url_rule("/admin/api/uppdatera-pdf", view_func=admin_update_pdf, methods=['POST'])
    app.add_url_rule("/admin/api/konton/losenord-status", view_func=admin_password_status, methods=['POST'])
    app.add_url_rule("/admin/api/konton/skapa-losenordslank", view_func=admin_send_create_password_link, methods=['POST'])
    app.add_url_rule("/admin/api/skicka-aterstallning", view_func=admin_send_password_reset, methods=['POST'])
    app.add_url_rule("/admin/api/foretagskonto/skapa", view_func=admin_create_supervisor_route, methods=['POST'])
    app.add_url_rule("/admin/api/foretagskonto/koppla", view_func=admin_link_supervisor_route, methods=['POST'])
    app.add_url_rule("/admin/api/foretagskonto/oversikt", view_func=admin_supervisor_overview, methods=['POST'])
    app.add_url_rule("/admin/api/foretagskonto/ta-bort", view_func=admin_remove_supervisor_connection, methods=['POST'])
    app.add_url_rule("/admin/api/foretagskonto/uppdatera-koppling", view_func=admin_change_supervisor_connection, methods=['POST'])
    app.add_url_rule("/admin/api/foretagskonto/radera", view_func=admin_delete_supervisor_account_route, methods=['POST'])
    app.add_url_rule("/admin/avancerat", view_func=admin_advanced, methods=['GET'])
    app.add_url_rule("/admin/advanced/api/schema/<table_name>", view_func=admin_advanced_schema, methods=['GET'])
    app.add_url_rule("/admin/advanced/api/rows/<table_name>", view_func=admin_advanced_rows, methods=['GET'])
    app.add_url_rule("/admin/advanced/api/rows/<table_name>", view_func=admin_advanced_create, methods=['POST'])
    app.add_url_rule("/admin/advanced/api/rows/<table_name>/<int:row_id>", view_func=admin_advanced_update, methods=['PUT'])
    app.add_url_rule("/admin/advanced/api/rows/<table_name>/<int:row_id>", view_func=admin_advanced_delete, methods=['DELETE'])
    app.add_url_rule("/verify_certificate/<personnummer>", methods=["GET"], view_func=verify_certificate_route)
    app.add_url_rule("/login_admin", methods=["POST", "GET"], view_func=login_admin)
    app.add_url_rule("/logout", view_func=logout)

# Copyright (c) Liam Suorsa and Mika Suorsa
