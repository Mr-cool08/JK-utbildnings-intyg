# Copyright (c) Liam Suorsa and Mika Suorsa
"""Routes för inloggade standardkonton och deras intyg."""
from __future__ import annotations
from datetime import date
from flask import Flask, Response, abort, flash, jsonify, make_response, redirect, render_template, request, session, url_for
import functions
from course_categories import COURSE_CATEGORIES, COURSE_CATEGORY_GROUPS, labels_for_slugs
from functions import security as sec
from functions.emails import service as email_service
from functions.logging import configure_module_logger, mask_email, mask_hash
from functions.pdf import service as pdf
from web.helpers import (
    ALLOWED_PDF_METADATA_UPDATE_ERRORS,
    ALLOWED_PDF_UPLOAD_ERRORS,
    CSRF_EXPIRED_MESSAGE,
    UPLOAD_MAX_BYTES,
    UPLOAD_MAX_MB,
    _coerce_text_payload_value,
    _editable_pdf_name,
    _format_display_name,
    _resolve_certificate_expiry,
    _safe_user_error,
)
logger = configure_module_logger("app")
validate_csrf_token = sec.validate_csrf_token

def dashboard():
    # Visa alla PDF:er för den inloggade användaren.
    if not session.get("user_logged_in"):
        logger.debug("Oautentiserad åtkomst till dashboard")
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
        pdf["editable_name"] = _editable_pdf_name(pdf.get("filename", ""))
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
    logger.debug("Dashboard för %s visar %d pdfer", pnr_hash, len(pdfs))
    user_name = _format_display_name(user_name)
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
        today_iso=date.today().isoformat(),
    )


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
    expiry_mode = request.form.get("expiry_mode", "none")
    expiry_date_raw = request.form.get("expiry_date", "")
    expiry_months_raw = request.form.get("expiry_months", "")
    expiry_years_raw = request.form.get("expiry_years", "")

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
        expires_on = _resolve_certificate_expiry(
            expiry_mode,
            expiry_date_raw,
            expiry_months_raw,
            expiry_years_raw,
        )
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect("/dashboard")

    try:
        pdf.save_pdf_for_user(
            personnummer,
            uploaded_file,
            [category],
            note=note,
            expires_on=expires_on,
            logger=logger,
        )
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


def user_remove_supervisor_connection_by_id_route(connection_id: int):
    if not session.get("user_logged_in"):
        return redirect("/login")
    if not validate_csrf_token(allow_if_absent=True):
        flash("Formuläret är inte längre giltigt. Ladda om sidan och försök igen.", "error")
        return redirect("/dashboard")
    personnummer_hash = session.get("personnummer")
    if not personnummer_hash:
        flash("Inte inloggad.", "error")
        return redirect("/login")
    if functions.user_remove_supervisor_connection_by_id(personnummer_hash, connection_id):
        flash("Kopplingen har tagits bort.", "success")
    else:
        flash("Kopplingen kunde inte tas bort.", "error")
    return redirect("/dashboard")


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
        logger.error("Kunde inte ta bort intyg %s för användare", pdf_id)
        flash("Ett fel inträffade när intyget skulle tas bort.", "error")

    return redirect("/dashboard")


def user_update_pdf_route(pdf_id: int):
    if not session.get("user_logged_in"):
        return jsonify({"fel": "Du måste vara inloggad för att uppdatera intyg."}), 401

    if not validate_csrf_token():
        return jsonify({"fel": CSRF_EXPIRED_MESSAGE}), 400

    personnummer = session.get("personnummer_raw")
    if not personnummer:
        return jsonify({"fel": "Kunde inte identifiera användaren. Logga in igen."}), 400
    personnummer_hash = functions.hash_value(personnummer)

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"fel": "Ogiltig begäran."}), 400

    try:
        filename_raw = _coerce_text_payload_value(
            payload.get("filename", ""),
            "Intygsnamnet",
        ).strip()
        note = _coerce_text_payload_value(payload.get("note", ""), "Anteckningen").strip()
        expiry_mode = _coerce_text_payload_value(
            payload.get("expiry_mode", "none"),
            "Val för utgångsdatum",
            default="none",
        ).strip()
        expiry_date_raw = _coerce_text_payload_value(
            payload.get("expiry_date", ""),
            "Utgångsdatum",
        ).strip()
        expiry_months_raw = _coerce_text_payload_value(
            payload.get("expiry_months", ""),
            "Antal månader",
        ).strip()
        expiry_years_raw = _coerce_text_payload_value(
            payload.get("expiry_years", ""),
            "Antal år",
        ).strip()
    except ValueError as exc:
        logger.info("PDF update payload validation failed: %s", exc)
        return (
            jsonify(
                {
                    "fel": "Ogiltig begäran.",
                }
            ),
            400,
        )

    if len(note) > 300:
        return jsonify({"fel": "Anteckningen får vara högst 300 tecken."}), 400

    current_pdf = functions.get_pdf_metadata(personnummer_hash, pdf_id)
    current_expires_on = current_pdf.get("expires_on") if current_pdf else None

    try:
        filename = pdf.build_editable_pdf_filename(filename_raw)
        expires_on = _resolve_certificate_expiry(
            expiry_mode,
            expiry_date_raw,
            expiry_months_raw,
            expiry_years_raw,
            current_expires_on=current_expires_on,
        )
    except ValueError as exc:
        logger.info("PDF metadata update validation failed: %s", exc)
        return (
            jsonify(
                {
                    "fel": _safe_user_error(
                        str(exc),
                        ALLOWED_PDF_METADATA_UPDATE_ERRORS,
                        "Ogiltig begäran.",
                    )
                }
            ),
            400,
        )

    try:
        updated = functions.update_user_pdf_metadata(
            personnummer,
            pdf_id,
            filename,
            note,
            expires_on,
        )
    except Exception:
        logger.exception("Kunde inte uppdatera intyg %s för användare", pdf_id)
        return jsonify({"fel": "Ett fel inträffade när intyget skulle uppdateras."}), 500

    if not updated:
        return jsonify({"fel": "Intyget kunde inte hittas."}), 404

    return (
        jsonify(
            {
                "meddelande": "Intyget har uppdaterats.",
                "data": {
                    "id": pdf_id,
                    "filename": filename,
                    "note": note,
                    "expires_on": (
                        expires_on.isoformat()
                        if expires_on and hasattr(expires_on, "isoformat")
                        else None
                    ),
                },
            }
        ),
        200,
    )

def user_upload_page():
    if not session.get("user_logged_in"):
        logger.debug("Oautentiserad åtkomst till uppladdningssidan")
        return redirect("/login")

    personnummer_hash = session.get("personnummer")
    if not personnummer_hash:
        return redirect("/login")

    user_name = session.get("username")
    if not user_name:
        user_name = functions.get_username_by_personnummer_hash(personnummer_hash)
        if user_name:
            session["username"] = user_name

    csrf_token = sec.ensure_csrf_token()
    certificate_count = functions.count_user_pdfs(personnummer_hash)
    return render_template(
        "upload_intyg.html",
        course_categories=COURSE_CATEGORIES,
        course_category_groups=COURSE_CATEGORY_GROUPS,
        csrf_token=csrf_token,
        user_name=_format_display_name(user_name),
        certificate_count=certificate_count,
        today_iso=date.today().isoformat(),
        max_upload_mb=UPLOAD_MAX_MB,
        max_upload_bytes=UPLOAD_MAX_BYTES,
    )


def download_pdf(pdf_id: int):
    # Serve a stored PDF for the logged-in user from the database.
    if not session.get("user_logged_in"):
        logger.debug("Oautentiserat nedladdningsförsök för %s", pdf_id)
        return redirect("/login")
    pnr_hash = session.get("personnummer")
    if not pnr_hash:
        return redirect("/login")
    as_attachment = request.args.get("download", "1") != "0"
    pdf = functions.get_pdf_content(pnr_hash, pdf_id)
    if not pdf:
        logger.warning("PDF %s hittades inte för användare %s", pdf_id, pnr_hash)
        abort(404)
    filename, content = pdf
    logger.info("Användare %s hämtar %s (as_attachment=%s)", pnr_hash, filename, as_attachment)
    response = make_response(content)
    response.headers["Content-Type"] = "application/pdf"
    disposition = "attachment" if as_attachment else "inline"
    response.headers["Content-Disposition"] = f'{disposition}; filename="{filename}"'
    return response


def share_pdf() -> tuple[Response, int]:  # pragma: no cover
    # Share a PDF with a recipient via e-post.
    if not session.get("user_logged_in"):
        logger.debug("Oautentiserat delningsförsök")
        return jsonify({"fel": "Du måste vara inloggad för att dela intyg."}), 401

    payload = request.get_json(silent=True) or request.form
    if not payload:
        logger.error("Tom payload i share_pdf: %r", payload)
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
        logger.debug("Inga pdf_ids angavs i share_pdf: %r", payload)
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
            logger.warning("Ogiltigt pdf_id angavs för delning: %r", raw_id)
            return jsonify({"fel": "Ogiltigt intyg angivet."}), 400
        if pdf_id in seen_ids:
            continue
        seen_ids.add(pdf_id)
        pdf_ids.append(pdf_id)

    if not pdf_ids:
        logger.debug("Tomma pdf_ids efter bearbetning i share_pdf: %r", payload)
        return jsonify({"fel": "Ogiltigt intyg angivet."}), 400

    if not recipient_email:
        logger.debug("Tom recipient_email i share_pdf: %r", payload)
        return jsonify({"fel": "Ange en e-postadress."}), 400

    pnr_hash = session.get("personnummer")
    if not pnr_hash:
        logger.error("Delningsbegäran saknar personnummer i session. Nycklar: %s", sorted(session.keys()))
        return jsonify({"fel": "Saknar användaruppgifter."}), 400

    attachments: list[tuple[str, bytes]] = []

    for pdf_id in pdf_ids:
        pdf = functions.get_pdf_content(pnr_hash, pdf_id)
        if not pdf:
            logger.debug("PDF %s hittades inte för användare %s vid delning", pdf_id, pnr_hash)
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
        logger.debug("Ogiltig recipient_email i share_pdf: %s", mask_email(recipient_email))
        return jsonify({"fel": "Ogiltig e-postadress."}), 400

    if normalized_recipient != recipient_email:
        logger.debug(
            "Normaliserade mottagaradress för delning från %r till %s",
            mask_email(recipient_email),
            mask_email(normalized_recipient),
        )

    try:
        email_service.send_pdf_share_email(
            normalized_recipient,
            attachments,
            sender_display,
        )
    except RuntimeError as exc:
        logger.error(
            "Misslyckades med att dela pdf %s från %s till %s. Fel: %s",
            pdf_ids,
            pnr_hash,
            mask_email(normalized_recipient),
            exc,
        )
        return jsonify({"fel": "Ett internt fel har inträffat."}), 500

    logger.info(
        "Användare %s delade intyg %s med %s",
        pnr_hash,
        pdf_ids,
        mask_email(normalized_recipient),
    )
    success_message = (
        "Intyget har skickats via e-post."
        if len(attachments) == 1
        else "Intygen har skickats via e-post."
    )
    return jsonify({"meddelande": success_message}), 200


def view_pdf(pdf_id: int):
    # Redirect to a direct download of the specified PDF.
    if not session.get("user_logged_in"):
        logger.debug("Oautentiserat visningsförsök för %s", pdf_id)
        return redirect("/login")
    pnr_hash = session.get("personnummer")
    if not pnr_hash:
        return redirect("/login")
    pdf = functions.get_pdf_metadata(pnr_hash, pdf_id)
    if not pdf:
        logger.warning("PDF %s hittades inte för användare %s", pdf_id, pnr_hash)
        abort(404)
    logger.info("Användare %s laddar ned %s via direktlänk", pnr_hash, pdf["filename"])
    return redirect(url_for("download_pdf", pdf_id=pdf_id))

def register_user_routes(app: Flask) -> None:
    app.add_url_rule("/dashboard", methods=["GET"], view_func=dashboard)
    app.add_url_rule("/dashboard/ladda-upp", view_func=user_upload_pdf_route, methods=['POST'])
    app.add_url_rule("/dashboard/kopplingsforfragan/<supervisor_hash>/godkann", view_func=user_accept_link_request_route, methods=['POST'])
    app.add_url_rule("/dashboard/kopplingsforfragan/<supervisor_hash>/avsla", view_func=user_reject_link_request_route, methods=['POST'])
    app.add_url_rule("/dashboard/kopplingar/<supervisor_hash>/ta-bort", view_func=user_remove_supervisor_connection_route, methods=['POST'])
    app.add_url_rule("/dashboard/kopplingar/id/<int:connection_id>/ta-bort", view_func=user_remove_supervisor_connection_by_id_route, methods=['POST'])
    app.add_url_rule("/dashboard/intyg/<int:pdf_id>/ta-bort", view_func=user_delete_pdf_route, methods=['POST'])
    app.add_url_rule("/dashboard/intyg/<int:pdf_id>/uppdatera", view_func=user_update_pdf_route, methods=['POST'])
    app.add_url_rule("/dashboard/upload", methods=["GET"], view_func=user_upload_page)
    app.add_url_rule("/my_pdfs/<int:pdf_id>", view_func=download_pdf)
    app.add_url_rule("/share_pdf", methods=["POST"], view_func=share_pdf)
    app.add_url_rule("/view_pdf/<int:pdf_id>", view_func=view_pdf)

# Copyright (c) Liam Suorsa and Mika Suorsa
