# Copyright (c) Liam Suorsa and Mika Suorsa
"""Delade hjälpfunktioner och säkra felvägar för webblagret."""

from __future__ import annotations

from calendar import monthrange
from datetime import date
import importlib
import importlib.util
import re
from typing import Any

from flask import Response, abort, jsonify, render_template, request, session
from markupsafe import Markup

import functions
from functions.logging import configure_module_logger, mask_email, mask_hash
from functions.pdf import service as pdf


logger = configure_module_logger("app")


ALLOWED_PDF_UPLOAD_ERRORS = {
    "Ingen fil vald.",
    "Endast PDF, PNG eller JPG tillåts.",
    "Filen verkar inte vara en giltig PDF.",
    "Exakt en kurskategori måste väljas.",
    "Bilden kunde inte konverteras till PDF.",
    "PDF:en blockerades av säkerhetsskannern.",
}
ALLOWED_PDF_METADATA_UPDATE_ERRORS = {
    "Intygsnamnet kan inte vara tomt.",
    "Intygsnamnet innehåller inga tillåtna tecken.",
    "Intygsnamnet får vara högst 120 tecken.",
    "Intygsnamnet måste anges som text.",
    "Anteckningen måste anges som text.",
    "Utgångsdatum måste anges som text.",
    "Antal månader måste anges som text.",
    "Antal år måste anges som text.",
    "Välj ett utgångsdatum.",
    "Välj ett giltigt utgångsdatum.",
    "Utgångsdatum kan inte vara tidigare än idag.",
    "Ange ett giltigt antal månader.",
    "Antal månader kan inte vara mindre än 0.",
    "Antal månader får vara högst 1200.",
    "Ange ett giltigt antal år.",
    "Antal år kan inte vara mindre än 0.",
    "Antal år får vara högst 100.",
    "Ange antal år, månader eller båda.",
    "Välj ett giltigt alternativ för utgångsdatum.",
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

UPLOAD_MAX_MB = 50
UPLOAD_MAX_BYTES = 52_428_800

# Gemensamma användarmeddelanden ligger här så att alla route-moduler
# kan använda exakt samma texter utan att duplicera dem.
CSRF_EXPIRED_MESSAGE = "Formuläret är inte längre giltigt. Ladda om sidan och försök igen."
TOO_MANY_ATTEMPTS_MESSAGE = "Du har gjort för många försök. Vänta en stund och prova igen."
UPLOAD_TOO_LARGE_MESSAGE = f"Uppladdningen är för stor. Max {UPLOAD_MAX_MB} MB tillåts."


class SafeUserPayloadError(ValueError):
    # Markerar valideringsfel som redan är säkra att visa direkt för användaren.
    pass


def _render_create_supervisor_page(
    error: str | None = None,
    invalid: bool = False,
    **extra: Any,
) -> str:
    """Rendera aktiveringssidan med en konsekvent uppsättning standardvärden."""
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
    rendered_lines: list[str] = []
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
    # Adminguiden ska fungera även om Markdown-paketet saknas lokalt.
    markdown_spec = importlib.util.find_spec("markdown")
    if markdown_spec is None:
        logger.warning("Markdown-biblioteket saknas, använder enkel renderare.")
        return Markup(_render_basic_markdown(text))
    markdown_module = importlib.import_module("markdown")
    rendered = markdown_module.markdown(text, extensions=["extra"])
    return Markup(rendered)


def _safe_user_error(message: str, allowed: set[str], fallback: str) -> str:
    # Släpp bara igenom fel som vi uttryckligen har godkänt för klienten.
    cleaned = (message or "").strip()
    if cleaned in allowed:
        return cleaned
    return fallback


def _add_months_to_date(base_date: date, months: int) -> date:
    # När ett datum flyttas fram ska vi bevara dagnumret när det går.
    absolute_month = (base_date.year * 12) + (base_date.month - 1) + months
    target_year, target_month_index = divmod(absolute_month, 12)
    target_month = target_month_index + 1
    target_day = min(base_date.day, monthrange(target_year, target_month)[1])
    return date(target_year, target_month, target_day)


def _parse_duration_expiry_value(raw_value: str, field_label: str, maximum: int) -> int:
    cleaned = (raw_value or "").strip()
    if not cleaned:
        return 0
    try:
        parsed = int(cleaned)
    except ValueError as exc:
        raise ValueError(f"Ange ett giltigt antal {field_label}.") from exc
    if parsed < 0:
        raise ValueError(f"Antal {field_label} kan inte vara mindre än 0.")
    if parsed > maximum:
        raise ValueError(f"Antal {field_label} får vara högst {maximum}.")
    return parsed


def _resolve_certificate_expiry(
    expiry_mode: str,
    expiry_date_raw: str,
    expiry_months_raw: str,
    expiry_years_raw: str,
    *,
    current_expires_on: date | None = None,
    today: date | None = None,
) -> date | None:
    today = today or date.today()
    normalized_mode = (expiry_mode or "none").strip().lower()
    if normalized_mode in {"", "none"}:
        return None

    if normalized_mode == "date":
        cleaned_date = (expiry_date_raw or "").strip()
        if not cleaned_date:
            raise ValueError("Välj ett utgångsdatum.")
        try:
            expires_on = date.fromisoformat(cleaned_date)
        except ValueError as exc:
            raise ValueError("Välj ett giltigt utgångsdatum.") from exc
        if current_expires_on is not None and expires_on == current_expires_on:
            return expires_on
        if expires_on < today:
            raise ValueError("Utgångsdatum kan inte vara tidigare än idag.")
        return expires_on

    if normalized_mode in {"duration", "months", "years"}:
        month_count = _parse_duration_expiry_value(expiry_months_raw, "månader", 1200)
        year_count = _parse_duration_expiry_value(expiry_years_raw, "år", 100)
        if normalized_mode == "months" and month_count == 0:
            raise ValueError("Ange hur många månader intyget gäller.")
        if normalized_mode == "years" and year_count == 0:
            raise ValueError("Ange hur många år intyget gäller.")
        if normalized_mode == "duration" and month_count == 0 and year_count == 0:
            raise ValueError("Ange antal år, månader eller båda.")
        return _add_months_to_date(today, month_count + (year_count * 12))

    raise ValueError("Välj ett giltigt alternativ för utgångsdatum.")


def _coerce_text_payload_value(value: Any, field_label: str, *, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    raise SafeUserPayloadError(f"{field_label} måste anges som text.")


def _format_display_name(name: str | None) -> str:
    # Normalisera bara visningen. Vi ändrar inte lagrade namn här.
    cleaned_name = (name or "").strip()
    if not cleaned_name:
        return ""
    return " ".join(part[:1].upper() + part[1:] for part in cleaned_name.split())


def _editable_pdf_name(filename: str) -> str:
    # Gamla timestamp-prefix ska inte läcka ut till redigeringsfältet i UI:t.
    extracted = pdf.extract_editable_pdf_name(filename)
    cleaned = re.sub(r"\.pdf$", "", extracted, flags=re.IGNORECASE).strip()
    return cleaned or "intyg"


def _request_error_context(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    # Samla felsammanhang på ett ställe så alla admin-API:er loggar lika.
    session_personnummer = session.get("personnummer")
    masked_user = (
        mask_hash(session_personnummer)
        if isinstance(session_personnummer, str) and session_personnummer
        else None
    )
    context: dict[str, Any] = {
        "endpoint": request.path,
        "method": request.method,
        "admin": session.get("admin_username") if session.get("admin_logged_in") else None,
        "user": masked_user,
    }
    if extra:
        context.update(extra)
    return context


def _log_api_error(
    *,
    user_message: str,
    status_code: int,
    severity: str,
    error: Exception | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    context = _request_error_context(extra)
    if severity == "warning":
        logger.warning(
            "API-fel (%s): %s | context=%s | error=%s",
            status_code,
            user_message,
            context,
            str(error) if error else "-",
        )
        return
    if error is not None:
        logger.exception(
            "API-systemfel (%s): %s | context=%s",
            status_code,
            user_message,
            context,
        )
        return
    logger.error("API-systemfel (%s): %s | context=%s", status_code, user_message, context)


def _api_error_response(
    user_message: str,
    status_code: int,
    *,
    severity: str = "warning",
    error: Exception | None = None,
    extra: dict[str, Any] | None = None,
) -> tuple[Response, int]:
    _log_api_error(
        user_message=user_message,
        status_code=status_code,
        severity=severity,
        error=error,
        extra=extra,
    )
    return jsonify({"status": "error", "message": user_message}), status_code


def _truncate_log_value(value: Any, limit: int) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


_SENSITIVE_KEYS = frozenset(
    {
        "email",
        "personnummer",
        "ssn",
        "name",
        "namn",
        "forename",
        "surname",
        "username",
    }
)


def _mask_sensitive_fields(value: Any) -> Any:
    # Det här används i adminverktyg där vi gärna visar struktur men inte rådata.
    if isinstance(value, dict):
        masked: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in _SENSITIVE_KEYS:
                masked[key] = "***"
            else:
                masked[key] = _mask_sensitive_fields(item)
        return masked
    if isinstance(value, list):
        return [_mask_sensitive_fields(item) for item in value]
    return value


def _sanitize_search_term(search_term: str | None) -> str | None:
    if not search_term:
        return search_term

    cleaned = search_term.strip()
    if not cleaned:
        return cleaned

    if "@" in cleaned:
        return mask_email(cleaned)

    digits = "".join(ch for ch in cleaned if ch.isdigit())
    if len(digits) in {10, 12}:
        return mask_hash(functions.hash_value(digits))

    if len(cleaned) <= 3:
        return "***"
    return f"{cleaned[:1]}***{cleaned[-1:]}"


def _mask_username_for_log(username: str | None) -> str:
    # Admininloggning ska kunna följas i loggen utan att skriva ut råa namn.
    cleaned = (username or "").strip()
    if not cleaned:
        return "<saknas>"
    if "@" in cleaned:
        return mask_email(cleaned)
    if len(cleaned) <= 3:
        return "***"
    return f"{cleaned[:2]}***{cleaned[-1]}"


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


# Copyright (c) Liam Suorsa and Mika Suorsa
