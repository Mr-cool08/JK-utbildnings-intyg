# Copyright (c) Liam Suorsa
from __future__ import annotations

import logging
import os
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from html import escape
from smtplib import (
    SMTP,
    SMTPAuthenticationError,
    SMTPException,
    SMTPServerDisconnected,
    SMTP_SSL,
)
from typing import Sequence

from config_loader import load_environment
from functions.logging import configure_module_logger, mask_hash

import functions


logger = configure_module_logger(__name__)
logger.setLevel(logging.INFO)

load_environment()

SUPPORT_EMAIL = "support@utbildningsintyg.se"


@dataclass(frozen=True)
class SMTPSettings:
    server: str
    port: int
    user: str
    password: str
    timeout: int
    from_address: str


def load_smtp_settings() -> SMTPSettings:
    """Read SMTP configuration from environment variables."""

    smtp_server = os.getenv("smtp_server")
    smtp_port = int(os.getenv("smtp_port", "587"))
    smtp_user = os.getenv("smtp_user")
    smtp_password = os.getenv("smtp_password")
    smtp_timeout = int(os.getenv("smtp_timeout", "10"))
    smtp_from = os.getenv("smtp_from") or smtp_user

    if not (smtp_server and smtp_user and smtp_password):
        raise RuntimeError("Saknar env: smtp_server, smtp_user eller smtp_password")

    try:
        normalized_from = normalize_valid_email(smtp_from)
    except ValueError as exc:
        raise RuntimeError("Ogiltig avsändaradress. Ange en giltig smtp_from.") from exc

    return SMTPSettings(
        server=smtp_server,
        port=smtp_port,
        user=smtp_user,
        password=smtp_password,
        timeout=smtp_timeout,
        from_address=normalized_from,
    )


def normalize_valid_email(address: str) -> str:
    """Normalize an email address and ensure it appears valid."""

    normalized = functions.normalize_email(address)
    if "@" not in normalized:
        raise ValueError("Ogiltig e-postadress.")

    local_part, _, domain = normalized.partition("@")
    if not local_part or not domain:
        raise ValueError("Ogiltig e-postadress.")

    if domain.startswith("-") or domain.endswith("-") or ".." in domain:
        raise ValueError("Ogiltig e-postadress.")

    if normalized != address:
        logger.debug("Normalized recipient email from %r to %s", address, normalized)

    return normalized


def send_email_message(
    msg: EmailMessage, normalized_recipient: str, settings: SMTPSettings
) -> None:
    """Send ``msg`` to ``normalized_recipient`` using ``settings``."""

    context = ssl.create_default_context()
    recipient_mask = mask_hash(functions.hash_value(normalized_recipient))

    try:
        use_ssl = settings.port == 465
        logger.info(
            "Förbereder utskick till %s via %s:%s (%s, timeout %ss)",
            recipient_mask,
            settings.server,
            settings.port,
            "SSL" if use_ssl else "STARTTLS",
            settings.timeout,
        )

        smtp_cls = SMTP_SSL if use_ssl else SMTP
        smtp_kwargs = {"timeout": settings.timeout}
        if use_ssl:
            smtp_kwargs["context"] = context

        with smtp_cls(settings.server, settings.port, **smtp_kwargs) as smtp:
            if hasattr(smtp, "ehlo"):
                smtp.ehlo()

            if not use_ssl:
                try:
                    from inspect import signature

                    if "context" in signature(smtp.starttls).parameters:
                        smtp.starttls(context=context)
                        logger.debug("SMTP STARTTLS initierad med kontext")
                    else:
                        smtp.starttls()
                        logger.debug("SMTP STARTTLS initierad utan kontext")
                except (TypeError, ValueError):
                    smtp.starttls()
                    logger.debug("SMTP STARTTLS initierad (fallback)")

                if hasattr(smtp, "ehlo"):
                    smtp.ehlo()

            smtp.login(settings.user, settings.password)
            logger.debug("SMTP inloggning lyckades för %s", settings.user)

            if hasattr(smtp, "send_message"):
                refused = smtp.send_message(
                    msg,
                    from_addr=settings.from_address,
                    to_addrs=[normalized_recipient],
                )
            else:
                refused = smtp.sendmail(
                    settings.from_address, [normalized_recipient], msg.as_string()
                )

            logger.debug("SMTP svar för %s: %s", recipient_mask, refused or "ok")
            if refused:
                logger.error("SMTP server refused recipients: %s", recipient_mask)
                raise RuntimeError("E-postservern accepterade inte mottagaren.")

        logger.debug(
            "Meddelande-ID för utskick till %s: %s",
            recipient_mask,
            msg["Message-ID"],
        )

    except SMTPAuthenticationError as exc:
        logger.exception("SMTP login failed for %s", settings.user)
        raise RuntimeError("SMTP-inloggning misslyckades") from exc
    except SMTPServerDisconnected as exc:
        logger.exception("Server closed the connection during SMTP session")
        raise RuntimeError("Det gick inte att skicka e-post") from exc
    except SMTPException as exc:
        logger.exception("SMTP error when sending to %s", recipient_mask)
        raise RuntimeError("Det gick inte att skicka e-post") from exc
    except OSError as exc:
        logger.exception("Connection error to email server")
        raise RuntimeError("Det gick inte att ansluta till e-postservern") from exc


def send_email(
    recipient_email: str,
    subject: str,
    html_body: str,
    attachments: Sequence[tuple[str, bytes]] | None = None,
) -> None:
    """Create an ``EmailMessage`` and send it to ``recipient_email``."""

    normalized_email = normalize_valid_email(recipient_email)
    recipient_mask = mask_hash(functions.hash_value(normalized_email))
    logger.info(
        "Förbereder e-post med ämne '%s' till %s (bilagor: %s)",
        subject,
        recipient_mask,
        len(attachments) if attachments else 0,
    )
    settings = load_smtp_settings()
    logger.debug(
        "SMTP-inställningar laddade: server=%s port=%s användare=%s avsändare=%s",
        settings.server,
        settings.port,
        mask_hash(functions.hash_value(settings.user)),
        mask_hash(functions.hash_value(settings.from_address)),
    )

    msg = EmailMessage(policy=policy.SMTP.clone(max_line_length=1000))
    msg["Subject"] = subject
    msg["From"] = settings.from_address
    msg["To"] = normalized_email
    msg["Message-ID"] = make_msgid()
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg.set_content(html_body, subtype="html")

    if attachments:
        for filename, content in attachments:
            msg.add_attachment(
                content,
                maintype="application",
                subtype="pdf",
                filename=filename,
            )

    send_email_message(msg, normalized_email, settings)
    logger.info("E-post med ämne '%s' skickad till %s", subject, recipient_mask)


def format_email_html(
    title: str,
    content_html: str,
    accent_color: str = "#0f766e",
    footer_text: str = (
        "Detta är ett automatiskt meddelande från utbildningsintyg.se. "
        "Svara inte på detta e-postmeddelande."
    ),
) -> str:
    """Wrap HTML content in a shared, styled email layout."""
    safe_title = escape(title)
    safe_footer = escape(footer_text)
    return f"""
        <html>
            <body style='margin:0;padding:0;background-color:#f4f7fb;'>
                <table role='presentation' cellpadding='0' cellspacing='0' width='100%' style='background-color:#f4f7fb;padding:24px 0;'>
                    <tr>
                        <td align='center'>
                            <table role='presentation' cellpadding='0' cellspacing='0' width='600' style='width:600px;max-width:100%;background-color:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 6px 18px rgba(15,23,42,0.08);'>
                                <tr>
                                    <td style='background-color:{accent_color};padding:24px 32px;'>
                                        <h1 style='margin:0;font-family:Arial,sans-serif;font-size:22px;line-height:1.3;color:#ffffff;'>{safe_title}</h1>
                                    </td>
                                </tr>
                                <tr>
                                    <td style='padding:28px 32px;font-family:Arial,sans-serif;color:#1f2937;font-size:15px;line-height:1.6;'>
                                        {content_html}
                                    </td>
                                </tr>
                                <tr>
                                    <td style='padding:20px 32px;background-color:#f8fafc;border-top:1px solid #e2e8f0;font-family:Arial,sans-serif;font-size:12px;color:#64748b;text-align:center;'>
                                        {safe_footer}
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
        </html>
    """


def _render_action_button(url: str, label: str) -> str:
    safe_url = escape(url, quote=True)
    safe_label = escape(label)
    return (
        "<table role='presentation' cellspacing='0' cellpadding='0' style='margin:16px 0 8px;'>"
        "<tr>"
        "<td align='center' style='border-radius:6px;' bgcolor='#0f766e'>"
        f"<a href='{safe_url}' "
        "style='display:inline-block;padding:12px 20px;font-family:Arial,sans-serif;"
        "font-size:15px;color:#ffffff;text-decoration:none;font-weight:bold;'>"
        f"{safe_label}</a>"
        "</td>"
        "</tr>"
        "</table>"
    )


def send_creation_email(to_email: str, link: str) -> None:
    """Send an account creation email containing ``link``."""

    safe_link = escape(link, quote=True)
    content = (
        "<p>Hej,</p>"
        "<p>Vi har tagit emot en begäran om att skapa ett konto. "
        "Klicka på knappen nedan för att komma igång.</p>"
        f"{_render_action_button(link, 'Skapa konto')}"
        "<p>Om knappen inte fungerar kan du kopiera länken:</p>"
        f"<p><a href='{safe_link}'>{safe_link}</a></p>"
        "<p>Om du inte begärde detta e-postmeddelande kan du ignorera det.</p>"
    )

    body = format_email_html("Skapa ditt konto", content)
    send_email(to_email, "Skapa ditt konto", body)


def send_password_reset_email(to_email: str, link: str) -> None:
    """Send a password reset email containing ``link``."""

    safe_link = escape(link, quote=True)
    content = (
        "<p>Hej,</p>"
        "<p>Du har begärt att återställa ditt lösenord. "
        "Använd knappen nedan för att välja ett nytt lösenord.</p>"
        f"{_render_action_button(link, 'Återställ lösenord')}"
        "<p>Om knappen inte fungerar kan du kopiera länken:</p>"
        f"<p><a href='{safe_link}'>{safe_link}</a></p>"
        "<p>Länken är giltig i 48 timmar. Om du inte begärde detta kan du ignorera meddelandet.</p>"
    )

    body = format_email_html("Återställ ditt lösenord", content, accent_color="#2563eb")
    send_email(to_email, "Återställ ditt lösenord", body)


def send_account_deletion_email(to_email: str, username: str | None = None) -> None:
    """Send an account deletion notification."""

    stripped = username.strip() if username is not None else ""
    display_name = escape(stripped) if stripped else "ditt konto"
    content = (
        "<p>Hej,</p>"
        f"<p>Vi vill informera dig om att {display_name} hos utbildningsintyg.se har raderats.</p>"
        "<p>Om detta inte stämmer, kontakta vår support på "
        f"<a href='mailto:{SUPPORT_EMAIL}'>{SUPPORT_EMAIL}</a>.</p>"
        "<p>Tack för att du har använt utbildningsintyg.se.</p>"
    )

    body = format_email_html("Ditt konto har raderats", content, accent_color="#ef4444")
    send_email(to_email, "Ditt konto har raderats", body)


def send_pdf_share_email(
    recipient_email: str,
    attachments: Sequence[tuple[str, bytes]],
    sender_name: str,
    owner_name: str | None = None,
) -> None:
    """Send shared certificate emails with ``attachments``."""

    if not attachments:
        raise ValueError("Minst ett intyg krävs för delning.")

    safe_sender = escape(sender_name.strip() or "Ett standardkonto")
    safe_owner = escape((owner_name or "").strip()) if owner_name else None

    subject_prefix = "Delade" if len(attachments) > 1 else "Delat"
    if safe_owner:
        subject = f"{subject_prefix} intyg för {safe_owner} från {safe_sender}"
    else:
        subject = f"{subject_prefix} intyg från {safe_sender}"

    if len(attachments) == 1:
        safe_filename = escape(attachments[0][0])
        if safe_owner:
            sharing_line = f"<p><strong>{safe_sender}</strong> delar <strong>{safe_owner}</strong>s intyg med dig via utbildningsintyg.se.</p>"
        else:
            sharing_line = f"<p><strong>{safe_sender}</strong> har delat ett intyg med dig via utbildningsintyg.se.</p>"
        content = (
            "<p>Hej,</p>"
            + sharing_line
            + f"<p>Intyget hittar du i bilagan med filnamnet <em>{safe_filename}</em>.</p>"
            "<p>Har du inte begärt detta intyg kan du ignorera detta e-postmeddelande.</p>"
        )
    else:
        item_list = "".join(f"<li><em>{escape(filename)}</em></li>" for filename, _ in attachments)
        if safe_owner:
            sharing_line = f"<p><strong>{safe_sender}</strong> delar intyg som tillhör <strong>{safe_owner}</strong> med dig via utbildningsintyg.se.</p>"
        else:
            sharing_line = f"<p><strong>{safe_sender}</strong> har delat flera intyg med dig via utbildningsintyg.se.</p>"
        content = (
            "<p>Hej,</p>" + sharing_line + "<p>Intygen hittar du i följande bilagor:</p>"
            f"<ul>{item_list}</ul>"
            "<p>Har du inte begärt dessa intyg kan du ignorera detta e-postmeddelande.</p>"
        )

    body_html = format_email_html(subject, content, accent_color="#0ea5e9")
    send_email(recipient_email, subject, body_html, attachments=attachments)


def send_application_rejection_email(to_email: str, company_name: str, reason: str) -> None:
    """Skicka besked om avslagen ansökan."""

    safe_company = escape((company_name or "").strip())
    if not safe_company:
        safe_company = "företaget"
    safe_reason = escape(reason)
    subject = f"Ansökan avslogs för {safe_company}"
    content = (
        "<p>Hej,</p>"
        f"<p>Vi har tyvärr inte kunnat godkänna din ansökan om konto kopplat till {safe_company}.</p>"
        "<p><strong>Motivering:</strong></p>"
        f"<p style='background-color:#fef2f2;border-left:4px solid #ef4444;padding:12px 14px;border-radius:6px;margin-top:6px;'>"
        f"{safe_reason}</p>"
        f"<p>Har du frågor är du välkommen att kontakta oss på {SUPPORT_EMAIL}.</p>"
        "<p>Vänliga hälsningar<br>utbildningsintyg.se</p>"
    )
    body = format_email_html("Din ansökan blev avslagen", content, accent_color="#ef4444")
    send_email(to_email, subject, body)


def send_critical_event_alert(event_type: str, details: str = "") -> None:
    """Skicka kritisk händelseavisering till en eller flera systemadministratörer.

    Supports multiple email addresses separated by commas:
    CRITICAL_ALERTS_EMAIL=admin1@example.com,admin2@example.com
    """

    alert_email_str = os.getenv("CRITICAL_ALERTS_EMAIL", "admin@example.com")

    if not alert_email_str:
        logger.warning("CRITICAL_ALERTS_EMAIL not configured, cannot send alert")
        return

    # Split by comma and strip whitespace
    alert_emails = [e.strip() for e in alert_email_str.split(",") if e.strip()]

    if not alert_emails:
        logger.warning("CRITICAL_ALERTS_EMAIL is empty, cannot send alert")
        return

    event_labels = {
        "startup": "Applikationen startade",
        "shutdown": "Applikationen stängdes av",
        "restart": "Applikationen startades om",
        "crash": "Applikationen kraschade",
        "error": "Kritiskt fel inträffade",
    }

    event_label = event_labels.get(event_type, event_type)
    safe_details = escape(details) if details else "Ingen ytterligare information."

    subject = f"[KRITISK HÄNDELSE] {event_label}"

    from datetime import datetime

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = os.getenv("HOSTNAME", "okänd")

    content = (
        "<p>En kritisk systemhändelse har inträffat.</p>"
        f"<p><strong>Händelse:</strong> {event_label}</p>"
        f"<p><strong>Tid:</strong> {timestamp}</p>"
        f"<p><strong>Server:</strong> {escape(hostname)}</p>"
        "<p><strong>Detaljer:</strong></p>"
        f"<pre style='background-color:#f1f5f9;padding:12px;border-radius:6px;white-space:pre-wrap;'>"
        f"{safe_details}</pre>"
        "<p>Kontrollera loggar och driftstatus så snart som möjligt.</p>"
    )
    body = format_email_html(
        "Kritisk systemhändelse",
        content,
        accent_color="#dc2626",
        footer_text="Detta är ett automatiskt meddelande från systemövervakningen för utbildningsintyg.se.",
    )

    # Send to all configured email addresses
    for email_address in alert_emails:
        try:
            send_email(email_address, subject, body)
            logger.info(
                "Critical event alert sent to %s for event_type=%s", email_address, event_type
            )
        except RuntimeError as e:
            logger.error("Failed to send critical event alert to %s: %s", email_address, e)
