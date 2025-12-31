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
from logging_utils import configure_module_logger, mask_hash

import functions


logger = configure_module_logger(__name__)
logger.setLevel(logging.INFO)

load_environment()


@dataclass(frozen=True)
class SMTPSettings:
    server: str
    port: int
    user: str
    password: str
    timeout: int


def load_smtp_settings() -> SMTPSettings:
    """Read SMTP configuration from environment variables."""

    smtp_server = os.getenv("smtp_server")
    smtp_port = int(os.getenv("smtp_port", "587"))
    smtp_user = os.getenv("smtp_user")
    smtp_password = os.getenv("smtp_password")
    smtp_timeout = int(os.getenv("smtp_timeout", "10"))

    if not (smtp_server and smtp_user and smtp_password):
        raise RuntimeError("Saknar env: smtp_server, smtp_user eller smtp_password")

    return SMTPSettings(
        server=smtp_server,
        port=smtp_port,
        user=smtp_user,
        password=smtp_password,
        timeout=smtp_timeout,
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
                refused = smtp.send_message(msg)
            else:
                refused = smtp.sendmail(
                    settings.user, [normalized_recipient], msg.as_string()
                )

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

    msg = EmailMessage(policy=policy.SMTP.clone(max_line_length=1000))
    msg["Subject"] = subject
    msg["From"] = settings.user
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
    logger.info(
        "E-post med ämne '%s' skickad till %s", subject, recipient_mask
    )


def send_creation_email(to_email: str, link: str) -> None:
    """Send an account creation email containing ``link``."""

    safe_link = escape(link, quote=True)
    body = f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                <p>Hej,</p>
                <p>Skapa ditt konto genom att besöka denna länk:</p>
                <p><a href="{safe_link}">{safe_link}</a></p>
                <p>Om du inte begärde detta e-postmeddelande kan du ignorera det.</p>
            </body>
        </html>
    """

    send_email(to_email, "Skapa ditt konto", body)


def send_password_reset_email(to_email: str, link: str) -> None:
    """Send a password reset email containing ``link``."""

    safe_link = escape(link, quote=True)
    body = f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                <p>Hej,</p>
                <p>Du har begärt att återställa ditt lösenord. Använd länken nedan för att välja ett nytt lösenord:</p>
                <p><a href="{safe_link}">{safe_link}</a></p>
                <p>Länken är giltig i 48 timmar. Om du inte begärde detta kan du ignorera meddelandet.</p>
            </body>
        </html>
    """

    send_email(to_email, "Återställ ditt lösenord", body)


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
            sharing_line = (
                f"<p><strong>{safe_sender}</strong> delar <strong>{safe_owner}</strong>s intyg med dig via JK Utbildningsintyg.</p>"
            )
        else:
            sharing_line = (
                f"<p><strong>{safe_sender}</strong> har delat ett intyg med dig via JK Utbildningsintyg.</p>"
            )
        body_html = (
            "<html>"
            "<body style='font-family: Arial, sans-serif; line-height: 1.5;'>"
            "<p>Hej,</p>"
            + sharing_line
            + f"<p>Intyget hittar du i bilagan med filnamnet <em>{safe_filename}</em>.</p>"
            "<p>Har du inte begärt detta intyg kan du ignorera detta e-postmeddelande.</p>"
            "</body>"
            "</html>"
        )
    else:
        item_list = "".join(
            f"<li><em>{escape(filename)}</em></li>" for filename, _ in attachments
        )
        if safe_owner:
            sharing_line = (
                f"<p><strong>{safe_sender}</strong> delar intyg som tillhör <strong>{safe_owner}</strong> med dig via JK Utbildningsintyg.</p>"
            )
        else:
            sharing_line = (
                f"<p><strong>{safe_sender}</strong> har delat flera intyg med dig via JK Utbildningsintyg.</p>"
            )
        body_html = (
            "<html>"
            "<body style='font-family: Arial, sans-serif; line-height: 1.5;'>"
            "<p>Hej,</p>"
            + sharing_line
            + "<p>Intygen hittar du i följande bilagor:</p>"
            f"<ul>{item_list}</ul>"
            "<p>Har du inte begärt dessa intyg kan du ignorera detta e-postmeddelande.</p>"
            "</body>"
            "</html>"
        )

    send_email(recipient_email, subject, body_html, attachments=attachments)


def send_application_approval_email(
    to_email: str, account_type: str, company_name: str
) -> None:
    """Skicka besked om godkänd ansökan."""

    normalized_type = account_type.lower()
    company_text = (company_name or "").strip()
    company_text = " ".join(company_text.splitlines())
    safe_company_html = escape(company_text)

    if normalized_type == "foretagskonto":
        if not company_text:
            company_text = "företaget"
            safe_company_html = "företaget"
        account_label = "ett företagskonto"
        subject = f"Ansökan godkänd för {company_text}"
        body = f"""
            <html>
                <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                    <p>Hej,</p>
                    <p>Din ansökan om {account_label} kopplat till {safe_company_html} har blivit godkänd.</p>
                    <p>Vi har registrerat kontot och kopplat det till företaget via organisationsnumret. Du får separat information om hur du loggar in.</p>
                    <p>Om något ser fel ut, kontakta oss på support@jarnvagskonsulterna.se.</p>
                    <p>Vänliga hälsningar<br>JK Utbildningsintyg</p>
                </body>
            </html>
        """
    else:
        account_label = "ett standardkonto"
        company_phrase = f" kopplat till {safe_company_html}" if company_text else ""
        subject = (
            f"Ansökan om standardkonto godkänd{f' för {company_text}' if company_text else ''}"
        )
        body = f"""
            <html>
                <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                    <p>Hej,</p>
                    <p>Din ansökan om {account_label}{company_phrase} har blivit godkänd.</p>
                    <p>Kontot har skapats och du får separat information om hur du loggar in.</p>
                    <p>Om något ser fel ut, kontakta oss på support@jarnvagskonsulterna.se.</p>
                    <p>Vänliga hälsningar<br>JK Utbildningsintyg</p>
                </body>
            </html>
        """
    send_email(to_email, subject, body)


def send_application_rejection_email(
    to_email: str, company_name: str, reason: str
) -> None:
    """Skicka besked om avslagen ansökan."""

    safe_company = escape((company_name or "").strip())
    if not safe_company:
        safe_company = "företaget"
    safe_reason = escape(reason)
    subject = f"Ansökan avslogs för {safe_company}"
    body = f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                <p>Hej,</p>
                <p>Vi har tyvärr inte kunnat godkänna din ansökan om konto kopplat till {safe_company}.</p>
                <p>Motivering: {safe_reason}</p>
                <p>Har du frågor är du välkommen att kontakta oss på support@jarnvagskonsulterna.se.</p>
                <p>Vänliga hälsningar<br>JK Utbildningsintyg</p>
            </body>
        </html>
    """
    send_email(to_email, subject, body)


def send_critical_event_alert(event_type: str, details: str = "") -> None:
    """Skicka kritisk händelseavisering till systemadministratör."""

    alert_email = os.getenv("CRITICAL_ALERTS_EMAIL", "liam@suorsa.se")
    
    if not alert_email:
        logger.warning("CRITICAL_ALERTS_EMAIL not configured, cannot send alert")
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
    
    body = f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.5; color: #333;'>
                <h2 style='color: #d9534f;'>Kritisk systemhändelse</h2>
                <p><strong>Händelse:</strong> {event_label}</p>
                <p><strong>Tid:</strong> {timestamp}</p>
                <p><strong>Server:</strong> {escape(hostname)}</p>
                <p><strong>Detaljer:</strong></p>
                <pre style='background-color: #f5f5f5; padding: 10px; border-radius: 4px;'>{safe_details}</pre>
                <hr>
                <p style='font-size: 12px; color: #666;'>
                    Detta är ett automatiskt meddelande från JK Utbildningsintyg systemövervakning.
                </p>
            </body>
        </html>
    """
    
    try:
        send_email(alert_email, subject, body)
        logger.info("Critical event alert sent for event_type=%s", event_type)
    except RuntimeError as e:
        logger.error("Failed to send critical event alert: %s", e)
