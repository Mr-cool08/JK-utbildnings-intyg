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
from typing import Callable, Sequence

from logging_utils import configure_module_logger


logger = configure_module_logger(__name__)
logger.setLevel(logging.INFO)


@dataclass(frozen=True)
class SMTPSettings:
    server: str
    port: int
    user: str
    password: str
    timeout: int


def load_smtp_settings() -> SMTPSettings:
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


def normalize_valid_email(email: str) -> str:
    if email is None:
        raise ValueError("Saknar e-postadress")

    if "\n" in email or "\r" in email:
        raise ValueError("Ogiltig e-postadress")

    cleaned = email.strip()
    if not cleaned or "@" not in cleaned:
        raise ValueError("Ogiltig e-postadress")

    local, _, domain = cleaned.partition("@")
    if not local or not domain:
        raise ValueError("Ogiltig e-postadress")

    if any(ord(ch) < 33 for ch in cleaned):
        raise ValueError("Ogiltig e-postadress")

    normalized = cleaned.lower()
    return normalized


def send_email_message(
    msg: EmailMessage,
    normalized_recipient: str,
    settings: SMTPSettings,
    *,
    smtp_class: type[SMTP] = SMTP,
    smtp_ssl_class: type[SMTP_SSL] = SMTP_SSL,
) -> None:
    context = ssl.create_default_context()

    try:
        use_ssl = settings.port == 465
        logger.info(
            "Förbereder utskick till %s via %s:%s (%s, timeout %ss)",
            normalized_recipient,
            settings.server,
            settings.port,
            "SSL" if use_ssl else "STARTTLS",
            settings.timeout,
        )

        smtp_cls = smtp_ssl_class if use_ssl else smtp_class
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
                logger.error("SMTP server refused recipients: %s", refused)
                raise RuntimeError("E-postservern accepterade inte mottagaren.")

        logger.debug(
            "Meddelande-ID för utskick till %s: %s",
            normalized_recipient,
            msg["Message-ID"],
        )

    except SMTPAuthenticationError as exc:
        logger.exception("SMTP login failed for %s", settings.user)
        raise RuntimeError("SMTP-inloggning misslyckades") from exc
    except SMTPServerDisconnected as exc:
        logger.exception("Server closed the connection during SMTP session")
        raise RuntimeError("Det gick inte att skicka e-post") from exc
    except SMTPException as exc:
        logger.exception("SMTP error when sending to %s", normalized_recipient)
        raise RuntimeError("Det gick inte att skicka e-post") from exc
    except OSError as exc:
        logger.exception("Connection error to email server")
        raise RuntimeError("Det gick inte att ansluta till e-postservern") from exc


def _configure_message_headers(msg: EmailMessage, normalized_email: str, settings: SMTPSettings) -> None:
    msg["From"] = settings.user
    msg["To"] = normalized_email
    msg["Message-ID"] = make_msgid()
    msg["Date"] = format_datetime(datetime.now(timezone.utc))


def send_pdf_share_email(
    recipient_email: str,
    attachments: Sequence[tuple[str, bytes]],
    sender_name: str,
    owner_name: str | None = None,
    *,
    settings: SMTPSettings | None = None,
    send_func: Callable[[EmailMessage, str, SMTPSettings], None] | None = None,
) -> None:
    if not attachments:
        raise ValueError("Minst ett intyg krävs för delning.")

    normalized_email = normalize_valid_email(recipient_email)
    effective_settings = settings or load_smtp_settings()
    effective_send = send_func or send_email_message

    safe_sender = escape(sender_name.strip() or "En användare")
    safe_owner = escape((owner_name or "").strip()) if owner_name else None

    msg = EmailMessage(policy=policy.SMTP.clone(max_line_length=1000))
    subject_prefix = "Delade" if len(attachments) > 1 else "Delat"
    if safe_owner:
        msg["Subject"] = f"{subject_prefix} intyg för {safe_owner} från {safe_sender}"
    else:
        msg["Subject"] = f"{subject_prefix} intyg från {safe_sender}"

    _configure_message_headers(msg, normalized_email, effective_settings)

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

    msg.set_content(body_html, subtype="html")

    for filename, content in attachments:
        msg.add_attachment(
            content,
            maintype="application",
            subtype="pdf",
            filename=filename,
        )

    effective_send(msg, normalized_email, effective_settings)


def send_password_reset_email(
    to_email: str,
    link: str,
    *,
    settings: SMTPSettings | None = None,
    send_func: Callable[[EmailMessage, str, SMTPSettings], None] | None = None,
) -> None:
    normalized_email = normalize_valid_email(to_email)
    effective_settings = settings or load_smtp_settings()
    effective_send = send_func or send_email_message

    msg = EmailMessage(policy=policy.SMTP.clone(max_line_length=1000))
    msg["Subject"] = "Återställ ditt lösenord"
    _configure_message_headers(msg, normalized_email, effective_settings)
    msg.set_content(
        f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                <p>Hej,</p>
                <p>Du har begärt att återställa ditt lösenord. Använd länken nedan för att välja ett nytt lösenord:</p>
                <p><a href=\"{link}\">{link}</a></p>
                <p>Länken är giltig i 48 timmar. Om du inte begärde detta kan du ignorera meddelandet.</p>
            </body>
        </html>
        """,
        subtype="html",
    )

    effective_send(msg, normalized_email, effective_settings)


def send_creation_email(
    to_email: str,
    link: str,
    *,
    settings: SMTPSettings | None = None,
    send_func: Callable[[EmailMessage, str, SMTPSettings], None] | None = None,
) -> None:
    normalized_email = normalize_valid_email(to_email)
    effective_settings = settings or load_smtp_settings()
    effective_send = send_func or send_email_message

    msg = EmailMessage(policy=policy.SMTP.clone(max_line_length=1000))
    msg["Subject"] = "Skapa ditt konto"
    _configure_message_headers(msg, normalized_email, effective_settings)
    msg.set_content(
        f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.5;'>
                <p>Hej,</p>
                <p>Skapa ditt konto genom att besöka denna länk:</p>
                <p><a href=\"{link}\">{link}</a></p>
                <p>Om du inte begärde detta e-postmeddelande kan du ignorera det.</p>
            </body>
        </html>
        """,
        subtype="html",
    )

    effective_send(msg, normalized_email, effective_settings)
