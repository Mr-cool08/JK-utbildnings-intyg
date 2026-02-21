# Copyright (c) Liam Suorsa
# Service for sending email notifications about critical application events.

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from email.utils import format_datetime
from html import escape
from threading import Thread, local
from typing import Optional

from config_loader import load_environment
from functions.emails import service as email_service
from functions.logging import AppTimezoneFormatter, collect_log_attachments, configure_module_logger


logger = configure_module_logger(__name__)
logger.setLevel(logging.INFO)

load_environment()

_EMAIL_HANDLER_STATE = local()
_EMAIL_FAILURE_LOGGER = logging.getLogger("notifications.email_failures")
if not _EMAIL_FAILURE_LOGGER.handlers:
    _email_failure_handler = logging.StreamHandler()
    _email_failure_handler.setFormatter(
        AppTimezoneFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    _EMAIL_FAILURE_LOGGER.addHandler(_email_failure_handler)
_EMAIL_FAILURE_LOGGER.propagate = False
_EMAIL_FAILURE_LOGGER.setLevel(logging.ERROR)


class EmailErrorHandler(logging.Handler):
    """Logging handler that emails ERROR level records to admin recipients.

    Sends ERROR-level log records to configured ADMIN_EMAIL.
    CRITICAL level records are handled separately through other notification mechanisms.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # Only handle ERROR level logs (not CRITICAL - those are handled separately)
            if record.levelno != logging.ERROR:
                return
            if getattr(record, "_email_error_handler_sent", False):
                return
            if getattr(_EMAIL_HANDLER_STATE, "active", False):
                return

            record._email_error_handler_sent = True
            _EMAIL_HANDLER_STATE.active = True
            try:
                # Format the log message
                message = self.format(record)

                # Notification type for ERROR level logs
                notification_type = "error"
                title = f"[FEL] {record.levelname}: {record.name}"
                log_level = logging.ERROR

                # Use unified notification system - will get ADMIN_EMAIL automatically
                send_unified_notification(
                    notification_type=notification_type,
                    title=title,
                    description=message,
                    log_level=log_level,
                )
            finally:
                _EMAIL_HANDLER_STATE.active = False

        except Exception as error:
            # Never raise from a logging handler, but log failure without recursive email handler usage.
            _EMAIL_FAILURE_LOGGER.error(
                "Emailnotifiering misslyckades i EmailErrorHandler: %s",
                str(error),
                exc_info=True
            )


def _get_admin_emails() -> list[str]:
    """Get admin email addresses from environment.

    Supports both single and multiple emails:
    - Single: ADMIN_EMAIL=email@example.com
    - Multiple: ADMIN_EMAIL=email1@example.com,email2@example.com
    """
    email_str = os.getenv("ADMIN_EMAIL")
    if not email_str:
        raise RuntimeError("ADMIN_EMAIL environment variable is not set")

    # Split by comma and strip whitespace
    emails = [e.strip() for e in email_str.split(",") if e.strip()]
    if not emails:
        raise RuntimeError("ADMIN_EMAIL environment variable is empty")

    return emails


def _get_app_name() -> str:
    """Get the application name from environment or use default."""
    return os.getenv("APP_NAME", "utbildningsintyg.se")


def _get_timestamp() -> str:
    """Get current timestamp in Swedish locale."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%d %H:%M:%S UTC")


def _get_hostname() -> str:
    """Get current hostname from environment or system."""
    hostname = os.getenv("HOSTNAME")
    if hostname:
        return hostname
    try:
        import socket

        return socket.gethostname()
    except OSError:
        return "okänd"


def _send_email_async(recipients: list[str], subject: str, html_body: str) -> None:
    """Send email asynchronously to multiple recipients to avoid blocking the application."""
    attachments: list[tuple[str, bytes]] = collect_log_attachments()

    for recipient in recipients:
        try:
            if attachments:
                email_service.send_email(recipient, subject, html_body, attachments=attachments)
            else:
                email_service.send_email(recipient, subject, html_body)
        except Exception as error:
            _EMAIL_FAILURE_LOGGER.error(
                "Misslyckades att skicka e-post till %s: %s",
                recipient,
                str(error),
                exc_info=True
            )


def send_unified_notification(
    notification_type: str,
    title: str,
    description: str,
    error_message: Optional[str] = None,
    log_level: int = logging.ERROR,
    recipients: Optional[list[str]] = None,
) -> None:
    """
    Unified notification function that logs and sends emails consistently.

    Args:
        notification_type: Type of notification (error, critical, crash, etc.)
        title: Email subject and log title
        description: Human-readable description of the event
        error_message: Optional error/exception message to include
        log_level: Python logging level to use (default: ERROR)
        recipients: Email recipients (uses ADMIN_EMAIL if not provided)
    """
    timestamp = datetime.now(timezone.utc)
    timestamp_str = format_datetime(timestamp)
    iso_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    app_name = _get_app_name()
    hostname = _get_hostname()

    # Determine recipients
    if recipients is None:
        try:
            recipients = _get_admin_emails()
        except RuntimeError:
            recipients = []

    # Log the notification
    log_message = f"[{notification_type.upper()}] {title}\n{description}"
    if error_message:
        log_message += f"\n\nFelmeddelande:\n{error_message}"

    logger.log(log_level, log_message)

    # If no recipients, skip email sending
    if not recipients:
        return

    # Build email content
    safe_description = escape(description)
    safe_error = escape(error_message) if error_message else None

    event_colors = {
        "error": "#f97316",      # Orange
        "critical": "#dc3545",   # Red
        "crash": "#dc3545",      # Red
        "warning": "#ff9800",    # Orange
        "startup": "#28a745",    # Green
        "shutdown": "#ffc107",   # Amber
        "restart": "#17a2b8",    # Cyan
    }
    color = event_colors.get(notification_type.lower(), "#6c757d")

    content = (
        f"<p><strong>Tidsstämpel:</strong> {timestamp_str}</p>"
        f"<p><strong>Applikation:</strong> {escape(app_name)}</p>"
        f"<p><strong>Värd:</strong> {escape(hostname)}</p>"
        f"<p><strong>Händelsetyp:</strong> {escape(notification_type)}</p>"
        "<p><strong>Beskrivning:</strong></p>"
        f"<p style='margin-top:6px;white-space:pre-wrap;word-wrap:break-word;'>{safe_description}</p>"
    )

    if safe_error:
        content += (
            "<p><strong>Felmeddelande:</strong></p>"
            "<p style='margin-top:6px;background-color:#fef2f2;border-left:4px solid #ef4444;"
            "padding:10px;border-radius:6px;white-space:pre-wrap;word-wrap:break-word;'>"
            f"{safe_error}</p>"
        )

    html_body = email_service.format_email_html(
        title,
        content,
        accent_color=color,
    )

    # Send email asynchronously
    thread = Thread(
        target=_send_email_async, args=(recipients, title, html_body), daemon=True
    )
    thread.start()


def send_critical_event_email(
    event_type: str,
    title: str,
    description: str,
    error_message: Optional[str] = None,
) -> None:
    """
    Send an email notification about a critical application event.

    Args:
        event_type: Type of event (startup, shutdown, crash, restart, error)
        title: Email subject title
        description: Description of what happened
        error_message: Optional error/exception message
    """
    send_unified_notification(
        notification_type=event_type,
        title=title,
        description=description,
        error_message=error_message,
        log_level=logging.CRITICAL,
    )


def send_startup_notification(hostname: str = "Unknown") -> None:
    """Send notification that the application has started."""
    send_critical_event_email(
        event_type="startup",
        title="🟢 Applikation startad",
        description=f"Applikationen har startats framgångsrikt.\n\nVärd: {escape(hostname)}\nTidsstämpel: {_get_timestamp()}",
    )

def send_crash_notification(
    error_message: str,
    traceback: str = "",
) -> None:
    """Send notification that the application has crashed."""
    send_critical_event_email(
        event_type="crash",
        title="🔴 KRITISK: Applikationen har kraschat",
        description=f"Applikationen har drabbats av ett allvarligt fel och kan ha kraschat.\n\nTidsstämpel: {_get_timestamp()}",
        error_message=error_message if error_message else traceback,
    )


def send_restart_notification(reason: str = "Systemomstart") -> None:
    """Send notification that the application is restarting."""
    send_critical_event_email(
        event_type="restart",
        title="🔄 Applikation startas om",
        description=f"Applikationen startas om.\n\nAnledning: {escape(reason)}\nTidsstämpel: {_get_timestamp()}",
    )


def send_unhandled_exception_notification(
    error_message: str,
    traceback: str = "",
    context: str = "",
) -> None:
    """Send notification about an unhandled exception."""
    full_error = error_message
    if traceback:
        full_error = f"{error_message}\n\n--- Traceback ---\n{traceback}"

    description = f"En obehandlad exception uppstod i applikationen.\n\nKontext: {escape(context)}\nTidsstämpel: {_get_timestamp()}"

    send_critical_event_email(
        event_type="exception",
        title="⚠️ Obehandlad Exception",
        description=description,
        error_message=full_error,
    )


def send_critical_error_notification(
    error_message: str,
    endpoint: str = "",
    user_ip: str = "",
) -> None:
    """Send notification about a critical HTTP error (500)."""
    context_parts = []
    if endpoint:
        context_parts.append(f"Endpoint: {escape(endpoint)}")
    if user_ip:
        context_parts.append(f"IP-adress: {escape(user_ip)}")

    context_str = "\n".join(context_parts) if context_parts else "Okänd kontext"

    send_critical_event_email(
        event_type="error",
        title="🔴 Kritiskt HTTP-fel (500)",
        description=f"En intern serverfel uppstod.\n\n{context_str}\nTidsstämpel: {_get_timestamp()}",
        error_message=error_message,
    )


def send_critical_alert(event_type: str, details: str = "") -> None:
    """
    Send a critical alert email notification.

    This unified function replaces separate CRITICAL_ALERTS_EMAIL, ERROR_ALERTS_EMAIL,
    and other email configurations. Uses ADMIN_EMAIL for all notifications.

    Args:
        event_type: Type of critical event (startup, shutdown, crash, error, etc.)
        details: Additional details about the event
    """
    event_labels = {
        "startup": "Applikationen startade",
        "shutdown": "Applikationen stängdes av",
        "restart": "Applikationen startades om",
        "crash": "Applikationen kraschade",
        "error": "Kritiskt fel inträffade",
    }

    event_label = event_labels.get(event_type, event_type)

    send_unified_notification(
        notification_type=event_type,
        title=f"[KRITISK HÄNDELSE] {event_label}",
        description="En kritisk systemhändelse har inträffat.\n\nKontrollera loggar och driftstatus så snart som möjligt.",
        error_message=details if details else None,
        log_level=logging.CRITICAL,
    )
