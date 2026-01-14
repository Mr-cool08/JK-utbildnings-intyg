# Service for sending email notifications about critical application events.

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from html import escape
from threading import Thread
from typing import Optional

from config_loader import load_environment
from functions.emails import service as email_service
from functions.logging import collect_log_attachments, configure_module_logger


logger = configure_module_logger(__name__)
logger.setLevel(logging.INFO)

load_environment()


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
    return os.getenv("APP_NAME", "JK Utbildningsintyg")


def _get_timestamp() -> str:
    """Get current timestamp in Swedish locale."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%d %H:%M:%S UTC")


def _send_email_async(
    recipients: list[str], subject: str, html_body: str
) -> None:
    """Send email asynchronously to multiple recipients to avoid blocking the application."""
    attachments: list[tuple[str, bytes]] = collect_log_attachments()

    for recipient in recipients:
        try:
            if attachments:
                email_service.send_email(recipient, subject, html_body, attachments=attachments)
            else:
                email_service.send_email(recipient, subject, html_body)
        except Exception as e:
            logger.error("Misslyckades att skicka kritisk event-email till %s: %s", recipient, str(e))


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
    try:
        admin_emails = _get_admin_emails()
        app_name = _get_app_name()
        timestamp = _get_timestamp()
        
        safe_description = escape(description)
        safe_error = escape(error_message) if error_message else None
        
        # Determine event icon and color
        event_colors = {
            "startup": "#28a745",      # Green
            "shutdown": "#ffc107",     # Amber
            "crash": "#dc3545",        # Red
            "restart": "#17a2b8",      # Cyan
            "error": "#e74c3c",        # Red-orange
            "exception": "#dc3545",    # Red
            "warning": "#ff9800",      # Orange
        }
        color = event_colors.get(event_type.lower(), "#6c757d")  # Gray default
        
        html_body = f"""
        <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.6; background-color: #f5f5f5; padding: 20px;'>
                <div style='max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                    <div style='border-left: 4px solid {color}; padding-left: 15px; margin-bottom: 20px;'>
                        <h2 style='margin: 0; color: {color};'>⚠️ Kritisk Event: {escape(title)}</h2>
                        <p style='margin: 5px 0; color: #666; font-size: 12px;'>Tidsstämpel: {timestamp}</p>
                    </div>
                    
                    <div style='background-color: #f9f9f9; padding: 15px; border-radius: 4px; margin-bottom: 15px;'>
                        <h3 style='margin-top: 0; color: #333;'>Applikation: {escape(app_name)}</h3>
                        <h3 style='margin-top: 0; color: #333;'>Händelsetyp: {escape(event_type)}</h3>
                        <p style='margin: 0; color: #333;'><strong>Beskrivning:</strong></p>
                        <p style='margin: 10px 0; color: #555; white-space: pre-wrap; word-wrap: break-word;'>{safe_description}</p>
        """
        
        if safe_error:
            html_body += f"""
                        <p style='margin: 10px 0 0 0; color: #333;'><strong>Felmeddelande:</strong></p>
                        <p style='margin: 10px 0; color: #d32f2f; white-space: pre-wrap; word-wrap: break-word; background-color: #ffebee; padding: 10px; border-radius: 4px;'>{safe_error}</p>
            """
        
        html_body += """
                    </div>
                    
                    <div style='background-color: #e3f2fd; padding: 15px; border-radius: 4px; margin-bottom: 15px;'>
                        <p style='margin: 0; color: #1976d2;'>
                            <strong>Åtgärd:</strong> Kontrollera applikationens status och loggfiler omedelbar.
                        </p>
                    </div>
                    
                    <hr style='border: none; border-top: 1px solid #ddd; margin: 20px 0;'>
                    <p style='margin: 0; color: #999; font-size: 12px; text-align: center;'>
                        Detta är ett automatiskt genererat meddelande från JK Utbildningsintyg. Svara inte på detta e-postmeddelande.
                    </p>
                </div>
            </body>
        </html>
        """
        
        # Send email asynchronously to avoid blocking
        thread = Thread(
            target=_send_email_async,
            args=(admin_emails, title, html_body),
            daemon=True
        )
        thread.start()
        
        logger.info(
            "Kritisk event-email skickad för %s: %s till %d mottagare",
            event_type,
            title,
            len(admin_emails)
        )
        
    except RuntimeError as e:
        logger.error("Kan inte skicka kritisk event-email: %s", str(e))
    except Exception as e:
        logger.exception("Oväntat fel vid sändning av kritisk event-email: %s", str(e))


def send_startup_notification(hostname: str = "Unknown") -> None:
    """Send notification that the application has started."""
    send_critical_event_email(
        event_type="startup",
        title="🟢 Applikation startad",
        description=f"Applikationen har startats framgångsrikt.\n\nVärd: {escape(hostname)}\nTidsstämpel: {_get_timestamp()}",
    )


def send_shutdown_notification(reason: str = "Planerad nedstängning") -> None:
    """Send notification that the application is shutting down."""
    send_critical_event_email(
        event_type="shutdown",
        title="🟡 Applikation stängs ner",
        description=f"Applikationen stängs ner.\n\nAnledning: {escape(reason)}\nTidsstämpel: {_get_timestamp()}",
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
