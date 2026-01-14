from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from email.utils import format_datetime, make_msgid
from html import escape
from threading import Thread
from typing import List, Tuple

from functions.emails import service as email_service
from functions.logging import collect_log_attachments


class EmailErrorHandler(logging.Handler):
    """Logging handler that emails ERROR-level (non-critical) records to configured recipients.

    It sends only records with level ERROR (>= ERROR and < CRITICAL) to avoid duplicating
    the existing critical-event notifications which handle CRITICAL/exceptional cases.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # Only handle ERROR but not CRITICAL (to avoid duplication)
            if record.levelno < logging.ERROR or record.levelno >= logging.CRITICAL:
                return
            if getattr(record, "_email_error_handler_sent", False):
                return
            record._email_error_handler_sent = True

            recipients = os.getenv("ERROR_ALERTS_EMAIL", "")
            if not recipients:
                return

            recipient_list = [e.strip() for e in recipients.split(",") if e.strip()]
            if not recipient_list:
                return

            subject = f"[FEL] Applikationsfel: {record.levelname}"

            timestamp = datetime.now(timezone.utc)
            ts = format_datetime(timestamp)

            message = self.format(record)

            body = (
                f"<html><body style='font-family: Arial, sans-serif;'>"
                f"<h3>Applikationsfel (nivå: {escape(record.levelname)})</h3>"
                f"<p><strong>Tid:</strong> {ts}</p>"
                f"<p><strong>Loggmeddelande:</strong></p>"
                f"<pre style='background:#f5f5f5;padding:10px;border-radius:4px;'>{escape(message)}</pre>"
                f"</body></html>"
            )

            # Send attachments in background thread
            thread = Thread(
                target=self._send_with_attachments,
                args=(recipient_list, subject, body),
                daemon=True,
            )
            thread.start()

        except Exception:
            # Never raise from a logging handler
            pass

    def _send_with_attachments(self, recipients: List[str], subject: str, body: str) -> None:
        attachments: List[Tuple[str, bytes]] = collect_log_attachments()

        for recipient in recipients:
            try:
                if attachments:
                    email_service.send_email(recipient, subject, body, attachments=attachments)
                else:
                    email_service.send_email(recipient, subject, body)
            except Exception:
                # Swallow to avoid logging loops
                continue
