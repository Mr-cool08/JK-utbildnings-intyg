from __future__ import annotations

from functions.notifications.critical_events import send_critical_event_email
from functions.notifications.error_notifications import EmailErrorHandler

__all__ = ["EmailErrorHandler", "send_critical_event_email"]
