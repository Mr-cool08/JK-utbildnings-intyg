from __future__ import annotations

import hmac
import secrets
from typing import Any

from flask import request, session


CSRF_SESSION_KEY = "csrf_token"


def ensure_csrf_token() -> str:
    """Create or reuse a CSRF-token lagrad i sessionen."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def extract_csrf_token() -> str | None:
    """Extrahera CSRF-token från JSON, headers, formulär eller query-parametrar."""
    if request.is_json:
        payload: dict[str, Any] = request.get_json(silent=True) or {}
        token = payload.get("csrf_token")
        if token:
            return str(token)
    token = request.headers.get("X-CSRF-Token")
    if token:
        return token
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        form_token = request.form.get("csrf_token")
        if form_token:
            return form_token
    return request.args.get("csrf_token")


def validate_csrf_token() -> bool:
    """Validera att ett inkommande CSRF-token matchar sessionens token."""
    expected = session.get(CSRF_SESSION_KEY)
    candidate = extract_csrf_token()
    if not expected or not candidate:
        return False
    try:
        return hmac.compare_digest(str(candidate), str(expected))
    except Exception:
        return False
