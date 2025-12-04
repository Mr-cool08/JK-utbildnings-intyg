from __future__ import annotations

import time
from collections import deque

from flask import request

_PUBLIC_FORM_LIMIT = 5
_PUBLIC_FORM_WINDOW = 60 * 60  # 1 timme
_public_form_attempts: dict[str, deque[float]] = {}


def get_request_ip() -> str:
    """Hämta klientens IP-adress med hänsyn till X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def register_public_submission(ip: str) -> bool:
    """Registrera formulärförsök och rate-limita per IP."""
    now = time.time()
    bucket = _public_form_attempts.setdefault(ip, deque())
    while bucket and now - bucket[0] > _PUBLIC_FORM_WINDOW:
        bucket.popleft()
    if len(bucket) >= _PUBLIC_FORM_LIMIT:
        return False
    bucket.append(now)
    return True


def as_bool(value: str | None) -> bool:
    """Tolka strängar som booleska värden."""
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "on", "ja", "yes"}
