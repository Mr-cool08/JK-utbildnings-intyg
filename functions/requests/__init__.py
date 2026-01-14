from __future__ import annotations

import os
import time
from collections import deque

from flask import request

_PUBLIC_FORM_LIMIT = 5
_PUBLIC_FORM_WINDOW = 60 * 60  # 1 timme
_public_form_attempts: dict[str, deque[float]] = {}
_CLEANUP_INTERVAL = 10 * 60
_last_cleanup: float = 0.0


def _trusted_proxy_count() -> int:
    raw_value = os.getenv("TRUSTED_PROXY_COUNT")
    if raw_value is None or raw_value.strip() == "":
        return 1
    try:
        hops = int(raw_value)
    except ValueError:
        return 1
    if hops < 0:
        return 0
    return hops


def get_request_ip() -> str:
    """Hämta klientens IP-adress med hänsyn till X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded and _trusted_proxy_count() > 0:
        candidate = forwarded.split(",")[0].strip()
        if candidate:
            return candidate
    return request.remote_addr or "0.0.0.0"


def _cleanup_expired_attempts(now: float) -> None:
    """Rensa bort gamla IP-poster för att undvika oändlig tillväxt."""

    global _last_cleanup

    if now - _last_cleanup < _CLEANUP_INTERVAL and len(_public_form_attempts) < 1000:
        return

    stale_ips: list[str] = []

    for ip, bucket in list(_public_form_attempts.items()):
        while bucket and now - bucket[0] > _PUBLIC_FORM_WINDOW:
            bucket.popleft()
        if not bucket:
            stale_ips.append(ip)

    for ip in stale_ips:
        del _public_form_attempts[ip]

    _last_cleanup = now


def _trim_bucket(bucket: deque[float], now: float) -> None:
    """Avlägsna föråldrade försök från en specifik IP."""

    while bucket and now - bucket[0] > _PUBLIC_FORM_WINDOW:
        bucket.popleft()


def register_public_submission(ip: str) -> bool:
    """Registrera formulärförsök och rate-limita per IP."""
    now = time.time()

    _cleanup_expired_attempts(now)

    bucket = _public_form_attempts.setdefault(ip, deque())
    _trim_bucket(bucket, now)

    if len(bucket) >= _PUBLIC_FORM_LIMIT:
        return False
    bucket.append(now)
    return True


def as_bool(value: str | None) -> bool:
    """Tolka strängar som booleska värden."""
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "on", "ja", "yes"}
