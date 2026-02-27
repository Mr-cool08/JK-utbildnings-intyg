#!/usr/bin/env python3
"""Övervakar huvudsida och Traefik och växlar Cloudflare DNS vid driftstopp."""

import json
import os
import sys
from dataclasses import dataclass
from typing import Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class HealthState:
    main_ok: bool
    traefik_ok: bool


def parse_hostname(url_or_host: str) -> str:
    """Returnera hostnamn från URL eller oförändrad host-sträng."""
    value = (url_or_host or "").strip()
    parsed = urlparse(value)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname
    return value


def should_use_fallback(state: HealthState) -> bool:
    """Failover aktiveras om huvudsidan eller Traefik är nere."""
    return not (state.main_ok and state.traefik_ok)


def determine_target(state: HealthState, primary_target: str, fallback_target: str) -> Tuple[str, str]:
    """Välj DNS-target och en enkel orsakssträng."""
    if should_use_fallback(state):
        return fallback_target, "failover"
    return primary_target, "primary"


def http_ok(url: str, timeout_seconds: float) -> bool:
    """Kontrollera att URL svarar med HTTP 2xx/3xx."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False

    request = Request(url=url, method="GET")
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            status_code = response.getcode()
            return status_code is not None and 200 <= status_code < 400
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        return False


def get_dns_record(api_token: str, zone_id: str, record_id: str) -> dict:
    request = Request(
        url=f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        },
        method="GET",
    )
    with urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
        if not payload.get("success"):
            raise RuntimeError(f"Cloudflare GET misslyckades: {payload}")
        return payload["result"]


def update_dns_record(api_token: str, zone_id: str, record_id: str, record: dict, target: str) -> None:
    record_type = record["type"]
    if record_type not in {"A", "AAAA", "CNAME"}:
        raise RuntimeError(f"DNS-recordtyp stöds inte för failover: {record_type}")

    payload = {
        "type": record_type,
        "name": record["name"],
        "content": target,
        "ttl": record.get("ttl", 1),
    }
    proxied = record.get("proxied")
    if proxied is not None:
        payload["proxied"] = proxied

    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url=f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        },
        method="PUT",
        data=body,
    )
    with urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
        if not payload.get("success"):
            raise RuntimeError(f"Cloudflare PUT misslyckades: {payload}")


def env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Miljövariabel saknas: {name}")
    return value


def main() -> int:
    main_url = env("FAILOVER_MAIN_URL")
    traefik_url = env("FAILOVER_TRAEFIK_URL")
    primary_target = parse_hostname(env("FAILOVER_PRIMARY_TARGET"))
    fallback_target = parse_hostname(env("FAILOVER_FALLBACK_TARGET"))
    timeout_seconds = float(os.getenv("FAILOVER_HTTP_TIMEOUT_SECONDS", "8"))

    api_token = env("CLOUDFLARE_API_TOKEN")
    zone_id = env("CLOUDFLARE_ZONE_ID")
    record_id = env("CLOUDFLARE_RECORD_ID")

    state = HealthState(
        main_ok=http_ok(main_url, timeout_seconds),
        traefik_ok=http_ok(traefik_url, timeout_seconds),
    )
    desired_target, reason = determine_target(state, primary_target, fallback_target)

    record = get_dns_record(api_token, zone_id, record_id)
    current_target = parse_hostname(record.get("content", ""))

    print(
        f"main_ok={state.main_ok} traefik_ok={state.traefik_ok} "
        f"läge={reason} nuvarande={current_target} önskat={desired_target}",
        flush=True,
    )

    if current_target == desired_target:
        print("Ingen DNS-ändring behövs.", flush=True)
        return 0

    update_dns_record(api_token, zone_id, record_id, record, desired_target)
    print(f"DNS uppdaterad till: {desired_target}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"Fel i failover-jobb: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)

# Copyright (c) Liam Suorsa and Mika Suorsa
