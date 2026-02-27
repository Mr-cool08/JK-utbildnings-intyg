#!/usr/bin/env python3
"""Övervakar huvudsida och Traefik och växlar Cloudflare DNS vid driftstopp.

Viktigt:
- Om failover-target är en extern host (t.ex. onrender.com) och record är proxied=True kan Cloudflare ge:
  "Error 1000: DNS points to prohibited IP".
  Därför sätter vi proxied=False under failover (kan styras via env).
"""

import ipaddress
import json
import math
import os
import sys
from dataclasses import dataclass
from typing import Optional, Tuple
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


def parse_positive_timeout(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default

    try:
        parsed = float(raw)
    except (TypeError, ValueError):
        print(f"Varning: {name} måste vara ett positivt tal. Standardvärde {default} används.", flush=True)
        return default

    if not math.isfinite(parsed) or parsed <= 0:
        print(f"Varning: {name} måste vara större än 0. Standardvärde {default} används.", flush=True)
        return default
    return parsed


def parse_bool_env(name: str) -> Optional[bool]:
    """Returnerar True/False om env är satt, annars None."""
    raw = os.getenv(name)
    if raw is None:
        return None
    val = raw.strip().lower()
    if val in {"1", "true", "yes", "y", "on"}:
        return True
    if val in {"0", "false", "no", "n", "off"}:
        return False
    raise RuntimeError(f"Ogiltigt bool-värde för {name}: {raw!r} (använd true/false)")


def get_dns_record(api_token: str, zone_id: str, record_id: str, timeout_seconds: float) -> dict:
    request = Request(
        url=f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
        headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
        method="GET",
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))
        if not payload.get("success"):
            raise RuntimeError(f"Cloudflare GET misslyckades: {payload}")
        return payload["result"]


def _validate_content(record_type: str, target: str) -> None:
    """Validera att content matchar record-typen (för att slippa Cloudflare 400)."""
    if record_type == "A":
        try:
            ip = ipaddress.ip_address(target)
        except ValueError as exc:
            raise RuntimeError(f"A-record kräver IPv4-adress, fick: {target!r}") from exc
        if ip.version != 4:
            raise RuntimeError(f"A-record kräver IPv4-adress, fick IPv{ip.version}: {target!r}")
    elif record_type == "AAAA":
        try:
            ip = ipaddress.ip_address(target)
        except ValueError as exc:
            raise RuntimeError(f"AAAA-record kräver IPv6-adress, fick: {target!r}") from exc
        if ip.version != 6:
            raise RuntimeError(f"AAAA-record kräver IPv6-adress, fick IPv{ip.version}: {target!r}")
    elif record_type == "CNAME":
        # Hostnamn – vi accepterar även FQDN och “origin.example.se”
        if not target or " " in target:
            raise RuntimeError(f"CNAME-record kräver ett giltigt hostnamn, fick: {target!r}")
    else:
        raise RuntimeError(f"DNS-recordtyp stöds inte för failover: {record_type}")


def choose_proxied(
    record: dict,
    reason: str,
) -> Optional[bool]:
    """Bestäm proxied-värde för uppdateringen.

    - För failover (fallback): default False för CNAME (för att undvika CF Error 1000),
      men kan styras via FAILOVER_FALLBACK_PROXIED.
    - För primary: default recordens ursprungliga proxied,
      men kan styras via FAILOVER_PRIMARY_PROXIED.
    """
    record_type = record.get("type")
    current_proxied = record.get("proxied")

    if reason == "failover":
        forced = parse_bool_env("FAILOVER_FALLBACK_PROXIED")
        if forced is not None:
            return forced
        # Default: om CNAME -> False, annars behåll
        if record_type == "CNAME":
            return False
        return current_proxied

    # primary
    forced = parse_bool_env("FAILOVER_PRIMARY_PROXIED")
    if forced is not None:
        return forced
    return current_proxied


def update_dns_record(
    api_token: str,
    zone_id: str,
    record_id: str,
    record: dict,
    target: str,
    proxied: Optional[bool],
    timeout_seconds: float,
) -> None:
    record_type = record["type"]
    _validate_content(record_type, target)

    payload = {
        "type": record_type,
        "name": record["name"],
        "content": target,
        "ttl": record.get("ttl", 1),
    }
    if proxied is not None:
        payload["proxied"] = proxied

    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url=f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
        headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
        method="PUT",
        data=body,
    )

    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            resp_payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as e:
        # Försök läsa Cloudflares felbody så vi får bra fel i loggen
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        raise RuntimeError(f"Cloudflare PUT HTTP {e.code}: {body}") from e

    if not resp_payload.get("success"):
        raise RuntimeError(f"Cloudflare PUT misslyckades: {resp_payload}")


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
    timeout_seconds = parse_positive_timeout("FAILOVER_HTTP_TIMEOUT_SECONDS", 8.0)
    cloudflare_timeout_seconds = parse_positive_timeout("FAILOVER_CLOUDFLARE_TIMEOUT_SECONDS", 20.0)

    api_token = env("CLOUDFLARE_API_TOKEN")
    zone_id = env("CLOUDFLARE_ZONE_ID")
    record_id = env("CLOUDFLARE_RECORD_ID")

    state = HealthState(
        main_ok=http_ok(main_url, timeout_seconds),
        traefik_ok=http_ok(traefik_url, timeout_seconds),
    )
    desired_target, reason = determine_target(state, primary_target, fallback_target)

    record = get_dns_record(api_token, zone_id, record_id, cloudflare_timeout_seconds)
    current_target = parse_hostname(record.get("content", ""))
    current_proxied = record.get("proxied")

    desired_proxied = choose_proxied(record, reason)

    print(
        f"main_ok={state.main_ok} traefik_ok={state.traefik_ok} "
        f"läge={reason} nuvarande={current_target} önskat={desired_target} "
        f"proxied_nu={current_proxied} proxied_önskat={desired_proxied}",
        flush=True,
    )

    if current_target == desired_target and (desired_proxied is None or current_proxied == desired_proxied):
        print("Ingen DNS-ändring behövs.", flush=True)
        return 0

    update_dns_record(
        api_token,
        zone_id,
        record_id,
        record,
        desired_target,
        desired_proxied,
        cloudflare_timeout_seconds,
    )
    print(f"DNS uppdaterad till: {desired_target} (proxied={desired_proxied})", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"Fel i failover-jobb: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)

# Copyright (c) Liam Suorsa and Mika Suorsa