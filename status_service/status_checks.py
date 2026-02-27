# Copyright (c) Liam Suorsa and Mika Suorsa
import logging
import os
import socket
import ssl
import time
from datetime import timedelta
from statistics import mean
from urllib import error, request
import psutil

START_TIME = time.monotonic()
LOGGER = logging.getLogger(__name__)

PRIMARY_SITE_HOST = "utbildningsintyg.se"
PRIMARY_SITE_HEALTH_URL = "https://utbildningsintyg.se/health"
PRIMARY_SITE_INTERNAL_HEALTH_URL = "http://app:80/health"


def get_uptime(now=None):
    current_time = now if now is not None else time.monotonic()
    seconds = max(0, current_time - START_TIME)
    return timedelta(seconds=int(seconds))


def get_cpu_procent():
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        return {
            "status": "OK",
            "details": f"{cpu_percent:.2f} %",
        }
    except Exception:
        LOGGER.warning("CPU-användning kunde inte läsas i den aktuella miljön.")
        return {"status": "Inte tillgänglig", "details": "Inte tillgänglig"}


def format_uptime(uptime):
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days} dagar")
    if hours:
        parts.append(f"{hours} timmar")
    if minutes:
        parts.append(f"{minutes} minuter")
    if not parts:
        parts.append(f"{seconds} sekunder")

    return ", ".join(parts)


def check_tcp(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        LOGGER.warning(
            "TCP-kontroll misslyckades för %s:%s med timeout %s.",
            host,
            port,
            timeout,
        )
        return False


def check_database_status():
    host = os.getenv("STATUS_DB_HOST")
    name = os.getenv("STATUS_DB_NAME")
    user = os.getenv("STATUS_DB_USER")
    password = os.getenv("STATUS_DB_PASSWORD")
    port = int(os.getenv("STATUS_DB_PORT", "5432"))

    if not all([host, name, user, password]):
        LOGGER.warning("Databaskontroll hoppades över eftersom variabler saknas.")
        return {"status": "Inte konfigurerad", "details": "Saknar inställningar"}

    try:
        import psycopg2

        connection = psycopg2.connect(
            host=host,
            dbname=name,
            user=user,
            password=password,
            port=port,
            connect_timeout=2,
        )
        connection.close()
        return {"status": "OK", "details": "Anslutning lyckades"}
    except Exception:
        LOGGER.error(
            "Databaskontroll misslyckades mot %s:%s/%s.",
            host,
            port,
            name,
        )
        return {"status": "Fel", "details": "Anslutning misslyckades"}


def _is_reachable_http_status(status_code):
    # Statussidan ska visa tjänsten som uppe när den svarar, även vid 4xx.
    return 100 <= status_code < 500


def _request_with_host_header(url, host_header=None):
    headers = {"User-Agent": "StatusCheck"}
    if host_header:
        headers["Host"] = host_header
    return request.Request(url, method="GET", headers=headers)


def check_ssl_status():
    context = ssl.create_default_context()
    # Kräv modern TLS-version för handskakning.
    if hasattr(ssl, "TLSVersion") and hasattr(context, "minimum_version"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        if hasattr(ssl, "OP_NO_TLSv1"):
            context.options |= ssl.OP_NO_TLSv1
        if hasattr(ssl, "OP_NO_TLSv1_1"):
            context.options |= ssl.OP_NO_TLSv1_1

    def _execute_ssl_request(url, host_header=None):
        req = _request_with_host_header(url, host_header=host_header)
        with request.urlopen(req, timeout=4, context=context) as response:
            return response.status

    try:
        status_code = _execute_ssl_request(PRIMARY_SITE_HEALTH_URL)
        if _is_reachable_http_status(status_code):
            return {"status": "OK", "details": f"TLS + HTTP {status_code}"}
        return {"status": "Fel", "details": f"TLS + HTTP {status_code}"}
    except error.HTTPError as exc:
        LOGGER.warning("SSL-kontroll fick HTTP-fel %s från %s.", exc.code, PRIMARY_SITE_HEALTH_URL)
        status = "OK" if _is_reachable_http_status(exc.code) else "Fel"
        return {"status": status, "details": f"TLS + HTTP {exc.code}"}
    except error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ConnectionRefusedError) or getattr(reason, "errno", None) == 111:
            LOGGER.warning("SSL-kontroll kunde inte ansluta till %s:443.", PRIMARY_SITE_HOST)
            try:
                fallback_status = _execute_ssl_request(
                    PRIMARY_SITE_INTERNAL_HEALTH_URL,
                    host_header=PRIMARY_SITE_HOST,
                )
                if _is_reachable_http_status(fallback_status):
                    return {
                        "status": "OK",
                        "details": f"TLS + HTTP {fallback_status} (intern kontroll)",
                    }
                return {
                    "status": "Fel",
                    "details": f"TLS + HTTP {fallback_status} (intern kontroll)",
                }
            except Exception as fallback_exc:
                LOGGER.warning(
                    "Intern SSL-kontroll misslyckades för %s: %s",
                    PRIMARY_SITE_INTERNAL_HEALTH_URL,
                    fallback_exc,
                )
            return {"status": "Fel", "details": "Anslutning nekades"}
        LOGGER.warning("SSL-kontroll misslyckades för %s: %s", PRIMARY_SITE_HEALTH_URL, reason)
        return {"status": "Fel", "details": "TLS/anslutning misslyckades"}
    except OSError:
        LOGGER.error("SSL-kontroll misslyckades mot %s:443.", PRIMARY_SITE_HOST)
        return {"status": "Fel", "details": "TLS-handshake misslyckades"}


def _resolve_proxy_target():
    host = "traefik"
    for env_var in ("STATUS_TRAEFIK_HOST", "STATUS_NGINX_HOST", "STATUS_PROXY_HOST"):
        value = os.getenv(env_var)
        if value:
            host = value
            break

    port_env_var = None
    raw_port = None
    for env_var in ("STATUS_TRAEFIK_PORT", "STATUS_NGINX_PORT", "STATUS_PROXY_PORT"):
        value = os.getenv(env_var)
        if value:
            raw_port = value
            port_env_var = env_var
            break
    if raw_port is None:
        raw_port = "80"
    try:
        port = int(raw_port)
    except ValueError:
        LOGGER.warning(
            "Ogiltigt portvärde för %s (%s). Använder standardport 80.",
            port_env_var or "STATUS_PROXY_PORT",
            raw_port,
        )
        port = 80
    return host, port


def check_traefik_status():
    host, port = _resolve_proxy_target()

    tcp_ok = check_tcp(host, port, timeout=2)
    return {
        "status": "OK" if tcp_ok else "Fel",
        "details": "TCP-svar" if tcp_ok else "Inget TCP-svar",
    }


def check_http_status(
    name,
    url,
    timeout=3,
    host_header=None,
    fallback_url=None,
    fallback_host_header=None,
):
    if not url:
        LOGGER.warning("HTTP-kontroll '%s' saknar URL.", name)
        return {"name": name, "status": "Inte konfigurerad", "details": "Saknar URL"}

    try:
        LOGGER.debug("HTTP-kontroll startar: %s %s", name, url)
        req = _request_with_host_header(url, host_header=host_header)
        start_time = time.monotonic()
        with request.urlopen(req, timeout=timeout) as response:
            status_code = response.status
        elapsed_ms = (time.monotonic() - start_time) * 1000
        LOGGER.debug(
            "HTTP-kontroll svar: %s %s status=%s tid_ms=%s",
            name,
            url,
            status_code,
            round(elapsed_ms),
        )
        if _is_reachable_http_status(status_code):
            return {
                "name": name,
                "status": "OK",
                "details": f"HTTP {status_code}",
                "response_time_ms": round(elapsed_ms),
            }
        LOGGER.warning(
            "HTTP-kontroll '%s' fick serverfel %s för %s.",
            name,
            status_code,
            url,
        )
        return {
            "name": name,
            "status": "Fel",
            "details": f"HTTP {status_code}",
            "response_time_ms": round(elapsed_ms),
        }
    except error.HTTPError as exc:
        LOGGER.warning(
            "HTTP-kontroll '%s' fick HTTP-fel %s för %s.",
            name,
            exc.code,
            url,
        )
        status = "Nåbar" if _is_reachable_http_status(exc.code) else "Fel"
        return {"name": name, "status": status, "details": f"HTTP {exc.code}"}
    except error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ConnectionRefusedError) or getattr(reason, "errno", None) == 111:
            LOGGER.warning(
                "HTTP-kontroll '%s' kunde inte ansluta till %s.",
                name,
                url,
            )
            if fallback_url:
                return check_http_status(
                    name,
                    fallback_url,
                    timeout=timeout,
                    host_header=fallback_host_header,
                )
            return {"name": name, "status": "Fel", "details": "Anslutning nekades"}
        if isinstance(reason, TimeoutError):
            LOGGER.warning(
                "HTTP-kontroll '%s' nådde timeout för %s.",
                name,
                url,
            )
            return {"name": name, "status": "Fel", "details": "Timeout"}
        LOGGER.warning("HTTP-kontroll '%s' misslyckades för %s: %s", name, url, reason)
        return {"name": name, "status": "Fel", "details": "Nätverksfel"}
    except TimeoutError:
        LOGGER.warning(
            "HTTP-kontroll '%s' nådde timeout för %s.",
            name,
            url,
        )
        return {"name": name, "status": "Fel", "details": "Timeout"}
    except Exception:
        LOGGER.error("HTTP-kontroll '%s' misslyckades för %s.", name, url)
        return {"name": name, "status": "Fel", "details": "Okänt fel"}


def get_http_check_targets():
    return [
        {
            "name": "Huvudsidan",
            "url": PRIMARY_SITE_HEALTH_URL,
            "fallback_url": PRIMARY_SITE_INTERNAL_HEALTH_URL,
            "fallback_host_header": PRIMARY_SITE_HOST,
        }
    ]


def get_country_availability():
    raw_countries = os.getenv("STATUS_COUNTRY_AVAILABILITY", "")
    countries = []
    if not raw_countries:
        LOGGER.info("Inga landstatusar angivna för status-sidan.")
        return countries

    for entry in raw_countries.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "=" in entry:
            name, status = entry.split("=", 1)
        elif ":" in entry:
            name, status = entry.split(":", 1)
        else:
            LOGGER.warning("Ogiltig landstatus-entry: %s", entry)
            continue
        countries.append(
            {
                "name": name.strip(),
                "status": status.strip() or "Okänd",
            }
        )
    return countries


def get_load_average():
    try:
        load1, load5, load15 = os.getloadavg()
        return {
            "status": "OK",
            "details": f"{load1:.2f} / {load5:.2f} / {load15:.2f}",
        }
    except (AttributeError, OSError):
        LOGGER.warning("Systemlast kunde inte läsas i den aktuella miljön.")
        return {"status": "Inte tillgänglig", "details": "Inte tillgänglig"}


def summarize_latency(http_checks):
    response_times = [
        check["response_time_ms"]
        for check in http_checks
        if isinstance(check, dict) and "response_time_ms" in check
    ]

    if not response_times:
        return {"status": "Inte tillgänglig", "details": "Inga mätningar"}

    average_ms = mean(response_times)
    return {
        "status": "OK",
        "details": f"Medel {average_ms:.0f} ms, högst {max(response_times):.0f} ms",
    }


def build_latency_series(http_checks):
    series = []
    for check in http_checks:
        if not isinstance(check, dict):
            continue
        series.append(
            {
                "label": check.get("name", "Okänd kontroll"),
                "value": check.get("response_time_ms"),
                "status": check.get("status", "Okänd"),
                "details": check.get("details", ""),
            }
        )
    return series


def get_metadata(uptime):
    hostname = socket.gethostname()
    environment = os.getenv("STATUS_ENVIRONMENT", "Okänd")
    return {
        "hostname": hostname,
        "environment": environment,
        "uptime_seconds": int(uptime.total_seconds()),
    }


def get_ram_procent():
    try:
        ram = psutil.virtual_memory()
        ram_percent = ram.percent
        return {
            "status": "OK",
            "details": f"{ram_percent:.2f} %",
        }
    except Exception:
        LOGGER.warning("RAM-användning kunde inte läsas i den aktuella miljön.")
        return {"status": "Inte tillgänglig", "details": "Inte tillgänglig"}


def build_status(now=None):
    uptime = get_uptime(now=now)
    http_checks = [
        check_http_status(
            item["name"],
            item["url"],
            host_header=item.get("host_header"),
            fallback_url=item.get("fallback_url"),
            fallback_host_header=item.get("fallback_host_header"),
        )
        for item in get_http_check_targets()
    ]
    proxy_status = check_traefik_status()
    return {
        "uptime": format_uptime(uptime),
        "checks": {
            "ssl": check_ssl_status(),
            "database": check_database_status(),
            "traefik": proxy_status,
            "nginx": proxy_status,
        },
        "http_checks": http_checks,
        "countries": get_country_availability(),
        "performance": {
            "load": get_load_average(),
            "latency": summarize_latency(http_checks),
            "cpu": get_cpu_procent(),
            "ram": get_ram_procent(),
        },
        "latency_series": build_latency_series(http_checks),
        "metadata": get_metadata(uptime),
    }
