import logging
import os
import socket
import ssl
import time
from datetime import timedelta
from urllib import error, request

START_TIME = time.monotonic()
LOGGER = logging.getLogger(__name__)


def get_uptime(now=None):
    current_time = now if now is not None else time.monotonic()
    seconds = max(0, current_time - START_TIME)
    return timedelta(seconds=int(seconds))


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
        LOGGER.exception(
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
        LOGGER.exception(
            "Databaskontroll misslyckades mot %s:%s/%s.",
            host,
            port,
            name,
        )
        return {"status": "Fel", "details": "Anslutning misslyckades"}


def check_ssl_status():
    host = os.getenv("STATUS_SSL_HOST", "utbildningsintyg.se")
    port = int(os.getenv("STATUS_SSL_PORT", "443"))

    context = ssl.create_default_context()
    # Enforce modern TLS versions (TLS 1.2+) regardless of system defaults
    if hasattr(ssl, "TLSVersion") and hasattr(context, "minimum_version"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        # Fallback for older Python versions: disable TLS 1.0 and 1.1 if flags exist
        if hasattr(ssl, "OP_NO_TLSv1"):
            context.options |= ssl.OP_NO_TLSv1
        if hasattr(ssl, "OP_NO_TLSv1_1"):
            context.options |= ssl.OP_NO_TLSv1_1
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return {"status": "OK", "details": "TLS-handshake lyckades"}
    except ConnectionRefusedError:
        LOGGER.warning("SSL-kontroll kunde inte ansluta till %s:%s.", host, port)
        return {"status": "Fel", "details": "Anslutning nekades"}
    except OSError:
        LOGGER.exception("SSL-kontroll misslyckades mot %s:%s.", host, port)
        return {"status": "Fel", "details": "TLS-handshake misslyckades"}


def check_nginx_status():
    host = os.getenv("STATUS_NGINX_HOST", "nginx")
    port = int(os.getenv("STATUS_NGINX_PORT", "80"))

    tcp_ok = check_tcp(host, port, timeout=2)
    return {
        "status": "OK" if tcp_ok else "Fel",
        "details": "TCP-svar" if tcp_ok else "Inget TCP-svar",
    }


def check_http_status(name, url, timeout=3):
    if not url:
        LOGGER.warning("HTTP-kontroll '%s' saknar URL.", name)
        return {"name": name, "status": "Inte konfigurerad", "details": "Saknar URL"}

    try:
        req = request.Request(url, method="GET", headers={"User-Agent": "StatusCheck"})
        with request.urlopen(req, timeout=timeout) as response:
            status_code = response.status
        if 200 <= status_code < 400:
            return {"name": name, "status": "OK", "details": f"HTTP {status_code}"}
        LOGGER.warning(
            "HTTP-kontroll '%s' fick oväntad statuskod %s för %s.",
            name,
            status_code,
            url,
        )
        return {"name": name, "status": "Fel", "details": f"HTTP {status_code}"}
    except error.HTTPError as exc:
        LOGGER.exception(
            "HTTP-kontroll '%s' misslyckades med HTTP-fel %s för %s.",
            name,
            exc.code,
            url,
        )
        return {"name": name, "status": "Fel", "details": f"HTTP {exc.code}"}
    except error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ConnectionRefusedError) or getattr(
            reason, "errno", None
        ) == 111:
            LOGGER.warning(
                "HTTP-kontroll '%s' kunde inte ansluta till %s.",
                name,
                url,
            )
            return {"name": name, "status": "Fel", "details": "Anslutning nekades"}
        LOGGER.exception("HTTP-kontroll '%s' misslyckades för %s.", name, url)
        return {"name": name, "status": "Fel", "details": "Nätverksfel"}
    except Exception:
        LOGGER.exception("HTTP-kontroll '%s' misslyckades för %s.", name, url)
        return {"name": name, "status": "Fel", "details": "Okänt fel"}


def get_http_check_targets():
    targets = [
        {
            "name": "Huvudsidan",
            "url": os.getenv("STATUS_MAIN_URL", "http://app/health"),
        },
        {
            "name": "Demosidan",
            "url": os.getenv("STATUS_DEMO_URL", "http://app_demo/health"),
        },
    ]
    raw_extra = os.getenv("STATUS_EXTRA_HTTP_CHECKS", "")
    if not raw_extra:
        return targets
    for entry in raw_extra.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "|" not in entry:
            LOGGER.warning(
                "Extra HTTP-kontroll saknar formatet Namn|URL: %s",
                entry,
            )
            continue
        name, url = entry.split("|", 1)
        targets.append({"name": name.strip(), "url": url.strip()})
    return targets


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


def build_status(now=None):
    uptime = get_uptime(now=now)
    http_checks = [
        check_http_status(item["name"], item["url"])
        for item in get_http_check_targets()
    ]
    return {
        "uptime": format_uptime(uptime),
        "checks": {
            "ssl": check_ssl_status(),
            "database": check_database_status(),
            "nginx": check_nginx_status(),
        },
        "http_checks": http_checks,
        "countries": get_country_availability(),
    }
