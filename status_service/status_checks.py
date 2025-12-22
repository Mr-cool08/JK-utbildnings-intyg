import os
import socket
import ssl
import time
from datetime import timedelta

START_TIME = time.monotonic()


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
        return False


def check_database_status():
    host = os.getenv("STATUS_DB_HOST")
    name = os.getenv("STATUS_DB_NAME")
    user = os.getenv("STATUS_DB_USER")
    password = os.getenv("STATUS_DB_PASSWORD")
    port = int(os.getenv("STATUS_DB_PORT", "5432"))

    if not all([host, name, user, password]):
        return "Inte konfigurerad"

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
        return "OK"
    except Exception:
        return "Fel"


def check_ssl_status():
    host = os.getenv("STATUS_SSL_HOST", "utbildningsintyg.se")
    port = int(os.getenv("STATUS_SSL_PORT", "443"))

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return "OK"
    except OSError:
        return "Fel"


def check_nginx_status():
    host = os.getenv("STATUS_NGINX_HOST", "nginx")
    port = int(os.getenv("STATUS_NGINX_PORT", "80"))

    return "OK" if check_tcp(host, port, timeout=2) else "Fel"


def build_status(now=None):
    uptime = get_uptime(now=now)
    return {
        "uptime": format_uptime(uptime),
        "ssl": check_ssl_status(),
        "database": check_database_status(),
        "nginx": check_nginx_status(),
    }
