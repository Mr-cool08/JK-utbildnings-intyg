# Copyright (c) Liam Suorsa
import os
from pathlib import Path
from app import app as application
from functions.requests import as_bool

# Expose ``app`` for servers expecting this name (e.g., gunicorn's ``wsgi:app``)
app = application


# Default locations for TLS certificate and key files used by the Flask
# development server. These can be populated via environment variables
# when TLS is needed for local development.
DEFAULT_CERT_PATH = "/etc/ssl/cloudflare/origin.crt"
DEFAULT_KEY_PATH = "/etc/ssl/cloudflare/origin.key"


def _write_pem(content: str, path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.replace("\\n", "\n"))


def get_ssl_context():
    """Return an SSL context tuple if TLS cert values are set.

    The application can run with TLS by specifying ``TLS_CERT`` and
    ``TLS_KEY`` environment variables containing PEM-formatted strings.
    When both values are present they are written to the default paths
    and returned as a tuple suitable for ``Flask.run``'s ``ssl_context``
    parameter. If ``ORIGIN_CERT_PATH`` and ``ORIGIN_KEY_PATH`` are set and point
    to existing files those are used directly. If the environment variables
    are absent but files already exist at the default paths those are used
    instead. Otherwise ``None`` is returned so the app starts without TLS.
    """

    cert_path = os.getenv("ORIGIN_CERT_PATH", DEFAULT_CERT_PATH)
    key_path = os.getenv("ORIGIN_KEY_PATH", DEFAULT_KEY_PATH)
    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        return cert_path, key_path

    cert = os.getenv("TLS_CERT")
    key = os.getenv("TLS_KEY")
    if cert and key:
        _write_pem(cert, cert_path)
        _write_pem(key, key_path)
        return cert_path, key_path
    return None


debug = as_bool(os.getenv("DEV_MODE"))


if __name__ == "__main__":
    # This allows running the app with `python wsgi.py`
    application.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 80)),
        debug=debug,
        ssl_context=get_ssl_context(),
    )
