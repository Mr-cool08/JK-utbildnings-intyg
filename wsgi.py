import os
from pathlib import Path
from app import app as application


# Default locations for TLS certificate and key files used by the Flask
# development server. They mirror the paths consumed by the nginx
# entrypoint so a single set of certificates can be shared if desired.
DEFAULT_CERT_PATH = "/etc/nginx/certs/server.crt"
DEFAULT_KEY_PATH = "/etc/nginx/certs/server.key"


def _write_pem(content: str, path: str) -> None:
    Path(path).write_text(content.replace("\\n", "\n"))


def get_ssl_context():
    """Return an SSL context tuple if TLS cert values are set.

    The application can run with TLS by specifying ``TLS_CERT`` and
    ``TLS_KEY`` environment variables containing PEM-formatted strings.
    When both values are present they are written to the default paths
    and returned as a tuple suitable for ``Flask.run``'s ``ssl_context``
    parameter. If the environment variables are absent but files already
    exist at the default paths those are used instead. Otherwise ``None``
    is returned so the app starts without TLS.
    """

    cert = os.getenv("TLS_CERT")
    key = os.getenv("TLS_KEY")
    if cert and key:
        _write_pem(cert, DEFAULT_CERT_PATH)
        _write_pem(key, DEFAULT_KEY_PATH)
        return DEFAULT_CERT_PATH, DEFAULT_KEY_PATH
    if os.path.isfile(DEFAULT_CERT_PATH) and os.path.isfile(DEFAULT_KEY_PATH):
        return DEFAULT_CERT_PATH, DEFAULT_KEY_PATH
    return None


debug = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "yes")


if __name__ == "__main__":
    # This allows running the app with `python wsgi.py`
    application.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 80)),
        debug=debug,
        ssl_context=get_ssl_context(),
    )
