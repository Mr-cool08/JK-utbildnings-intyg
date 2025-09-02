import os
from app import app as application



# Default locations for TLS certificate and key files used by the Flask
# development server. They mirror the paths consumed by the nginx
# entrypoint so a single set of certificates can be shared if desired.
DEFAULT_CERT_PATH = "/etc/nginx/certs/server.crt"
DEFAULT_KEY_PATH = "/etc/nginx/certs/server.key"



def get_ssl_context():
    """Return an SSL context tuple if TLS cert paths are set.

    The application can run with TLS by specifying ``TLS_CERT_PATH`` and
    ``TLS_KEY_PATH`` environment variables. When both values are present the paths are
    returned as a tuple suitable for ``Flask.run``'s ``ssl_context``
    parameter. Otherwise ``None`` is returned so the app starts without
    TLS.
    """

    cert_path = os.getenv("TLS_CERT_PATH", DEFAULT_CERT_PATH)
    key_path = os.getenv("TLS_KEY_PATH", DEFAULT_KEY_PATH)
    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        return cert_path, key_path
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
