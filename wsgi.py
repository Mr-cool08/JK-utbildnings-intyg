import os
from app import app as application



# Default locations for TLS certificate and key files. The files are placed
# directly in the ubuntu user's home directory rather than a nested
# "certs" folder so the application can pick them up automatically when no
# explicit environment variables are provided.
DEFAULT_CERT_PATH = "/home/client_52_3/cert.pem"
DEFAULT_KEY_PATH = "/home/client_52_3/key.pem"



def get_ssl_context():
    """Return an SSL context tuple if Cloudflare cert paths are set.

    The application can run with a Cloudflare Origin Certificate by
    specifying ``CLOUDFLARE_CERT_PATH`` and ``CLOUDFLARE_KEY_PATH``
    environment variables. When both values are present the paths are
    returned as a tuple suitable for ``Flask.run``'s ``ssl_context``
    parameter. Otherwise ``None`` is returned so the app starts without
    TLS.
    """

    cert_path = os.getenv("CLOUDFLARE_CERT_PATH", DEFAULT_CERT_PATH)
    key_path = os.getenv("CLOUDFLARE_KEY_PATH", DEFAULT_KEY_PATH)
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
