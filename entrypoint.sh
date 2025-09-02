#!/bin/sh
set -e

# Default workers om inget annat anges
WORKERS=${WORKERS:-3}

# Look for TLS assets in the ubuntu user's home directory by default. This
# matches the location provided in the deployment environment where
# ``cert.pem`` and ``key.pem`` are copied directly under
# ``/home/client_52_3``.
CERT_PATH=${CLOUDFLARE_CERT_PATH:-/home/client_52_3/cert.pem}
KEY_PATH=${CLOUDFLARE_KEY_PATH:-/home/client_52_3/key.pem}

if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    echo "Starting Gunicorn with TLS using $CERT_PATH and $KEY_PATH"
    exec gunicorn app:app \
        --workers="$WORKERS" \
        --bind=0.0.0.0:$PORT \
        --access-logfile=- \
        --error-logfile=- \
        --log-level=debug \
        --capture-output \
        --certfile="$CERT_PATH" \
        --keyfile="$KEY_PATH"
else
    echo "TLS certs not found, starting Gunicorn without TLS"
    exec gunicorn app:app \
        --workers="$WORKERS" \
        --bind=0.0.0.0:$PORT \
        --access-logfile=- \
        --error-logfile=- \
        --log-level=debug \
        --capture-output
fi
