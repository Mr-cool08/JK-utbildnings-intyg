#!/bin/sh
set -e

# Default workers om inget annat anges
WORKERS=${WORKERS:-3}

CERT_PATH=${CLOUDFLARE_CERT_PATH:-/home/client_52_3/certs/cert.pem}
KEY_PATH=${CLOUDFLARE_KEY_PATH:-/home/client_52_3/certs/key.pem}

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
