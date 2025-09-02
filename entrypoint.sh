#!/bin/sh
set -e

# Default workers om inget annat anges
WORKERS=${WORKERS:-3}

if [ -f "$CLOUDFLARE_CERT_PATH" ] && [ -f "$CLOUDFLARE_KEY_PATH" ]; then
    echo "Starting Gunicorn with TLS using $CLOUDFLARE_CERT_PATH and $CLOUDFLARE_KEY_PATH"
    exec gunicorn app:app \
        --workers="$WORKERS" \
        --bind=0.0.0.0:$PORT \
        --access-logfile=- \
        --error-logfile=- \
        --log-level=debug \
        --capture-output \
        --certfile="$CLOUDFLARE_CERT_PATH" \
        --keyfile="$CLOUDFLARE_KEY_PATH"
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
