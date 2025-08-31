#!/bin/sh
set -e

if [ -n "$CLOUDFLARE_CERT_PATH" ] && [ -n "$CLOUDFLARE_KEY_PATH" ]; then
    exec gunicorn app:app --workers=3 --bind=0.0.0.0:$PORT --access-logfile=- --error-logfile=- --log-level=debug --capture-output --certfile="$CLOUDFLARE_CERT_PATH" --keyfile="$CLOUDFLARE_KEY_PATH"
else
    exec gunicorn app:app --workers=3 --bind=0.0.0.0:$PORT --access-logfile=- --error-logfile=- --log-level=debug --capture-output
fi
