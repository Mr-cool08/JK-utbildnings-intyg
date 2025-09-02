#!/bin/sh
set -e

# Default ports
PORT=${PORT:-8080}
FLASK_PORT=${FLASK_PORT:-5000}

# Default certificate paths
CERT_PATH=${TLS_CERT_PATH:-/etc/nginx/certs/server.crt}
KEY_PATH=${TLS_KEY_PATH:-/etc/nginx/certs/server.key}

# Ensure runtime directories exist
mkdir -p /run/nginx /etc/nginx/certs

if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "Generating self-signed TLS certificate"
    CERT_PATH=/etc/nginx/certs/selfsigned.crt
    KEY_PATH=/etc/nginx/certs/selfsigned.key
    openssl req -x509 -nodes -days 365 \
        -subj "/CN=localhost" \
        -newkey rsa:2048 -keyout "$KEY_PATH" -out "$CERT_PATH"
fi

SSL_LISTEN="listen ${PORT} ssl;"
TLS_CONFIG="ssl_certificate ${CERT_PATH};\n        ssl_certificate_key ${KEY_PATH};"

# Generate nginx configuration
cat > /etc/nginx/nginx.conf <<EOF
worker_processes  1;
events { worker_connections 1024; }

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    server {
        ${SSL_LISTEN}
        server_name  _;

        ${TLS_CONFIG}

        location /static {
            alias /app/static;
        }

        location / {
            proxy_pass http://127.0.0.1:${FLASK_PORT};
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
}
EOF

# Start Flask application on the internal port
PORT=$FLASK_PORT python wsgi.py &

# Start nginx in the foreground
exec nginx -g 'daemon off;'

