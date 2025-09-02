#!/bin/sh
set -e

# Default ports
PORT=${PORT:-8080}
FLASK_PORT=${FLASK_PORT:-5000}

# Default certificate paths for optional TLS
CERT_PATH=${CLOUDFLARE_CERT_PATH:-/home/client_52_3/cert.pem}
KEY_PATH=${CLOUDFLARE_KEY_PATH:-/home/client_52_3/key.pem}

# Ensure runtime directory for nginx exists
mkdir -p /run/nginx

if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    echo "Starting Nginx with TLS using $CERT_PATH and $KEY_PATH"
    SSL_LISTEN="listen ${PORT} ssl;"
    TLS_CONFIG="ssl_certificate ${CERT_PATH};\n        ssl_certificate_key ${KEY_PATH};"
else
    echo "TLS certs not found, starting Nginx without TLS"
    SSL_LISTEN="listen ${PORT};"
    TLS_CONFIG=""
fi

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

