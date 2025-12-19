#!/bin/sh
set -euo pipefail

STOPPING=0
GUNICORN_PID=""
NGINX_PID=""

shutdown() {
  if [ "${STOPPING}" -eq 1 ]; then
    return
  fi
  STOPPING=1

  if [ -n "${NGINX_PID}" ]; then
    kill "${NGINX_PID}" 2>/dev/null || true
  fi
  if [ -n "${GUNICORN_PID}" ]; then
    kill "${GUNICORN_PID}" 2>/dev/null || true
  fi
}

trap 'shutdown' INT TERM EXIT

# Standardportar i containern (mappa utanför)
HTTPS_PORT="${HTTPS_PORT:-443}"
HTTP_PORT="${HTTP_PORT:-80}"
FLASK_PORT="${FLASK_PORT:-5000}"

# TLS-källor:
# 1) TLS_CERT_PATH/TLS_KEY_PATH -> läs filer (t.ex. Let's Encrypt)
# 2) TLS_CERT/TLS_KEY (PEM eller base64)
# 3) self-signed fallback
CERT_DIR=/etc/nginx/certs
CERT_PATH="${CERT_DIR}/server.crt"
KEY_PATH="${CERT_DIR}/server.key"
mkdir -p /run/nginx "$CERT_DIR"

write_tls_from_env() {
  # Skriv från TLS_CERT/TLS_KEY (PEM eller base64)
  if [ -n "${TLS_CERT:-}" ] && [ -n "${TLS_KEY:-}" ]; then
    if echo "$TLS_CERT" | grep -q "BEGIN CERTIFICATE"; then
      # Tillåt både faktiska radbrytningar och \n-escape-sekvenser i .env-filen
      printf '%b' "$TLS_CERT" > "$CERT_PATH"
    else
      echo "$TLS_CERT" | base64 -d > "$CERT_PATH"
    fi
    if echo "$TLS_KEY" | grep -q "BEGIN "; then
      printf '%b' "$TLS_KEY" > "$KEY_PATH"
    else
      echo "$TLS_KEY" | base64 -d > "$KEY_PATH"
    fi
    chmod 600 "$KEY_PATH"
    return 0
  fi
  return 1
}

if [ -n "${TLS_CERT_PATH:-}" ] && [ -n "${TLS_KEY_PATH:-}" ] && [ -f "$TLS_CERT_PATH" ] && [ -f "$TLS_KEY_PATH" ]; then
  CERT_PATH="$TLS_CERT_PATH"
  KEY_PATH="$TLS_KEY_PATH"
elif ! write_tls_from_env; then
  echo "Generating self-signed TLS certificate"
  CERT_PATH="${CERT_DIR}/selfsigned.crt"
  KEY_PATH="${CERT_DIR}/selfsigned.key"
  openssl req -x509 -nodes -days 365 \
    -subj "/CN=localhost" \
    -newkey rsa:2048 -keyout "$KEY_PATH" -out "$CERT_PATH"
  chmod 600 "$KEY_PATH"
fi

# Nginx konfig – säkerhetsheaders, HSTS, rate limit, blockera kända probningar
cat > /etc/nginx/nginx.conf <<'NGINX'
worker_processes  1;
events { worker_connections 1024; }
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile on;
    keepalive_timeout  65;
    server_tokens off;
    client_max_body_size 32m;

    # Rate limiting: 10 req/s burst 20
    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }

    # Lita på Cloudflare-headern för klientens IP-adress när proxy används
    real_ip_header CF-Connecting-IP;
    set_real_ip_from 0.0.0.0/0;
    set_real_ip_from ::/0;

    server {
        listen       __HTTP__;
        listen       __HTTPS__ ssl http2;
        server_name  _;

        ssl_certificate     __CERT__;
        ssl_certificate_key __KEY__;

        # TLS-inställningar (gäller ej self-signed OCSP)
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;

        # Säkerhetsheaders
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header Content-Security-Policy "default-src 'self'" always;

        # Enkla block för skräpvägar (return 444 = tyst drop)
        location ~* ^/(wp-admin|wordpress|xmlrpc\.php|vendor/|\.git|\.env|actuator|owa/|Autodiscover|console/|_ignition|geoserver|phpunit|solr|webui|containers/json) {
            return 444;
        }

        # Rate limit på allt
        limit_req zone=perip burst=20 nodelay;

        # Cache för statiskt
        location /static/ {
            alias /app/static/;
            access_log off;
            expires 7d;
        }

        # Proxy till Gunicorn
        location / {
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_read_timeout 60s;
            proxy_pass http://127.0.0.1:__FLASK__;
        }
    }
}
NGINX

# Sätt in portar & certs i templatet
sed -i \
  -e "s#__HTTP__#${HTTP_PORT}#g" \
  -e "s#__HTTPS__#${HTTPS_PORT}#g" \
  -e "s#__FLASK__#${FLASK_PORT}#g" \
  -e "s#__CERT__#${CERT_PATH}#g" \
  -e "s#__KEY__#${KEY_PATH}#g" \
  /etc/nginx/nginx.conf

# Validate external PostgreSQL configuration or enable local SQLite fallback.
if [ -z "${DATABASE_URL:-}" ]; then
  enable_local_db="$(printf '%s' "${ENABLE_LOCAL_TEST_DB:-false}" | tr '[:upper:]' '[:lower:]')"

  case "${enable_local_db}" in
    1|true|on|yes|ja|sant)
      local_db_path="${LOCAL_TEST_DB_PATH:-instance/test.db}"
      if [ "${local_db_path}" = ":memory:" ]; then
        export DATABASE_URL="sqlite:///:memory:"
        echo "Using in-memory SQLite database for local tests"
      else
        if [ "${local_db_path#/}" = "${local_db_path}" ]; then
          local_db_path="/app/${local_db_path}"
        fi
        mkdir -p "$(dirname "${local_db_path}")"
        export DATABASE_URL="sqlite:///${local_db_path}"
        echo "Using local SQLite database for tests at ${local_db_path}"
      fi
      ;;
    *)
      if [ -z "${POSTGRES_HOST:-}" ]; then
        echo "Set DATABASE_URL, enable ENABLE_LOCAL_TEST_DB or configure POSTGRES_HOST with credentials" >&2
        exit 1
      fi

      if [ -z "${POSTGRES_USER:-}" ]; then
        echo "POSTGRES_USER must be set when POSTGRES_HOST is configured" >&2
        exit 1
      fi

      if [ -z "${POSTGRES_DB:-}" ]; then
        echo "POSTGRES_DB must be set when POSTGRES_HOST is configured" >&2
        exit 1
      fi

      POSTGRES_PORT="${POSTGRES_PORT:-5432}"

      encoded_user="$(python -c "import os, urllib.parse; print(urllib.parse.quote_plus(os.environ['POSTGRES_USER']))")"
      encoded_password="$(python -c "import os, urllib.parse; print(urllib.parse.quote_plus(os.environ.get('POSTGRES_PASSWORD', '')) if 'POSTGRES_PASSWORD' in os.environ else '')")"
      encoded_db="$(python -c "import os, urllib.parse; print(urllib.parse.quote_plus(os.environ['POSTGRES_DB']))")"

      if [ -n "${POSTGRES_PASSWORD:-}" ]; then
        credentials="${encoded_user}:${encoded_password}"
      else
        credentials="${encoded_user}"
      fi

      if [ -n "${POSTGRES_PORT}" ]; then
        port_segment=":${POSTGRES_PORT}"
      else
        port_segment=""
      fi

      export DATABASE_URL="postgresql+psycopg://${credentials}@${POSTGRES_HOST}${port_segment}/${encoded_db}"
      echo "Using external PostgreSQL server at ${POSTGRES_HOST}${port_segment}"
      ;;
  esac
fi

# Starta Gunicorn (kör som app:app)
# Justera workers/threads efter CPU
WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}"
THREADS="${THREADS:-8}"

# Kontrollera att wsgi:app finns (ändra modul om din heter något annat)
GUNICORN_CMD="gunicorn --bind 127.0.0.1:${FLASK_PORT} \
    --workers ${WEB_CONCURRENCY} --threads ${THREADS} \
    --access-logfile - --error-logfile - \
    --timeout 60 \
    --user app --group app \
    --preload \
    wsgi:app"

echo "Starting Gunicorn: $GUNICORN_CMD"
sh -c "$GUNICORN_CMD" &
GUNICORN_PID=$!

echo "Starting Nginx"
nginx -g 'daemon off;' &
NGINX_PID=$!

set +e
wait "${NGINX_PID}"
NGINX_STATUS=$?
set -e

shutdown

if [ -n "${GUNICORN_PID}" ]; then
  wait "${GUNICORN_PID}" 2>/dev/null || true
fi
exit "${NGINX_STATUS}"
