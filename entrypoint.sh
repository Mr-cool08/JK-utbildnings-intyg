#!/bin/sh
set -euo pipefail

STOPPING=0
POSTGRES_PID=""
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
  if [ -n "${POSTGRES_PID}" ]; then
    kill "${POSTGRES_PID}" 2>/dev/null || true
  fi
}

trap 'shutdown' INT TERM EXIT

BUNDLED_POSTGRES="${BUNDLED_POSTGRES:-auto}"

start_bundled_postgres() {
  POSTGRES_DATA_DIR="${POSTGRES_DATA_DIR:-/var/lib/postgresql/data}"
  POSTGRES_USER="${POSTGRES_USER:-appuser}"
  POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-change_me}"
  POSTGRES_DB="${POSTGRES_DB:-appdb}"
  POSTGRES_PORT="${POSTGRES_PORT:-5432}"

  mkdir -p "${POSTGRES_DATA_DIR}"
  chown -R postgres:postgres "${POSTGRES_DATA_DIR}"

  if [ ! -s "${POSTGRES_DATA_DIR}/PG_VERSION" ]; then
    echo "Initializing bundled PostgreSQL data directory at ${POSTGRES_DATA_DIR}"
    PASSFILE=$(mktemp)
    printf '%s\n' "${POSTGRES_PASSWORD}" > "${PASSFILE}"
    # Make the password file readable by the postgres user (mktemp creates it for root).
    chown postgres:postgres "${PASSFILE}"
    chmod 600 "${PASSFILE}"
    su-exec postgres:postgres sh -c "initdb -D \"${POSTGRES_DATA_DIR}\" -U \"${POSTGRES_USER}\" --auth=scram-sha-256 --pwfile=\"${PASSFILE}\""
    rm -f "${PASSFILE}"
  else
    echo "Reusing existing bundled PostgreSQL data directory"
  fi

  echo "Starting bundled PostgreSQL"
  su-exec postgres:postgres postgres \
    -D "${POSTGRES_DATA_DIR}" \
    -c listen_addresses=127.0.0.1 \
    -c "port=${POSTGRES_PORT}" &
  POSTGRES_PID=$!

  export DATABASE_URL="postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}"

  echo "Waiting for PostgreSQL to accept connections"
  ready=0
  attempt=0
  while [ "${attempt}" -lt 30 ]; do
    if PGPASSWORD="${POSTGRES_PASSWORD}" su-exec postgres:postgres pg_isready \
      -h 127.0.0.1 -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" >/dev/null 2>&1; then
      ready=1
      break
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  if [ "${ready}" -ne 1 ]; then
    echo "PostgreSQL did not become ready in time" >&2
    return 1
  fi

  if ! PGPASSWORD="${POSTGRES_PASSWORD}" su-exec postgres:postgres psql \
    -h 127.0.0.1 -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" \
    -tAc "SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB}'" \
    | grep -q 1; then
    echo "Creating database ${POSTGRES_DB}"
    PGPASSWORD="${POSTGRES_PASSWORD}" su-exec postgres:postgres createdb \
      -h 127.0.0.1 -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" "${POSTGRES_DB}"
  fi
}

# Standardportar i containern (mappa utanför)
HTTPS_PORT="${HTTPS_PORT:-8443}"
HTTP_PORT="${HTTP_PORT:-8080}"
FLASK_PORT="${FLASK_PORT:-5000}"

# TLS källor:
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
      printf '%s' "$TLS_CERT" > "$CERT_PATH"
    else
      echo "$TLS_CERT" | base64 -d > "$CERT_PATH"
    fi
    if echo "$TLS_KEY" | grep -q "BEGIN "; then
      printf '%s' "$TLS_KEY" > "$KEY_PATH"
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

    server {
        listen       __HTTP__;
        listen       __HTTPS__ ssl http2;
        server_name  _;

        ssl_certificate     __CERT__;
        ssl_certificate_key __KEY__;

        # TLS inställningar (gäller ej self-signed OCSP)
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

# Starta Postgres om vi inte har en extern anslutning
if [ "${BUNDLED_POSTGRES}" != "off" ]; then
  if [ "${BUNDLED_POSTGRES}" = "always" ] || [ -z "${DATABASE_URL:-}" ]; then
    echo "Bundled PostgreSQL startup enabled (mode=${BUNDLED_POSTGRES})"
    if ! start_bundled_postgres; then
      echo "Failed to start bundled PostgreSQL" >&2
      exit 1
    fi
  else
    echo "DATABASE_URL provided; skipping bundled PostgreSQL startup"
  fi
else
  echo "Bundled PostgreSQL disabled via BUNDLED_POSTGRES=off"
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
if [ -n "${POSTGRES_PID}" ]; then
  wait "${POSTGRES_PID}" 2>/dev/null || true
fi

exit "${NGINX_STATUS}"
