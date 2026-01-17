#!/bin/sh
set -euo pipefail

STOPPING=0
GUNICORN_PID=""

shutdown() {
  if [ "${STOPPING}" -eq 1 ]; then
    return
  fi
  STOPPING=1

  if [ -n "${GUNICORN_PID}" ]; then
    kill "${GUNICORN_PID}" 2>/dev/null || true
  fi
}

trap 'shutdown' INT TERM EXIT

# Standardportar i containern (mappa utanför)
HTTP_PORT="${HTTP_PORT:-80}"
APP_PORT="${APP_PORT:-${HTTP_PORT}}"
LOG_DIR="${LOG_DIR:-/app/logs}"

# Se till att loggkatalogen finns och kan skrivas av app-användaren
mkdir -p "${LOG_DIR}"
chown -R app:app "${LOG_DIR}"

# Validate external PostgreSQL configuration or enable local SQLite fallback.
if [ -z "${DATABASE_URL:-}" ]; then
  enable_local_db="${DEV_MODE:-false}"
  enable_local_db="$(printf '%s' "${enable_local_db}" | tr '[:upper:]' '[:lower:]')"

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
        echo "Sätt DATABASE_URL, aktivera DEV_MODE eller konfigurera POSTGRES_HOST med uppgifter" >&2
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
GUNICORN_CMD="gunicorn --bind 0.0.0.0:${APP_PORT} \
    --workers ${WEB_CONCURRENCY} --threads ${THREADS} \
    --access-logfile ${LOG_DIR}/gunicorn-access.log \
    --error-logfile ${LOG_DIR}/gunicorn-error.log \
    --timeout 60 \
    --user app --group app \
    --preload \
    wsgi:app"

echo "Starting Gunicorn: $GUNICORN_CMD"
sh -c "$GUNICORN_CMD" &
GUNICORN_PID=$!

shutdown

set +e
if [ -n "${GUNICORN_PID}" ]; then
  wait "${GUNICORN_PID}" 2>/dev/null
  GUNICORN_STATUS=$?
else
  GUNICORN_STATUS=0
fi
set -e
exit "${GUNICORN_STATUS}"
