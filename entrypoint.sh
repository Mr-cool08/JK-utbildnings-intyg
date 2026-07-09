#!/bin/sh
# Copyright (c) Liam Suorsa and Mika Suorsa
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

# Standardportar i containern (mappa utanfÃ¶r)
HTTP_PORT="${HTTP_PORT:-80}"
APP_PORT="${APP_PORT:-${HTTP_PORT}}"
LOG_DIR="${LOG_DIR:-/app/logs}"
APP_ENV="${APP_ENV:-production}"
normalized_app_env="$(printf '%s' "${APP_ENV}" | tr '[:upper:]' '[:lower:]')"
DEV_DATA_DIR="${DEV_DATA_DIR:-/app/dev-data}"

# Se till att loggkatalogen finns och kan skrivas av app-anvÃ¤ndaren
mkdir -p "${LOG_DIR}"
mkdir -p "${DEV_DATA_DIR}"
chown -R app:app "${LOG_DIR}"
chown -R app:app "${DEV_DATA_DIR}"

if [ "${normalized_app_env}" = "development" ]; then
  echo "Validerar separat utvecklingsmiljÃ¶ innan appstart"
  python -m scripts.validate_dev_environment
  echo "Seedar syntetiska utvecklingskonton"
  python -m scripts.seed_dev_environment
fi

# Validate external PostgreSQL configuration or enable local SQLite fallback.
if [ -z "${DATABASE_URL:-}" ]; then
  enable_local_db="${DEV_MODE:-false}"
  enable_local_db="$(printf '%s' "${enable_local_db}" | tr '[:upper:]' '[:lower:]')"
  enable_demo_mode="${ENABLE_DEMO_MODE:-false}"
  enable_demo_mode="$(printf '%s' "${enable_demo_mode}" | tr '[:upper:]' '[:lower:]')"

  case "${enable_local_db}:${enable_demo_mode}" in
    true:*|*:1|*:true|*:on|*:yes|*:ja|*:sant)
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
        echo "SÃ¤tt DATABASE_URL, aktivera DEV_MODE eller konfigurera POSTGRES_HOST med uppgifter" >&2
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

# Starta Gunicorn (kÃ¶r som app:app)
# Justera workers/threads efter CPU
WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}"
THREADS="${THREADS:-8}"

# Kontrollera att wsgi:app finns (Ã¤ndra modul om din heter nÃ¥got annat)
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

set +e
if [ -n "${GUNICORN_PID}" ]; then
  wait "${GUNICORN_PID}" 2>/dev/null
  GUNICORN_STATUS=$?
else
  GUNICORN_STATUS=0
fi
set -e
exit "${GUNICORN_STATUS}"
