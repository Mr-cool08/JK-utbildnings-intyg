#!/usr/bin/env bash
set -euo pipefail

# Default configuration
APP_IMAGE="${APP_IMAGE:-ghcr.io/mr-cool08/jk-utbildnings-intyg:latest}"
APP_CONTAINER="${APP_CONTAINER:-jk_utbildningsintyg_app}"
DB_IMAGE="${DB_IMAGE:-postgres:15-alpine}"
DB_CONTAINER="${DB_CONTAINER:-jk_utbildningsintyg_db}"
NETWORK_NAME="${NETWORK_NAME:-jk_utbildningsintyg_net}"
ENV_FILE="${ENV_FILE:-.env}"
POSTGRES_VOLUME="${POSTGRES_VOLUME:-jk_utbildningsintyg_postgres_data}"
UPLOADS_VOLUME="${UPLOADS_VOLUME:-jk_utbildningsintyg_uploads}"
LOGS_VOLUME="${LOGS_VOLUME:-jk_utbildningsintyg_logs}"
DATA_VOLUME="${DATA_VOLUME:-jk_utbildningsintyg_data}"

command -v docker >/dev/null 2>&1 || {
  echo "Docker is required to run this script." >&2
  exit 1
}

if [ ! -f "$ENV_FILE" ]; then
  echo "Environment file '$ENV_FILE' not found. Create it from .example.env first." >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
. "$ENV_FILE"
set +a

for var in POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD; do
  if [ -z "${!var:-}" ]; then
    echo "Set $var in $ENV_FILE before running this script." >&2
    exit 1
  fi
done

ensure_network() {
  local name="$1"
  if ! docker network inspect "$name" >/dev/null 2>&1; then
    echo "Creating network $name"
    docker network create "$name" >/dev/null
  fi
}

ensure_volume() {
  local name="$1"
  if ! docker volume inspect "$name" >/dev/null 2>&1; then
    echo "Creating volume $name"
    docker volume create "$name" >/dev/null
  fi
}

start_database() {
  if [ -n "$(docker ps -q --filter "name=^${DB_CONTAINER}$")" ]; then
    echo "Database container $DB_CONTAINER already running"
    return
  fi

  if [ -n "$(docker ps -aq --filter "name=^${DB_CONTAINER}$")" ]; then
    echo "Starting existing database container $DB_CONTAINER"
    docker start "$DB_CONTAINER" >/dev/null
    return
  fi

  echo "Creating database container $DB_CONTAINER"
  docker run -d \
    --name "$DB_CONTAINER" \
    --network "$NETWORK_NAME" \
    -e POSTGRES_DB="$POSTGRES_DB" \
    -e POSTGRES_USER="$POSTGRES_USER" \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -v "$POSTGRES_VOLUME:/var/lib/postgresql/data" \
    "$DB_IMAGE" >/dev/null
}

start_app() {
  if [ -n "$(docker ps -aq --filter "name=^${APP_CONTAINER}$")" ]; then
    echo "Removing existing application container $APP_CONTAINER"
    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
  fi

  echo "Creating application container $APP_CONTAINER"
  docker run -d \
    --name "$APP_CONTAINER" \
    --network "$NETWORK_NAME" \
    --env-file "$ENV_FILE" \
    -e DATABASE_URL="postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${DB_CONTAINER}:5432/${POSTGRES_DB}" \
    -p 80:80 \
    -p 443:443 \
    -v "$UPLOADS_VOLUME:/app/uploads" \
    -v "$LOGS_VOLUME:/app/logs" \
    -v "$DATA_VOLUME:/data" \
    "$APP_IMAGE" >/dev/null
}

echo "Preparing Docker resources"
ensure_network "$NETWORK_NAME"
ensure_volume "$POSTGRES_VOLUME"
ensure_volume "$UPLOADS_VOLUME"
ensure_volume "$LOGS_VOLUME"
ensure_volume "$DATA_VOLUME"

start_database
start_app

echo "Stack is running. Containers:"
docker ps --filter "name=${APP_CONTAINER}" --filter "name=${DB_CONTAINER}"
