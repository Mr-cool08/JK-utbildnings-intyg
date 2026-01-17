#!/usr/bin/env bash
# Copyright (c) Liam Suorsa
set -euo pipefail

# Säkerhetskopiera PostgreSQL till en volym med roterande retention

MODE="${1:---once}"

if [ "${MODE}" != "--once" ] && [ "${MODE}" != "--loop" ]; then
  echo "Användning: $0 [--once|--loop]"
  exit 1
fi

POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-}"
POSTGRES_USER="${POSTGRES_USER:-}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
BACKUP_INTERVAL_SECONDS="${BACKUP_INTERVAL_SECONDS:-86400}"

if [ -z "${POSTGRES_DB}" ] || [ -z "${POSTGRES_USER}" ]; then
  echo "Fel: POSTGRES_DB och POSTGRES_USER måste vara satta."
  exit 1
fi

mkdir -p "${BACKUP_DIR}"

run_backup() {
  local timestamp filename
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  filename="${BACKUP_DIR}/backup-${timestamp}.sql.gz"

  echo "Skapar backup: ${filename}"
  export PGPASSWORD="${POSTGRES_PASSWORD}"
  pg_dump -h "${POSTGRES_HOST}" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" \
    | gzip > "${filename}"

  find "${BACKUP_DIR}" -type f -name "backup-*.sql.gz" \
    -mtime "+${BACKUP_RETENTION_DAYS}" -print -delete || true
}

if [ "${MODE}" = "--once" ]; then
  run_backup
  exit 0
fi

while true; do
  run_backup
  sleep "${BACKUP_INTERVAL_SECONDS}"
done
