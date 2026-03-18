#!/usr/bin/env sh
# Copyright (c) Liam Suorsa and Mika Suorsa
set -eu

MODE="${1:---once}"

if [ "${MODE}" != "--once" ] && [ "${MODE}" != "--loop" ]; then
  echo "Anvandning: $0 [--once|--loop]"
  exit 1
fi

RCLONE_REMOTE="${RCLONE_REMOTE:-}"
RCLONE_BACKUP_PATH="${RCLONE_BACKUP_PATH:-jk-utbildnings-intyg/postgres}"
RCLONE_SYNC_INTERVAL_SECONDS="${RCLONE_SYNC_INTERVAL_SECONDS:-3600}"
RCLONE_PRUNE_REMOTE="${RCLONE_PRUNE_REMOTE:-false}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
RCLONE_CONFIG_FILE="${RCLONE_CONFIG_FILE:-/tmp/rclone/rclone.conf}"
BACKUP_SOURCE_DIR="${BACKUP_SOURCE_DIR:-/backups}"
RCLONE_ONEDRIVE_CLIENT_ID="${RCLONE_ONEDRIVE_CLIENT_ID:-}"
RCLONE_ONEDRIVE_CLIENT_SECRET="${RCLONE_ONEDRIVE_CLIENT_SECRET:-}"
RCLONE_ONEDRIVE_TOKEN="${RCLONE_ONEDRIVE_TOKEN:-}"
RCLONE_ONEDRIVE_DRIVE_ID="${RCLONE_ONEDRIVE_DRIVE_ID:-}"
RCLONE_ONEDRIVE_DRIVE_TYPE="${RCLONE_ONEDRIVE_DRIVE_TYPE:-}"
RCLONE_ONEDRIVE_REGION="${RCLONE_ONEDRIVE_REGION:-global}"
RCLONE_DROPBOX_CLIENT_ID="${RCLONE_DROPBOX_CLIENT_ID:-}"
RCLONE_DROPBOX_CLIENT_SECRET="${RCLONE_DROPBOX_CLIENT_SECRET:-}"
RCLONE_DROPBOX_TOKEN="${RCLONE_DROPBOX_TOKEN:-}"
RCLONE_DROPBOX_AUTH_URL="${RCLONE_DROPBOX_AUTH_URL:-}"
RCLONE_DROPBOX_TOKEN_URL="${RCLONE_DROPBOX_TOKEN_URL:-}"

if [ -z "${RCLONE_REMOTE}" ]; then
  echo "Fel: RCLONE_REMOTE maste vara satt."
  exit 1
fi

if [ ! -d "${BACKUP_SOURCE_DIR}" ]; then
  echo "Fel: backupkatalogen ${BACKUP_SOURCE_DIR} finns inte."
  exit 1
fi

require_value() {
  var_name="$1"
  message="$2"
  eval "var_value=\${${var_name}:-}"
  if [ -z "${var_value}" ]; then
    echo "Fel: ${message}"
    exit 1
  fi
}

validate_remote_credentials() {
  case "${RCLONE_REMOTE}" in
    onedrive)
      require_value "RCLONE_ONEDRIVE_TOKEN" "RCLONE_ONEDRIVE_TOKEN maste vara satt for OneDrive."
      require_value "RCLONE_ONEDRIVE_DRIVE_ID" "RCLONE_ONEDRIVE_DRIVE_ID maste vara satt for OneDrive."
      require_value "RCLONE_ONEDRIVE_DRIVE_TYPE" "RCLONE_ONEDRIVE_DRIVE_TYPE maste vara satt for OneDrive."
      ;;
    dropbox)
      require_value "RCLONE_DROPBOX_TOKEN" "RCLONE_DROPBOX_TOKEN maste vara satt for Dropbox."
      ;;
    *)
      echo "Fel: RCLONE_REMOTE maste vara 'onedrive' eller 'dropbox'."
      exit 1
      ;;
  esac
}

generate_rclone_config() {
  config_dir="$(dirname "${RCLONE_CONFIG_FILE}")"
  umask 077
  mkdir -p "${config_dir}"
  cat > "${RCLONE_CONFIG_FILE}" <<EOF
[onedrive]
type = onedrive
client_id = ${RCLONE_ONEDRIVE_CLIENT_ID}
client_secret = ${RCLONE_ONEDRIVE_CLIENT_SECRET}
token = ${RCLONE_ONEDRIVE_TOKEN}
drive_id = ${RCLONE_ONEDRIVE_DRIVE_ID}
drive_type = ${RCLONE_ONEDRIVE_DRIVE_TYPE}
region = ${RCLONE_ONEDRIVE_REGION}

[dropbox]
type = dropbox
client_id = ${RCLONE_DROPBOX_CLIENT_ID}
client_secret = ${RCLONE_DROPBOX_CLIENT_SECRET}
token = ${RCLONE_DROPBOX_TOKEN}
auth_url = ${RCLONE_DROPBOX_AUTH_URL}
token_url = ${RCLONE_DROPBOX_TOKEN_URL}
EOF
}

TARGET="${RCLONE_REMOTE}:${RCLONE_BACKUP_PATH}"

validate_remote_credentials
generate_rclone_config

run_sync() {
  echo "Kopierar databasbackuper fran ${BACKUP_SOURCE_DIR} till ${TARGET}"
  rclone copy \
    "${BACKUP_SOURCE_DIR}" \
    "${TARGET}" \
    --config "${RCLONE_CONFIG_FILE}" \
    --include "backup-*.sql.gz"

  if [ "${RCLONE_PRUNE_REMOTE}" = "true" ]; then
    echo "Rensar fjarrbackuper aldre an ${BACKUP_RETENTION_DAYS} dagar i ${TARGET}"
    rclone delete \
      "${TARGET}" \
      --config "${RCLONE_CONFIG_FILE}" \
      --include "backup-*.sql.gz" \
      --min-age "${BACKUP_RETENTION_DAYS}d"
  fi
}

if [ "${MODE}" = "--once" ]; then
  run_sync
  exit 0
fi

while true; do
  run_sync
  sleep "${RCLONE_SYNC_INTERVAL_SECONDS}"
done

# Copyright (c) Liam Suorsa and Mika Suorsa
