#!/bin/bash
# Copyright (c) Liam Suorsa
set -euo pipefail

SCAN_SCHEDULE="${SCAN_SCHEDULE:-0 */6 * * *}"
SCAN_PATHS="${SCAN_PATHS:-/host}"
QUARANTINE_PATH="${QUARANTINE_PATH:-}"
EXTRA_CLAMSCAN_ARGS="${EXTRA_CLAMSCAN_ARGS:-}"
RUN_AT_START="${RUN_AT_START:-true}"

mkdir -p /var/log/clamav
chmod 755 /var/log/clamav

cat > /etc/antivirus.env <<ENV
SCAN_PATHS="${SCAN_PATHS}"
QUARANTINE_PATH="${QUARANTINE_PATH}"
EXTRA_CLAMSCAN_ARGS="${EXTRA_CLAMSCAN_ARGS}"
ENV

freshclam --quiet || true

CRON_FILE=/etc/cron.d/antivirus
{
  echo "SHELL=/bin/bash"
  echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  echo "${SCAN_SCHEDULE} root /usr/local/bin/run_scan.sh >> /var/log/clamav/cron.log 2>&1"
} > "${CRON_FILE}"
chmod 0644 "${CRON_FILE}"
crontab "${CRON_FILE}"

if [ "${RUN_AT_START}" = "true" ]; then
  /usr/local/bin/run_scan.sh
fi

exec cron -f
