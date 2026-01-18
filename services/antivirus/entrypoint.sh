#!/bin/bash
# Copyright (c) Liam Suorsa
set -euo pipefail

SCAN_SCHEDULE="${SCAN_SCHEDULE:-0 */6 * * *}"
SCAN_PATHS="${SCAN_PATHS:-/host}"
QUARANTINE_PATH="${QUARANTINE_PATH:-}"
QUARANTINE_MODE="${QUARANTINE_MODE:-copy}"
EXTRA_CLAMSCAN_ARGS="${EXTRA_CLAMSCAN_ARGS:-}"
RUN_AT_START="${RUN_AT_START:-true}"
SMTP_SERVER="${smtp_server:-}"
SMTP_PORT="${smtp_port:-587}"
SMTP_USER="${smtp_user:-}"
SMTP_PASSWORD="${smtp_password:-}"
SMTP_TIMEOUT="${smtp_timeout:-10}"
CRITICAL_ALERTS_EMAIL="${CRITICAL_ALERTS_EMAIL:-}"

mkdir -p /var/log/clamav
chmod 755 /var/log/clamav

cat > /etc/antivirus.env <<ENV
SCAN_PATHS="${SCAN_PATHS}"
QUARANTINE_PATH="${QUARANTINE_PATH}"
QUARANTINE_MODE="${QUARANTINE_MODE}"
EXTRA_CLAMSCAN_ARGS="${EXTRA_CLAMSCAN_ARGS}"
SMTP_SERVER="${SMTP_SERVER}"
SMTP_PORT="${SMTP_PORT}"
SMTP_USER="${SMTP_USER}"
SMTP_PASSWORD="${SMTP_PASSWORD}"
SMTP_TIMEOUT="${SMTP_TIMEOUT}"
CRITICAL_ALERTS_EMAIL="${CRITICAL_ALERTS_EMAIL}"
ENV

if [ -n "${SMTP_SERVER}" ]; then
  {
    echo "defaults"
    if [ -n "${SMTP_USER}" ]; then
      echo "auth on"
    else
      echo "auth off"
    fi
    echo "tls on"
    echo "tls_trust_file /etc/ssl/certs/ca-certificates.crt"
    echo "logfile /var/log/clamav/msmtp.log"
    echo "timeout ${SMTP_TIMEOUT}"
    echo "account default"
    echo "host ${SMTP_SERVER}"
    echo "port ${SMTP_PORT}"
    if [ -n "${SMTP_USER}" ]; then
      echo "user ${SMTP_USER}"
      echo "password ${SMTP_PASSWORD}"
    fi
    if [ -n "${SMTP_USER}" ]; then
      echo "from ${SMTP_USER}"
    fi
  } > /etc/msmtprc
  chmod 600 /etc/msmtprc
fi

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
  if /usr/local/bin/run_scan.sh; then
    :
  else
    STATUS=$?
    echo "[$(date -Iseconds)] Startskanning misslyckades (exitkod: ${STATUS}). Fortsätter med cron." | tee -a /var/log/clamav/scan.log
  fi
fi

exec cron -f
