#!/bin/bash
# Copyright (c) Liam Suorsa
set -euo pipefail

SCAN_SCHEDULE="${SCAN_SCHEDULE:-0 */6 * * *}"
SCAN_PATHS="${SCAN_PATHS:-/host}"
QUARANTINE_PATH="${QUARANTINE_PATH:-}"
QUARANTINE_MODE="${QUARANTINE_MODE:-copy}"
EXTRA_CLAMSCAN_ARGS="${EXTRA_CLAMSCAN_ARGS:-}"
RUN_AT_START="${RUN_AT_START:-true}"
ALERT_EMAIL_TO="${ALERT_EMAIL_TO:-}"
ALERT_EMAIL_FROM="${ALERT_EMAIL_FROM:-}"
ALERT_SMTP_HOST="${ALERT_SMTP_HOST:-}"
ALERT_SMTP_PORT="${ALERT_SMTP_PORT:-587}"
ALERT_SMTP_USER="${ALERT_SMTP_USER:-}"
ALERT_SMTP_PASSWORD="${ALERT_SMTP_PASSWORD:-}"
ALERT_SMTP_TLS="${ALERT_SMTP_TLS:-true}"

mkdir -p /var/log/clamav
chmod 755 /var/log/clamav

cat > /etc/antivirus.env <<ENV
SCAN_PATHS="${SCAN_PATHS}"
QUARANTINE_PATH="${QUARANTINE_PATH}"
QUARANTINE_MODE="${QUARANTINE_MODE}"
EXTRA_CLAMSCAN_ARGS="${EXTRA_CLAMSCAN_ARGS}"
ALERT_EMAIL_TO="${ALERT_EMAIL_TO}"
ALERT_EMAIL_FROM="${ALERT_EMAIL_FROM}"
ALERT_SMTP_HOST="${ALERT_SMTP_HOST}"
ALERT_SMTP_PORT="${ALERT_SMTP_PORT}"
ALERT_SMTP_USER="${ALERT_SMTP_USER}"
ALERT_SMTP_PASSWORD="${ALERT_SMTP_PASSWORD}"
ALERT_SMTP_TLS="${ALERT_SMTP_TLS}"
ENV

if [ -n "${ALERT_SMTP_HOST}" ]; then
  {
    echo "defaults"
    if [ -n "${ALERT_SMTP_USER}" ]; then
      echo "auth on"
    else
      echo "auth off"
    fi
    echo "tls ${ALERT_SMTP_TLS}"
    echo "tls_trust_file /etc/ssl/certs/ca-certificates.crt"
    echo "logfile /var/log/clamav/msmtp.log"
    echo "account default"
    echo "host ${ALERT_SMTP_HOST}"
    echo "port ${ALERT_SMTP_PORT}"
    if [ -n "${ALERT_SMTP_USER}" ]; then
      echo "user ${ALERT_SMTP_USER}"
      echo "password ${ALERT_SMTP_PASSWORD}"
    fi
    if [ -n "${ALERT_EMAIL_FROM}" ]; then
      echo "from ${ALERT_EMAIL_FROM}"
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
