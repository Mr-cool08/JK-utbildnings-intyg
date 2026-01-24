#!/bin/bash
# Copyright (c) Liam Suorsa
set -euo pipefail

source /etc/antivirus.env

LOG_FILE=${LOG_FILE:-/var/log/clamav/scan.log}
TIMESTAMP=$(date -Iseconds)
QUARANTINE_MODE=${QUARANTINE_MODE:-copy}
SMTP_SERVER=${SMTP_SERVER:-}
SMTP_PORT=${SMTP_PORT:-587}
SMTP_USER=${SMTP_USER:-}
SMTP_PASSWORD=${SMTP_PASSWORD:-}
SMTP_TIMEOUT=${SMTP_TIMEOUT:-30}
CRITICAL_ALERTS_EMAIL=${CRITICAL_ALERTS_EMAIL:-}
ALERT_EMAIL_SUBJECT=${ALERT_EMAIL_SUBJECT:-"Varning: antivirus hittade infekterade filer"}

send_alert_email() {
  if [ -z "${CRITICAL_ALERTS_EMAIL}" ] || [ -z "${SMTP_SERVER}" ] || [ -z "${SMTP_USER}" ] || [ -z "${SMTP_PASSWORD}" ]; then
    return 0
  fi

  local mail_body
  mail_body=$(cat <<EOF
Antivirusskanningen hittade infekterade filer.

Tidpunkt: ${TIMESTAMP}
Skannade sökvägar: ${SCAN_PATHS}
Loggfil: ${LOG_FILE}

Kontrollera loggen för detaljer och vidta åtgärder omedelbart.
EOF
  )

  echo "${mail_body}" | mail -s "${ALERT_EMAIL_SUBJECT}" -r "${SMTP_USER}" "${CRITICAL_ALERTS_EMAIL}"
}

echo "[${TIMESTAMP}] Startar virusskanning (paths: ${SCAN_PATHS})" | tee -a "${LOG_FILE}"

if freshclam --quiet; then
  echo "[$(date -Iseconds)] Signaturdatabas uppdaterad" | tee -a "${LOG_FILE}"
else
  echo "[$(date -Iseconds)] Kunde inte uppdatera signaturdatabasen. Fortsätter med senaste kända version." | tee -a "${LOG_FILE}"
fi

if [ -n "${QUARANTINE_PATH}" ]; then
  mkdir -p "${QUARANTINE_PATH}"
fi

SCAN_PATHS_RESOLVED="${SCAN_PATHS//,/ }"
read -r -a PATH_ARRAY <<< "${SCAN_PATHS_RESOLVED}"

SCAN_CMD=(clamscan -ri --log="${LOG_FILE}")

if [ -n "${EXTRA_CLAMSCAN_ARGS}" ]; then
  read -r -a EXTRA_ARGS_ARRAY <<< "${EXTRA_CLAMSCAN_ARGS}"
  SCAN_CMD+=("${EXTRA_ARGS_ARRAY[@]}")
fi

EXCLUDE_DIRS=(
  "/host/proc"
  "/host/sys"
  "/host/dev"
  "/host/run"
  "/host/var/lib/docker"
  "/host/var/lib/containerd"
  "/quarantine"
  "/home/client_52_3/.cache/pip"
)

if [ -n "${QUARANTINE_PATH}" ]; then
  EXCLUDE_DIRS+=("${QUARANTINE_PATH}")
fi

for EXCLUDE_DIR in "${EXCLUDE_DIRS[@]}"; do
  SCAN_CMD+=(--exclude-dir="^${EXCLUDE_DIR}(/|$)")
done

if [ -n "${QUARANTINE_PATH}" ]; then
  if [ "${QUARANTINE_MODE}" = "move" ]; then
    SCAN_CMD+=(--move="${QUARANTINE_PATH}")
  else
    SCAN_CMD+=(--copy="${QUARANTINE_PATH}")
  fi
fi

SCAN_CMD+=("${PATH_ARRAY[@]}")

printf -v CLAMSCAN_CMD_STR '%q ' "${SCAN_CMD[@]}"
echo "[$(date -Iseconds)] Kör clamscan: ${CLAMSCAN_CMD_STR}" | tee -a "${LOG_FILE}"

if "${SCAN_CMD[@]}"; then
  STATUS=0
else
  STATUS=$?
fi

if [ ${STATUS} -eq 0 ]; then
  echo "[$(date -Iseconds)] Skanningen slutfördes utan infekterade filer." | tee -a "${LOG_FILE}"
elif [ ${STATUS} -eq 1 ]; then
  echo "[$(date -Iseconds)] Skanningen hittade infekterade filer. Se loggen för detaljer." | tee -a "${LOG_FILE}"
  send_alert_email
else
  if [ "${QUARANTINE_MODE}" = "move" ]; then
    echo "[$(date -Iseconds)] Karantänflytt misslyckades. Kontrollera att QUARANTINE_PATH är skrivbar eller använd QUARANTINE_MODE=copy." | tee -a "${LOG_FILE}"
  fi
  echo "[$(date -Iseconds)] Skanningen misslyckades (exitkod: ${STATUS}). Kontrollera loggarna." | tee -a "${LOG_FILE}"
fi

exit ${STATUS}
