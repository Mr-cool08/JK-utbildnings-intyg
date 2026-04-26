#!/bin/bash
# Copyright (c) Liam Suorsa and Mika Suorsa
set -euo pipefail

source /etc/antivirus.env

LOG_FILE=${LOG_FILE:-/var/log/clamav/scan.log}
TIMESTAMP=$(date -Iseconds)
SMTP_SERVER=${SMTP_SERVER:-}
SMTP_PORT=${SMTP_PORT:-587}
SMTP_USER=${SMTP_USER:-}
SMTP_PASSWORD=${SMTP_PASSWORD:-}
SMTP_TIMEOUT=${SMTP_TIMEOUT:-30}
CRITICAL_ALERTS_EMAIL=${CRITICAL_ALERTS_EMAIL:-}
ALERT_EMAIL_SUBJECT=${ALERT_EMAIL_SUBJECT:-"Varning: antivirus hittade infekterade filer"}
EXTRA_EXCLUDE_DIRS=${EXTRA_EXCLUDE_DIRS:-}

send_alert_email() {
  local infected_report="$1"

  if [ -z "${CRITICAL_ALERTS_EMAIL}" ] || [ -z "${SMTP_SERVER}" ] || [ -z "${SMTP_USER}" ] || [ -z "${SMTP_PASSWORD}" ]; then
    return 0
  fi

  local mail_body
  mail_body=$(cat <<MAIL
Antivirusskanningen hittade infekterade filer.

Tidpunkt: ${TIMESTAMP}
Skannade sökvägar: ${SCAN_PATHS}
Loggfil: ${LOG_FILE}

Infekterade filer:
${infected_report}

Kontrollera loggen för detaljer och vidta åtgärder omedelbart.
MAIL
  )

  echo "${mail_body}" | mail -s "${ALERT_EMAIL_SUBJECT}" -r "${SMTP_USER}" "${CRITICAL_ALERTS_EMAIL}"
}

echo "[${TIMESTAMP}] Startar virusskanning (paths: ${SCAN_PATHS})" | tee -a "${LOG_FILE}"

if freshclam --quiet; then
  echo "[$(date -Iseconds)] Signaturdatabas uppdaterad" | tee -a "${LOG_FILE}"
else
  echo "[$(date -Iseconds)] Kunde inte uppdatera signaturdatabasen. Fortsätter med senaste kända version." | tee -a "${LOG_FILE}"
fi

if [ -n "${QUARANTINE_PATH:-}" ]; then
  echo "[$(date -Iseconds)] OBS: QUARANTINE_PATH är satt men ignoreras. Inga filer flyttas eller kopieras." | tee -a "${LOG_FILE}"
fi

SCAN_PATHS_RESOLVED="${SCAN_PATHS//,/ }"
read -r -a PATH_ARRAY <<< "${SCAN_PATHS_RESOLVED}"

SCAN_CMD=(clamscan -r -i)

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
  "/host/home/client_52_3/JK-utbildnings-intyg/venv"
)


if [ -n "${EXTRA_EXCLUDE_DIRS}" ]; then
  # EXTRA_EXCLUDE_DIRS stöder kommaseparerad eller kolonseparerad lista.
  EXTRA_EXCLUDE_DIRS_NORMALIZED=${EXTRA_EXCLUDE_DIRS//:/,}
  IFS=',' read -r -a EXTRA_EXCLUDE_ARRAY <<< "${EXTRA_EXCLUDE_DIRS_NORMALIZED}"
  for RAW_EXCLUDE in "${EXTRA_EXCLUDE_ARRAY[@]}"; do
    EXCLUDE_TRIMMED=$(echo "${RAW_EXCLUDE}" | xargs)
    if [ -n "${EXCLUDE_TRIMMED}" ]; then
      EXCLUDE_DIRS+=("${EXCLUDE_TRIMMED}")
    fi
  done
fi

for EXCLUDE_DIR in "${EXCLUDE_DIRS[@]}"; do
  SCAN_CMD+=("--exclude-dir=${EXCLUDE_DIR}")
done

SCAN_CMD+=("${PATH_ARRAY[@]}")

printf -v CLAMSCAN_CMD_STR '%q ' "${SCAN_CMD[@]}"
echo "[$(date -Iseconds)] Kör clamscan: ${CLAMSCAN_CMD_STR}" | tee -a "${LOG_FILE}"

TMP_SCAN_OUTPUT=$(mktemp)
trap 'rm -f "${TMP_SCAN_OUTPUT}"' EXIT

if "${SCAN_CMD[@]}" 2>&1 | tee -a "${LOG_FILE}" >"${TMP_SCAN_OUTPUT}"; then
  STATUS=0
else
  STATUS=$?
fi

if [ ${STATUS} -eq 0 ]; then
  echo "[$(date -Iseconds)] Skanningen slutfördes utan infekterade filer." | tee -a "${LOG_FILE}"
elif [ ${STATUS} -eq 1 ]; then
  echo "[$(date -Iseconds)] Skanningen hittade infekterade filer. Se loggen för detaljer." | tee -a "${LOG_FILE}"
  INFECTED_REPORT=$(awk '/ FOUND$/ {print "- " $0}' "${TMP_SCAN_OUTPUT}")
  if [ -z "${INFECTED_REPORT}" ]; then
    INFECTED_REPORT="- Se loggfilen för detaljer om infekterade filer."
  fi
  send_alert_email "${INFECTED_REPORT}"
else
  echo "[$(date -Iseconds)] Skanningen misslyckades (exitkod: ${STATUS}). Kontrollera loggarna." | tee -a "${LOG_FILE}"
fi

exit ${STATUS}
