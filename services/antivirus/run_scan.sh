#!/bin/bash
set -euo pipefail

source /etc/antivirus.env

LOG_FILE=${LOG_FILE:-/var/log/clamav/scan.log}
TIMESTAMP=$(date -Iseconds)

echo "[${TIMESTAMP}] Startar virusskanning (paths: ${SCAN_PATHS})" | tee -a "${LOG_FILE}"

if freshclam --quiet; then
  echo "[$(date -Iseconds)] Signaturdatabas uppdaterad" | tee -a "${LOG_FILE}"
else
  echo "[$(date -Iseconds)] Kunde inte uppdatera signaturdatabasen. Fortsätter med senaste kända version." | tee -a "${LOG_FILE}"
fi

if [ -n "${QUARANTINE_PATH}" ]; then
  mkdir -p "${QUARANTINE_PATH}"
fi

read -r -a PATH_ARRAY <<< "${SCAN_PATHS}"

SCAN_CMD=(clamscan -ri --log="${LOG_FILE}")

if [ -n "${EXTRA_CLAMSCAN_ARGS}" ]; then
  read -r -a EXTRA_ARGS_ARRAY <<< "${EXTRA_CLAMSCAN_ARGS}"
  SCAN_CMD+=("${EXTRA_ARGS_ARRAY[@]}")
fi

if [ -n "${QUARANTINE_PATH}" ]; then
  SCAN_CMD+=(--move="${QUARANTINE_PATH}")
fi

SCAN_CMD+=("${PATH_ARRAY[@]}")

"${SCAN_CMD[@]}"
STATUS=$?

if [ ${STATUS} -eq 0 ]; then
  echo "[$(date -Iseconds)] Skanningen slutfördes utan infekterade filer." | tee -a "${LOG_FILE}"
elif [ ${STATUS} -eq 1 ]; then
  echo "[$(date -Iseconds)] Skanningen hittade infekterade filer. Se loggen för detaljer." | tee -a "${LOG_FILE}"
else
  echo "[$(date -Iseconds)] Skanningen misslyckades (exitkod: ${STATUS}). Kontrollera loggarna." | tee -a "${LOG_FILE}"
fi

exit ${STATUS}
