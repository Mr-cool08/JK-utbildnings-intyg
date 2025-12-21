#!/usr/bin/env bash
set -euo pipefail

# Enkel UFW-brandvägg för att bara tillåta Cloudflare IP-ranges mot 80/443

MODE="dry-run"

usage() {
  echo "Användning: $0 [--dry-run|--apply]"
}

if [ "${1:-}" = "--apply" ]; then
  MODE="apply"
elif [ "${1:-}" = "--dry-run" ] || [ -z "${1:-}" ]; then
  MODE="dry-run"
else
  usage
  exit 1
fi

if [ "${MODE}" = "apply" ] && [ "${EUID}" -ne 0 ]; then
  echo "Fel: måste köras som root eller med sudo för --apply."
  exit 1
fi

run_cmd() {
  if [ "${MODE}" = "dry-run" ]; then
    echo "[DRY-RUN] $*"
  else
    echo "[APPLY] $*"
    "$@"
  fi
}

ensure_rule() {
  if [ "${MODE}" = "dry-run" ]; then
    echo "[DRY-RUN] ufw $*"
    return 0
  fi

  local output status
  output="$(ufw "$@" 2>&1)" || status=$?
  status=${status:-0}

  if printf '%s' "${output}" | grep -qi "Skipping adding existing rule"; then
    echo "Regel finns redan: ufw $*"
    return 0
  fi

  if [ "${status}" -ne 0 ]; then
    echo "${output}" >&2
    return "${status}"
  fi

  if [ -n "${output}" ]; then
    echo "${output}"
  fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IPS_FILE="${IPS_FILE:-${SCRIPT_DIR}/cloudflare-ips.txt}"

if [ ! -f "${IPS_FILE}" ]; then
  echo "Fel: IP-lista saknas: ${IPS_FILE}"
  echo "Kör scripts/generate_cloudflare_ips.sh för att uppdatera listan."
  exit 1
fi

if [ "${MODE}" = "apply" ]; then
  ensure_rule default deny incoming
fi

ensure_rule allow 22/tcp

while IFS= read -r ip; do
  [ -z "${ip}" ] && continue
  case "${ip}" in
    \#*) continue ;;
  esac

  ensure_rule allow from "${ip}" to any port 80 proto tcp
  ensure_rule allow from "${ip}" to any port 443 proto tcp
done < "${IPS_FILE}"

if [ "${MODE}" = "apply" ]; then
  run_cmd ufw --force enable
fi

echo "Klar. Kontrollera UFW-status med: sudo ufw status numbered"
