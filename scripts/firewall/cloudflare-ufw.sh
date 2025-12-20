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

run_cmd() {
  if [ "${MODE}" = "dry-run" ]; then
    echo "[DRY-RUN] $*"
  else
    echo "[APPLY] $*"
    "$@"
  fi
}

ensure_rule() {
  local rule_check="$1"
  shift
  if ufw status | grep -Fq "${rule_check}"; then
    echo "Regel finns redan: ${rule_check}"
  else
    run_cmd ufw "$@"
  fi
}

# Cloudflare IP-ranges (uppdatera vid behov)
CF_IPV4=(
  "173.245.48.0/20"
  "103.21.244.0/22"
  "103.22.200.0/22"
  "103.31.4.0/22"
  "141.101.64.0/18"
  "108.162.192.0/18"
  "190.93.240.0/20"
  "188.114.96.0/20"
  "197.234.240.0/22"
  "198.41.128.0/17"
  "162.158.0.0/15"
  "104.16.0.0/13"
  "104.24.0.0/14"
  "172.64.0.0/13"
  "131.0.72.0/22"
)

CF_IPV6=(
  "2400:cb00::/32"
  "2606:4700::/32"
  "2803:f800::/32"
  "2405:b500::/32"
  "2405:8100::/32"
  "2a06:98c0::/29"
  "2c0f:f248::/32"
)

ensure_rule "22/tcp" allow 22/tcp

for ip in "${CF_IPV4[@]}"; do
  ensure_rule "80/tcp ALLOW IN ${ip}" allow from "${ip}" to any port 80 proto tcp
  ensure_rule "443/tcp ALLOW IN ${ip}" allow from "${ip}" to any port 443 proto tcp
done

for ip in "${CF_IPV6[@]}"; do
  ensure_rule "80/tcp (v6) ALLOW IN ${ip}" allow from "${ip}" to any port 80 proto tcp
  ensure_rule "443/tcp (v6) ALLOW IN ${ip}" allow from "${ip}" to any port 443 proto tcp
done

ensure_rule "80/tcp DENY IN Anywhere" deny 80/tcp
ensure_rule "443/tcp DENY IN Anywhere" deny 443/tcp
ensure_rule "80/tcp (v6) DENY IN Anywhere (v6)" deny 80/tcp
ensure_rule "443/tcp (v6) DENY IN Anywhere (v6)" deny 443/tcp

if [ "${MODE}" = "apply" ]; then
  run_cmd ufw --force enable
fi

echo "Klar. Kontrollera UFW-status med: sudo ufw status numbered"
