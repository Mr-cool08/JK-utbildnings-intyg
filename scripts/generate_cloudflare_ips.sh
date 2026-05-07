#!/usr/bin/env bash
# Copyright (c) Liam Suorsa and Mika Suorsa
set -euo pipefail

# Generera Cloudflare IP-lista för brandvägg

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
CF_IPV6_URL="https://www.cloudflare.com/ips-v6"

OUTPUT_FIREWALL="${REPO_ROOT}/scripts/firewall/cloudflare-ips.txt"

curl_args=(-fsSL -A "JK-Utbildningsintyg-IP-Generator/1.0")

ipv4_raw="$(curl "${curl_args[@]}" "${CF_IPV4_URL}")"
ipv6_raw="$(curl "${curl_args[@]}" "${CF_IPV6_URL}")"

CF_IPV4_RAW="${ipv4_raw}" CF_IPV6_RAW="${ipv6_raw}" \
OUTPUT_FIREWALL="${OUTPUT_FIREWALL}" \
python - <<'PY'
import ipaddress
import os
import sys
from datetime import datetime, timezone

ipv4_raw = os.environ["CF_IPV4_RAW"]
ipv6_raw = os.environ["CF_IPV6_RAW"]
output_firewall = os.environ["OUTPUT_FIREWALL"]


def parse_lines(raw: str) -> list[str]:
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    cidrs: list[str] = []
    for line in lines:
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError as exc:
            print(f"Ogiltigt CIDR-värde: {line} ({exc})", file=sys.stderr)
            sys.exit(1)
        cidrs.append(str(network))
    return cidrs


ipv4 = parse_lines(ipv4_raw)
ipv6 = parse_lines(ipv6_raw)
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

firewall_lines = [
    "# Autogenererad Cloudflare IP-lista",
    f"# Uppdaterad: {timestamp}",
]
firewall_lines += ipv4 + ipv6
firewall_lines.append("")

os.makedirs(os.path.dirname(output_firewall), exist_ok=True)

with open(output_firewall, "w", encoding="utf-8") as fh:
    fh.write("\n".join(firewall_lines))
PY

echo "Uppdaterade Cloudflare-listor:"
echo "- ${OUTPUT_FIREWALL}"
