#!/usr/bin/env bash
set -euo pipefail

# Generera Cloudflare IP-listor för Nginx och brandvägg

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
CF_IPV6_URL="https://www.cloudflare.com/ips-v6"

OUTPUT_NGINX="${REPO_ROOT}/deploy/nginx/conf.d/cloudflare-realip.conf"
OUTPUT_FIREWALL="${REPO_ROOT}/scripts/firewall/cloudflare-ips.txt"

curl_args=(-fsSL -A "JK-Utbildningsintyg-IP-Generator/1.0")

ipv4_raw="$(curl "${curl_args[@]}" "${CF_IPV4_URL}")"
ipv6_raw="$(curl "${curl_args[@]}" "${CF_IPV6_URL}")"

CF_IPV4_RAW="${ipv4_raw}" CF_IPV6_RAW="${ipv6_raw}" \
OUTPUT_NGINX="${OUTPUT_NGINX}" OUTPUT_FIREWALL="${OUTPUT_FIREWALL}" \
python - <<'PY'
import ipaddress
import os
import sys
from datetime import datetime, timezone

ipv4_raw = os.environ["CF_IPV4_RAW"]
ipv6_raw = os.environ["CF_IPV6_RAW"]
output_nginx = os.environ["OUTPUT_NGINX"]
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

nginx_lines = [
    "# Autogenererad Cloudflare realip-konfiguration",
    f"# Uppdaterad: {timestamp}",
    "real_ip_header CF-Connecting-IP;",
    "real_ip_recursive on;",
    "",
]
nginx_lines += [f"set_real_ip_from {cidr};" for cidr in ipv4 + ipv6]
nginx_lines.append("")

firewall_lines = [
    "# Autogenererad Cloudflare IP-lista",
    f"# Uppdaterad: {timestamp}",
]
firewall_lines += ipv4 + ipv6
firewall_lines.append("")

os.makedirs(os.path.dirname(output_nginx), exist_ok=True)
os.makedirs(os.path.dirname(output_firewall), exist_ok=True)

with open(output_nginx, "w", encoding="utf-8") as fh:
    fh.write("\n".join(nginx_lines))

with open(output_firewall, "w", encoding="utf-8") as fh:
    fh.write("\n".join(firewall_lines))
PY

echo "Uppdaterade Cloudflare-listor:"
echo "- ${OUTPUT_NGINX}"
echo "- ${OUTPUT_FIREWALL}"
