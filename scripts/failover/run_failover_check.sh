#!/usr/bin/env sh
set -eu

LOCK_DIR="/tmp/run_failover_check.lock"

if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
  echo "Failover-kontroll körs redan, hoppar över denna körning."
  exit 0
fi

cleanup() {
  rmdir "${LOCK_DIR}" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

exec python /app/scripts/failover/cloudflare_failover.py

# Copyright (c) Liam Suorsa and Mika Suorsa
