#!/usr/bin/env bash
# Stop everything start_all.sh launched.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
for svc in web proxy testbed; do
  if [ -f ".run/$svc.pid" ]; then
    kill "$(cat .run/$svc.pid)" 2>/dev/null && echo "stopped $svc" || echo "$svc not running"
    rm -f ".run/$svc.pid"
  fi
done
