#!/usr/bin/env bash
# Bring up the whole Blackwing stack locally: Codex⇄Bedrock shim, web UI, and (optional)
# the local vulnerable testbed. Idempotent-ish: it won't double-start a live port.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
set -a; . ./.env; set +a
mkdir -p .run
PY=".venv/bin/python"
UVPORT="${BLACKWING_PORT:-8900}"
PROXPORT="${CODEX_PROXY_PORT:-8791}"
TESTBED_PORT="${TESTBED_PORT:-8477}"

up() { curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$1" 2>/dev/null; }

# Codex⇄Bedrock shim
if ! curl -s --max-time 1 "http://127.0.0.1:$PROXPORT/health" >/dev/null 2>&1; then
  CODEX_PROXY_PORT="$PROXPORT" nohup $PY -m tools.codex_bedrock_proxy >.run/proxy.log 2>&1 &
  echo $! > .run/proxy.pid; echo "started Codex shim on $PROXPORT (pid $(cat .run/proxy.pid))"
else echo "Codex shim already up on $PROXPORT"; fi

# Web UI
if ! up "$UVPORT" ; then
  nohup $PY -m uvicorn web.app.main:app --host "${BLACKWING_HOST:-127.0.0.1}" --port "$UVPORT" \
    >.run/web.log 2>&1 &
  echo $! > .run/web.pid; echo "started web UI on http://127.0.0.1:$UVPORT (pid $(cat .run/web.pid))"
else echo "web UI already up on $UVPORT"; fi

# Optional local testbed
if [ "${1:-}" = "--testbed" ]; then
  if ! up "$TESTBED_PORT" ; then
    nohup $PY tools/testbed.py "$TESTBED_PORT" >.run/testbed.log 2>&1 &
    echo $! > .run/testbed.pid; echo "started testbed on http://127.0.0.1:$TESTBED_PORT (pid $(cat .run/testbed.pid))"
  else echo "testbed already up on $TESTBED_PORT"; fi
fi
echo; echo "Open the web UI:  http://127.0.0.1:$UVPORT"
echo "Sign in as a reviewer to approve active scans:  ${BLACKWING_REVIEWERS:-reviewer@tinycrows.com}"
