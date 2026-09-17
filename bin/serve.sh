#!/usr/bin/env bash
# Load .env and run the Blackwing web UI.
set -a; . ./.env; set +a
exec .venv/bin/uvicorn web.app.main:app --host "${BLACKWING_HOST:-127.0.0.1}" --port "${BLACKWING_PORT:-8000}"
