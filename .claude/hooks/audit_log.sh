#!/usr/bin/env bash
# PostToolUse/Bash: append a hash-chained, secret-redacted audit entry.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/audit_log.py"
