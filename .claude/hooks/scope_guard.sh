#!/usr/bin/env bash
# PreToolUse/Bash: deny active/dynamic stages until scope.yaml is authorised + human-approved,
# and deny out-of-scope hosts / repos / package names. Reference impl lives in lib/scope.py.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/scope_guard.py"
