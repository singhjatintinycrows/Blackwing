#!/usr/bin/env bash
# PreToolUse/Bash: block decode-then-execute / fetch-then-execute laundering.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/injection_guard.py"
