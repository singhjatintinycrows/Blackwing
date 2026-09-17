#!/usr/bin/env bash
# Pre+PostToolUse/Bash: deny writing the GitHub token / any detected live credential to a
# file outside the ephemeral in-memory scope; scrub secrets from logs before persist.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/secret_guard.py"
