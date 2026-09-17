#!/usr/bin/env bash
# PreToolUse/Bash: deny Google/GitHub dorking in EVERY track.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/dorking_guard.py"
