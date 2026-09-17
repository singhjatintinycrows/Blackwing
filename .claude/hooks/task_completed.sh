#!/usr/bin/env bash
# TaskCompleted: reject completion missing raw output, command log, or (source/android)
# the traced-path evidence the methodology requires.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/task_completed.py"
