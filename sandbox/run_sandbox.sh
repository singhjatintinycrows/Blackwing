#!/usr/bin/env bash
# Per-job sandbox lifecycle: build (once), run one job in an ephemeral container, tear down.
#
#   sandbox/run_sandbox.sh <job_dir>
#
# The container gets ONLY that job's directory (bind-mounted at /job) plus the Bedrock
# credential via env — never another job's data, never a persisted token. --rm tears it down
# after the run. Network is restricted to what the engagement needs; tighten per your policy.
set -euo pipefail

JOB_DIR="${1:?usage: run_sandbox.sh <job_dir>}"
JOB_DIR="$(cd "$JOB_DIR" && pwd)"
JOB_ID="$(basename "$JOB_DIR")"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="blackwing-sandbox:latest"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[sandbox] building $IMAGE ..."
  docker build -f "$ROOT/sandbox/Dockerfile" -t "$IMAGE" "$ROOT"
fi

echo "[sandbox] running job $JOB_ID (ephemeral, --rm)"
docker run --rm \
  --name "blackwing-$JOB_ID" \
  --network bridge \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 512 \
  --memory 4g \
  -v "$JOB_DIR":/job:rw \
  -e AWS_REGION="${AWS_REGION:-ap-south-1}" \
  -e AWS_BEARER_TOKEN_BEDROCK="${AWS_BEARER_TOKEN_BEDROCK:-}" \
  -e BLACKWING_MODEL="${BLACKWING_MODEL:-openai.gpt-oss-120b-1:0}" \
  -e BLACKWING_MODEL_MOCK="${BLACKWING_MODEL_MOCK:-0}" \
  "$IMAGE"

echo "[sandbox] job $JOB_ID complete; container removed"
