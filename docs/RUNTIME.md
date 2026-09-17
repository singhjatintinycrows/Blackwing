# Runtime configuration

## Model endpoint (verified 2026-09-17)

Blackwing drives its agent team through an OpenAI-compatible chat-completions endpoint
served by **AWS Bedrock** (Mantle).

| Setting | Value |
|---|---|
| Region | `ap-south-1` (Asia Pacific, Mumbai) |
| Base URL | `https://bedrock-runtime.ap-south-1.amazonaws.com/openai/v1` |
| Model ID | `openai.gpt-oss-120b-1:0` |
| Auth | `Authorization: Bearer $AWS_BEARER_TOKEN_BEDROCK` |
| Chat path | `POST /chat/completions` |
| Token param | `max_completion_tokens` (not `max_tokens`) |

### Residency note
The API key and inference run in `ap-south-1` (Mumbai). This satisfies an India
data-residency requirement. The `gpt-oss-120b` model is available directly (no
cross-region `us.`/`apac.` inference-profile prefix — those return `validation_error`).

### Reasoning output
`gpt-oss-120b` is a reasoning model; responses may include a `<reasoning>...</reasoning>`
block before the answer. The engine's model client strips reasoning from the final answer
but preserves it in `artifacts/` for audit.

## Smoke test

```bash
set -a; . ./.env; set +a
curl -sS "https://bedrock-runtime.${AWS_REGION}.amazonaws.com/openai/v1/chat/completions" \
  -H "Authorization: Bearer ${AWS_BEARER_TOKEN_BEDROCK}" \
  -H "Content-Type: application/json" \
  -d '{"model":"'"$BLACKWING_MODEL"'","messages":[{"role":"user","content":"say BLACKWING_OK"}],"max_completion_tokens":16}'
```

Expect HTTP 200 with a `choices[].message.content` field.

## Codex CLI

The engine invokes the Codex CLI inside each per-job sandbox, pointed at the Bedrock
endpoint above via `CODEX_BIN`. If Codex is unavailable, set `BLACKWING_MODEL_MOCK=1` to
drive the pipeline against a deterministic local mock (used by the test suite). The model
client (`lib/model_client.py`) is the single integration point; both Codex and the mock go
through it.
