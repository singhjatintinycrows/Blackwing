# Model selection (India data residency)

Blackwing's engine model is set in `config/opencode.json` (installed to
`~/.config/opencode/opencode.json` via `make agent-config`). The whole engine is
model-agnostic — switching models is a one-line change, no code edits.

## Constraint: India-only residency
The model must run **in-region in `ap-south-1` (Mumbai)** with region-locked inference. The
cross-region `apac.` / `us.` inference profiles can route to other regions (Tokyo, Sydney,
Seoul) and are therefore **not** residency-compliant. Test a model with a direct model ID on
the regional runtime endpoint (`bedrock-runtime.ap-south-1.amazonaws.com/openai/v1`); if it
answers with the base ID (no `apac.` prefix), inference stays in India.

## Verified in-region (ap-south-1) on the OpenAI-compatible endpoint
These are drop-in — same endpoint/provider, just change the model string:

| Model | ID | OpenCode integration | Notes |
|---|---|---|---|
| **DeepSeek V3.2** | `deepseek.v3.2` | ✅ clean | Strong agentic/coding, low refusal — **default** |
| GLM-5 | `zai.glm-5` | ✅ clean | Strong coder |
| gpt-oss-120b | `openai.gpt-oss-120b-1:0` | ✅ clean | Prior default; over-refuses, inconsistent |
| Qwen3-Coder-480B | `qwen.qwen3-coder-480b-a35b-v1:0` | ⚠️ hangs in OpenCode (works raw) | Not usable via OpenCode currently |
| Kimi K2 Thinking | `moonshot.kimi-k2-thinking` | ❌ error | — |

Claude on Bedrock (`anthropic.claude-*`) is **not** an option here: Sonnet 5 is not enabled on
the account, and in Mumbai Claude is served via the cross-region `apac.` profile (leaves India).

## Switching
Edit `config/opencode.json` → `model` and `agent.blackwing.model` to `bedrock/<id>`, then
`make agent-config`. Restart is not required for new assessments (each run spawns a fresh agent).
