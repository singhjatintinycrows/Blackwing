# Blackwing — project guide for Claude Code / Codex agents

Blackwing is an **authorised-only** application security auditing platform. Read this before
touching code. The rules below are invariants, not preferences.

## The spine (never weaken, in any track)

1. **Detection/confirmation-only.** Prove a finding with the *minimum* reproducible evidence
   (control-contrast, traced source→sink, on-device reachability PoC). Never cause real
   impact: no exfiltration beyond a planted canary, no persistence, no lateral movement, no
   using a discovered secret/token against a live service.
2. **Authorisation gate.** Passive/static stages may run on submission. Every active/dynamic
   stage is blocked until `scope.yaml` has `authorised: true`, which only the human-approval
   step sets. Enforced by `scope_guard.sh`.
3. **No dorking.** No Google or GitHub dorking, any track. Enforced by `dorking_guard.sh`.
4. **Secrets are radioactive.** Report location + kind only; never use, never log raw.
   Enforced by `secret_guard.sh`.

## Enforcement is by hooks, not prompts

Guardrails live in `.claude/hooks/*.sh` and are wired in `.claude/settings.json`. Do not move
a guarantee from a hook into an agent prompt — prompts can be talked around, hooks cannot.
Hooks read the tool-call JSON on stdin and exit non-zero (with a reason on stderr) to deny.

## Layout

- `web/` — FastAPI intake, dashboard, live view, report viewer.
- `orchestrator/` — job queue, scope.yaml generation, approval logic, sandbox lifecycle.
- `bin/` — DAG engine + per-track runners.
- `lib/` — stdlib-only reasoning libs (ranking, validation ledger, audit, taint tracer,
  android triage). No third-party deps in `lib/` so it runs anywhere the sandbox does.
- `.claude/agents/` — lead + per-track agent definitions.
- `.claude/hooks/` — the control plane.
- `sandbox/` — per-job Docker definition; ephemeral, torn down after each run.
- `config/scope.template.yaml` — the authorisation contract.
- `jobs/<job-id>/` — per-engagement output (git-ignored; contains raw evidence).

## Conventions

- `lib/` is **stdlib-only** (Python 3.11+). Web/orchestrator may use FastAPI etc.
- Secrets come from env (`.env`, git-ignored) — never hardcode, never commit, never log.
- Every finding carries a `track` field (`web`/`android`/`source`) and merges into one
  `findings.json` per engagement.
- Tests in `tests/`; run with `make test`. Model-dependent tests use `BLACKWING_MODEL_MOCK=1`.

## Runtime
See `docs/RUNTIME.md`. Model: `openai.gpt-oss-120b-1:0` via Bedrock, region `ap-south-1`.
