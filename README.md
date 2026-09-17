# Blackwing

**Authorised-only application security auditing platform.**

Blackwing puts a web intake in front of a swiftPentest-style multi-agent engine. A user
submits a domain, a GitHub repo (with a token), an APK, or any combination, through an
authenticated form. Blackwing routes each artifact to the matching **track** — web app
pentest, Android pentest, or source-code review — runs the full
`plan → hunt → validate/confirm → report` pipeline, and produces one unified report per
engagement.

> **Blackwing is detection- and confirmation-only.** It proves findings with the minimum
> reproducible evidence and never causes real impact: no data exfiltration beyond a planted
> canary, no persistence, no lateral movement, and it never uses a discovered secret or
> token against a live service. Active/dynamic stages require written authorisation and a
> human-approval step before they run.

## The non-negotiable spine

1. **Detection/confirmation-only.** Minimum reproducible evidence, never real damage.
2. **Written authorisation + human approval** before any active/dynamic stage.
3. **No Google/GitHub dorking**, any track — enforced by `dorking_guard.sh`.
4. **Secrets are radioactive** — reported (location + kind), never used, never logged raw.

These are enforced by *hooks* (mechanisms), not by prompt text alone. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Layers

| Layer | Dir | What it does |
|---|---|---|
| Web front-end | `web/` | SSO-gated intake form, job dashboard, live view, report viewer |
| Orchestration | `orchestrator/` | scope.yaml generation, approval gate, per-job sandbox lifecycle |
| Engine | `bin/`, `lib/`, `.claude/` | DAG runner, agent team, stdlib reasoning libs, control-plane hooks |
| Sandbox | `sandbox/` | per-job ephemeral container, torn down after each run |

## Tracks

- **Track A — Web** (`.claude/agents`, `bin/track_web.py`): passive-osint → threat-intel →
  cloud-enum → active-web → network-discovery → analysis → attack-planner → specialists →
  validation → reporting.
- **Track B — Source** (`source-orient`, `source-tracer`, `source-reporting`): entry-point
  and sink mapping → taint tracing in methodology priority order → `file:line` findings.
- **Track C — Android** (`android-recon`, `android-hunter`, `android-dynamic`,
  `android-reporting`): decompile + manifest → static triage → on-device PoC confirmation.

## Runtime

- Harness: **Codex CLI**, configured against **AWS Bedrock** (Mantle OpenAI-compatible
  endpoint), model **`openai.gpt-oss-120b-1:0`**, region **ap-south-1** (Mumbai — satisfies
  India data-residency). See [`docs/RUNTIME.md`](docs/RUNTIME.md).

## Quickstart (development)

```bash
cp .env.example .env      # fill AWS_BEARER_TOKEN_BEDROCK etc. — .env is git-ignored
make setup                # create venv, install deps
make check-bedrock        # verify model connectivity
make dev                  # run the web app on 127.0.0.1:8000
```

## Security & authorisation

Blackwing is **not** open to unauthenticated submission; gate the whole app behind your SSO.
Every engagement records an authorisation reference and requires reviewer approval before
active testing. Blackwing is for testing systems you own or are explicitly contracted /
bounty-authorised to test. Do not point it at anything else.
