# Blackwing architecture

Three layers, one spine.

```
┌─ web/ ─────────────┐   ┌─ orchestrator/ ──────────┐   ┌─ per-job sandbox ────────────┐
│ FastAPI intake     │   │ jobs.py  scope.yaml gen   │   │ bin/run_job → DAG runner     │
│ dashboard + live   │──▶│ approval (sep. of duties) │──▶│ track_source / android / web │
│ report viewer      │   │ unpack.py  secrets_store  │   │ lib/* (stdlib-only)          │
│ auth (SSO seam)    │   │ engine_runner (subprocess)│   │ .claude/hooks/* fail-closed  │
└────────────────────┘   └───────────────────────────┘   └──────────────────────────────┘
        SSO-gated              scope.yaml + approval             Codex CLI + gpt-oss-120b
```

## The spine (enforced by mechanisms, not prompts)

| Guarantee | Enforced by |
|---|---|
| Active/dynamic stages need authorisation + human approval | `scope_guard.sh` → `lib/scope.py` `allows_stage()`; DAG runner skips gated stages |
| No Google/GitHub dorking, any track | `dorking_guard.sh` |
| No fetch/decode-then-execute laundering | `injection_guard.sh` |
| Secrets never written/sent/logged raw | `secret_guard.sh` + `lib/redact.py` (also in audit + command log + report) |
| Completion carries evidence | `task_completed.sh` |
| Tamper-evident action trail | `audit_log.sh` → `lib/audit.py` (SHA-256 hash chain) |

The guards activate only in engine context (`BLACKWING_ENGINE=1`, set by the trusted
orchestrator) so they fail closed inside the sandbox and stay out of the dev shell.

## Data flow per engagement

1. **Intake** (`web`): requester (SSO) submits domain/repo/APK + **required** authority
   reference. Uploads are magic-byte validated and zip-slip-safely extracted. A GitHub token
   goes to `secrets_store` as a `token_ref`; the raw value never touches disk.
2. **Job** (`orchestrator/jobs.py`): renders `scope.yaml` (`authorised: false`), creates
   `jobs/<id>/`, status `awaiting_approval`. Passive/static stages launch immediately.
3. **Approval**: a *different* identity (separation of duties) flips `authorised: true`,
   recording approver + timestamp. Active/dynamic stages become runnable.
4. **Engine** (`bin/run_job`): selects tracks from scope, runs each track's `Stage` DAG. Each
   stage sets `BLACKWING_STAGE`; active stages self-gate. Findings (each `track`-tagged) land
   in `findings.json`; the candidate ledger keeps refuted candidates too.
5. **Report** (`bin/report.py`): merges all tracks into one redacted, severity-ordered
   `report.md` + `summary.json`.

## Tracks

- **A — web** (`bin/track_web.py`): passive OSINT now; active-web / nuclei / validation gated.
  Deep per-class specialists tracked in issue #7.
- **B — source** (`bin/track_source.py`): fully static — clone (token then discarded, never
  runs repo scripts) → `lib/taint.py` priority scan → per-candidate model adjudication →
  `file:line` findings. End-to-end working.
- **C — android** (`bin/track_android.py`): decode + manifest (`lib/android_triage.py`) →
  exported-first triage + secret-location scan → gated on-device confirmation.

## `jobs/<id>/` layout (git-ignored — contains raw evidence)

```
scope.yaml  job.json  findings.json  summary.json  report.md
command_log.jsonl   audit_log.jsonl (hash-chained)   engine.log
artifacts/   evidence/video/
```

## Runtime

Codex CLI drives the agent team against Bedrock `openai.gpt-oss-120b-1:0` (ap-south-1). The
single integration point is `lib/model_client.py`; `BLACKWING_MODEL_MOCK=1` swaps in a
deterministic mock so the whole pipeline runs offline (that is how the tests run). See
[RUNTIME.md](RUNTIME.md).
