# Running Blackwing live

## One command

```bash
make setup          # venv + deps (first time only)
make codex-config   # install ~/.codex/config.toml (Codex -> Bedrock shim)
make live           # starts: Codex⇄Bedrock shim (:8791), web UI (:8900), testbed (:8477)
```

Then open **http://127.0.0.1:8900** and sign in.

Stop everything with `make stop`.

## Services

| Service | Port | What |
|---|---|---|
| Web UI | 8900 | intake, dashboard, live view, report + evidence download |
| Codex⇄Bedrock shim | 8791 | translates Codex's Responses API to Bedrock chat/completions |
| Local testbed | 8477 | a deliberately-vulnerable target to try the web track against |

Ports come from `.env` (`BLACKWING_PORT`, `CODEX_PROXY_PORT`, `TESTBED_PORT`) — fully
configurable. The web UI won't start if its port is taken; change `BLACKWING_PORT`.

## Try it (web track, ~1 minute)

1. Sign in as an analyst, e.g. `analyst@tinycrows.com`.
2. **New engagement** → Authorisation reference `LOCAL-TEST`, Target domain `127.0.0.1:8477`, submit.
3. Passive stages run immediately; active stages wait for approval.
4. Sign in as a **reviewer** (`reviewer@tinycrows.com`, set in `BLACKWING_REVIEWERS`) and
   click **Approve active testing** on the job.
5. Watch the live view; the report will show confirmed **XSS, SQLi, SSTI** and missing headers
   — each proven detection-only via control-contrast + N-of-M.

## Try it (source track)

New engagement → GitHub repo URL + a fine-grained read-only token → submit. The source track
clones, traces taint, and the model confirms findings at exact `file:line`. No approval needed
(source review is fully static).

## Codex CLI

Codex is configured against Bedrock via the shim. Verify:

```bash
set -a; . ./.env; set +a
export CODEX_SHIM_KEY=local-shim
codex exec --skip-git-repo-check "Reply with exactly: BLACKWING_OK"
```

Codex speaks the OpenAI Responses API and Bedrock speaks chat/completions, so
`tools/codex_bedrock_proxy.py` bridges them. The Blackwing engine itself talks to Bedrock
directly via `lib/model_client.py` and does not require Codex to run.
