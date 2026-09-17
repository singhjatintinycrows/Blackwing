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

## Try it (≈1 minute)

1. Open **http://127.0.0.1:8900**.
2. Paste a target URL (e.g. `http://127.0.0.1:8477/` for the local testbed).
3. If the target needs an auth token, click **"This target needs an authentication token"** and paste it.
4. Click **Start assessment**. It runs immediately — no login, no approval step.
5. Watch the progress; confirmed **XSS, SQLi, SSTI** and other findings appear, each proven
   detection-only. Open the full report or download evidence from the same page.

Blackwing auto-routes the URL: a GitHub repo URL runs a source review; a `.apk` link runs an
Android review; anything else runs a web-app scan.

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
