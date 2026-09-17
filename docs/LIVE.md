# Running Blackwing live
> **Engine:** the assessment is run by an autonomous coding agent (OpenCode by default, or Codex) driving gpt-oss-120b on Bedrock. The agent itself runs the Kali toolkit (nmap, nuclei, sqlmap, ffuf, httpx, ...) to find the bugs and writes the findings.


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

## Codex CLI (optional)

Codex is installed at `~/.npm-global/bin` and configured against Bedrock via the shim. Your
shell rc now exports the PATH and `CODEX_SHIM_KEY`, so in a **new terminal**:

```bash
make live                 # ensure the shim on :8791 is running
codex                     # interactive, or:
codex exec "Reply with exactly: BLACKWING_OK"
```

If `codex` is "not found", your terminal predates the PATH change — open a new one or run
`source ~/.zshrc`. Codex speaks the OpenAI Responses API and Bedrock speaks chat/completions,
so `tools/codex_bedrock_proxy.py` bridges them. **You do not need Codex to use Blackwing** —
the web UI and engine talk to Bedrock directly.
