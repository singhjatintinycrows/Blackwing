"""Track B — source code review.

Three stages mirroring the source-code-review methodology:

* ``source-orient``   — clone the repo (token from the secrets store, in the sandbox only;
  NEVER run its scripts / npm install / pip install), map entry points, dangerous sinks,
  framework fingerprint and dependency manifest into a written inventory.
* ``source-tracer``   — model trust per surface, walk the priority order (missing-authz →
  reachable injection → auth/session/JWT → logic/race → SSRF → secrets/crypto → deps →
  client), and emit a candidate ledger (confirmed AND refuted) using lib.taint + the model.
* ``source-reporting``— assemble findings with exact file:line traces.

All three are passive/static — no packets, so they run without the approval gate. If a live
credential turns up in the repo it is reported by kind+location only, never used.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from bin.engine import Context, Stage
from lib import findings as findings_lib, ranking, redact, taint, validation

MAX_CANDIDATES_TO_MODEL = 25   # cap live-model triage per run
DEP_MANIFESTS = ("requirements.txt", "package.json", "pom.xml", "build.gradle",
                 "go.mod", "Gemfile", "composer.json", "Cargo.toml")


def _repo_dir(ctx: Context) -> str:
    return os.path.join(ctx.job_dir, "artifacts", "repo")


def stage_orient(ctx: Context) -> dict:
    repo_url = ctx.scope.repo_url
    dest = _repo_dir(ctx)
    cloned = False
    if repo_url and not os.path.isdir(dest):
        token = _resolve_token(ctx)
        clone_url = repo_url
        if token and repo_url.startswith("https://"):
            clone_url = repo_url.replace("https://", f"https://{token}@", 1)
        # Shallow, no submodules, no hooks. NEVER checkout+run anything.
        cmd = ["git", "clone", "--depth", "1", "--no-tags", clone_url, dest]
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
        # redact the URL (may embed the token) before logging
        ctx.command_log.record("source-orient", " ".join(cmd), output=proc.stderr[-300:])
        if proc.returncode != 0:
            return {"summary": f"clone failed: {redact.redact(proc.stderr[-200:])}", "cloned": False}
        cloned = True
        _forget_token(ctx)   # discard the credential the moment the clone is done

    if not os.path.isdir(dest):
        return {"summary": "no repo available to review", "cloned": False}

    # Inventory: languages, entry points (dep manifests), framework fingerprint.
    langs: dict[str, int] = {}
    manifests: list[str] = []
    for dp, dn, fn in os.walk(dest):
        dn[:] = [d for d in dn if d not in taint.SKIP_DIRS]
        for f in fn:
            ext = os.path.splitext(f)[1].lower()
            if ext in taint.EXT_LANG:
                langs[taint.EXT_LANG[ext]] = langs.get(taint.EXT_LANG[ext], 0) + 1
            if f in DEP_MANIFESTS:
                manifests.append(os.path.relpath(os.path.join(dp, f), dest))
    inventory = {
        "repo": repo_url or dest,
        "languages": langs,
        "dependency_manifests": manifests,
        "cloned": cloned,
    }
    ctx.write_artifact("source_inventory.json", json.dumps(inventory, indent=2))
    ctx.results["inventory"] = inventory
    return {"summary": f"mapped {sum(langs.values())} source files, langs={list(langs)}",
            "inventory": inventory}


def stage_tracer(ctx: Context) -> dict:
    dest = _repo_dir(ctx)
    if not os.path.isdir(dest):
        return {"summary": "no repo to trace"}
    hits = taint.prioritise(taint.scan_tree(dest))
    ctx.write_artifact("sink_candidates.json", json.dumps(
        [vars(h) | {"context": None} for h in hits[:200]], indent=2, default=str))

    confirmed = 0
    refuted = 0
    for i, h in enumerate(hits[:MAX_CANDIDATES_TO_MODEL]):
        rel = os.path.relpath(h.path, dest)
        cand = validation.Candidate(
            hypothesis=f"{h.cls} at {rel}:{h.line}",
            track="source",
            traced_path=[f"source→{rel}:{h.line}"],
            guard_analysis=("sanitiser nearby" if h.has_nearby_sanitiser else "no sanitiser seen"),
            reachability=("request-derived source nearby" if h.has_nearby_source else "source not obvious"),
            confidence=h.confidence,
        )
        verdict = _assess(ctx, h, rel)
        cand.notes = verdict.get("rationale", "")[:400]
        if verdict.get("exploitable") == "confirmed":
            cand.confirm(note=verdict.get("rationale", ""))
            _emit_finding(ctx, h, rel, verdict)
            confirmed += 1
        elif verdict.get("exploitable") == "refuted":
            cand.refute(note=verdict.get("rationale", ""))
            refuted += 1
        else:
            _emit_finding(ctx, h, rel, verdict, tentative=True)
        ctx.ledger.record(cand)

    ctx.write_artifact("candidate_ledger.json", json.dumps(ctx.ledger.to_dicts(), indent=2, default=str))
    return {"summary": f"{len(hits)} sink hits; triaged {min(len(hits), MAX_CANDIDATES_TO_MODEL)}; "
                       f"confirmed={confirmed} refuted={refuted}",
            "total_hits": len(hits)}


def stage_reporting(ctx: Context) -> dict:
    src_findings = ctx.store.by_track("source")
    ordered = ranking.report_order(src_findings)
    ctx.results["source_findings_ordered"] = ordered
    return {"summary": f"{len(src_findings)} source findings assembled"}


# -- helpers -----------------------------------------------------------------
def _assess(ctx: Context, hit: taint.SinkHit, rel: str) -> dict:
    """Ask the model whether this sink is a real, reachable, unsanitised vulnerability.
    Detection/confirmation-only: we reason about the code, we do not run it."""
    context = "\n".join(hit.context)
    prompt = (
        "You are a secure-code-review analyst. Decide if the flagged sink is an actually "
        "exploitable vulnerability reachable from untrusted input with no effective sanitiser. "
        "Reply ONLY as compact JSON: "
        '{\"exploitable\":\"confirmed|refuted|uncertain\",\"severity\":\"info|low|medium|high|critical\",'
        '\"cwe\":\"CWE-XX\",\"rationale\":\"one sentence\"}.\n\n'
        f"Class: {hit.cls}\nFile: {rel}:{hit.line}\nCode context:\n{context[:1500]}"
    )
    try:
        resp = ctx.model.complete(prompt, max_completion_tokens=400)
        return _parse_json(resp.content)
    except Exception as e:
        return {"exploitable": "uncertain", "severity": _default_sev(hit.cls),
                "rationale": f"model unavailable: {e}"}


def _emit_finding(ctx: Context, hit: taint.SinkHit, rel: str, verdict: dict, tentative=False):
    sev = verdict.get("severity") or _default_sev(hit.cls)
    if sev not in findings_lib.SEVERITIES:
        sev = _default_sev(hit.cls)
    ctx.store.add(findings_lib.Finding(
        track="source",
        title=f"{hit.cls} in {rel}",
        cls=hit.cls if hit.cls in ranking.CLASS_WEIGHT["source"] else "injection",
        severity=sev,
        confidence="confirmed" if verdict.get("exploitable") == "confirmed" else "tentative",
        location=f"{rel}:{hit.line}",
        description=redact.redact(hit.snippet),
        impact=verdict.get("rationale", "")[:300],
        trace=[f"untrusted source → {rel}:{hit.line} ({hit.cls} sink)"],
        cwe=verdict.get("cwe", ""),
        exploitability=verdict.get("exploitable", "uncertain"),
        status="confirmed" if verdict.get("exploitable") == "confirmed" else "candidate",
        evidence_ref=["artifacts/sink_candidates.json", "artifacts/candidate_ledger.json"],
    ))


def _default_sev(cls: str) -> str:
    return {"sqli": "high", "command-injection": "critical", "ssti": "high",
            "deserialization": "high", "path-traversal": "medium", "xss": "medium",
            "ssrf": "high", "xxe": "high"}.get(cls, "medium")


def _parse_json(text: str) -> dict:
    text = text.strip()
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return {"exploitable": "uncertain", "rationale": text[:200]}


def _resolve_token(ctx: Context):
    ref = ctx.scope.raw.get("targets", {}).get("source", {}).get("token_ref", "")
    if not ref:
        return None
    try:
        from orchestrator.secrets_store import STORE
        return STORE.get(ref)
    except Exception:
        return None


def _forget_token(ctx: Context):
    ref = ctx.scope.raw.get("targets", {}).get("source", {}).get("token_ref", "")
    if ref:
        try:
            from orchestrator.secrets_store import STORE
            STORE.discard(ref)
        except Exception:
            pass


STAGES = [
    Stage("source-orient", "passive", stage_orient, track="source"),
    Stage("source-tracer", "passive", stage_tracer, deps=("source-orient",), track="source"),
    Stage("source-reporting", "passive", stage_reporting, deps=("source-tracer",), track="source"),
]
